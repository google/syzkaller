// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	aflowhtml "github.com/google/syzkaller/pkg/aflow/trajectory/html"
	"github.com/google/syzkaller/pkg/osutil"
	"golang.org/x/sync/errgroup"
)

const (
	stateSuccess    = "success"
	stateGiveUp     = "giveup"
	stateError      = "error"
	stateInProgress = "in_progress"
)

var batchStates = []string{stateSuccess, stateGiveUp, stateError}

type batchTask struct {
	ID   string
	Path string
}

type batchResult struct {
	ID         string         `json:"id"`
	State      string         `json:"state"`
	Outputs    map[string]any `json:"outputs,omitempty"`
	Error      string         `json:"error,omitempty"`
	DurationMs int64          `json:"duration_ms"`
}

type RunnerArgs struct {
	FlowName   string
	Provider   string
	Model      string
	Workdir    string
	CacheSize  uint64
	Corpus     string
	Debug      bool
	TokenLimit int
	Parallel   int
	HTML       string
	Output     string
}

type Runner struct {
	flow       *aflow.Flow
	provider   backend.Provider
	cache      *aflow.Cache
	exporter   *CorpusExporter
	workdir    string
	debug      bool
	tokenLimit int
	parallel   int
	html       string
	output     string
}

func newRunner(ctx context.Context, args RunnerArgs) (*Runner, error) {
	flow := aflow.Flows[args.FlowName]
	if flow == nil {
		return nil, fmt.Errorf("workflow %q is not found", args.FlowName)
	}
	factory, ok := providers[args.Provider]
	if !ok {
		supported := slices.Sorted(maps.Keys(providers))
		return nil, fmt.Errorf("unknown provider %q (supported: %v)", args.Provider, supported)
	}
	var workdir string
	if args.Workdir != "" {
		workdir = osutil.Abs(args.Workdir)
	}
	cache, err := aflow.NewCache(filepath.Join(workdir, "cache"), args.CacheSize)
	if err != nil {
		return nil, err
	}
	exporter, err := openCorpus(args.Corpus)
	if err != nil {
		return nil, err
	}
	provider, err := factory(ctx, args.Model)
	if err != nil {
		return nil, errors.Join(err, exporter.Close())
	}
	if workdir != "" {
		for _, state := range append(slices.Clone(batchStates), stateInProgress) {
			if err := osutil.MkdirAll(filepath.Join(workdir, "trajectories", state)); err != nil {
				provider.Close()
				return nil, errors.Join(err, exporter.Close())
			}
		}
	}

	return &Runner{
		flow:       flow,
		provider:   provider,
		cache:      cache,
		exporter:   exporter,
		workdir:    workdir,
		debug:      args.Debug,
		tokenLimit: args.TokenLimit,
		parallel:   args.Parallel,
		html:       args.HTML,
		output:     args.Output,
	}, nil
}

func (r *Runner) Close() error {
	var errs []error
	if r.exporter != nil {
		errs = append(errs, r.exporter.Close())
		r.exporter = nil
	}
	if r.provider != nil {
		r.provider.Close()
		r.provider = nil
	}
	return errors.Join(errs...)
}

func loadTaskInputs(path string) (map[string]any, error) {
	inputs, err := osutil.ReadJSON[map[string]any](path)
	if err != nil {
		return nil, err
	}
	if err := expandFileInputs(inputs, filepath.Dir(path)); err != nil {
		return nil, err
	}
	return inputs, nil
}

func (r *Runner) runSingle(ctx context.Context, task batchTask) error {
	inputs, err := loadTaskInputs(task.Path)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}
	if r.html != "" {
		_ = osutil.MkdirAll(filepath.Dir(r.html))
	}

	var spans []*trajectory.Span
	onEvent := func(span *trajectory.Span) error {
		spans = appendOrUpdateSpan(spans, span)
		if r.html != "" {
			saveHTML(r.html, spans)
		}
		if span.Error != "" {
			return nil
		}
		log.Printf("%v", span)
		return nil
	}

	output, flowErr := r.flow.Execute(ctx, inputs, aflow.ExecuteOptions{
		Provider:   r.provider,
		Workdir:    r.workdir,
		Cache:      r.cache,
		OnEvent:    onEvent,
		Debug:      r.debug,
		TokenLimit: r.tokenLimit,
	})

	if err := r.exporter.ExportSpans(inputs, spans); err != nil {
		return err
	}

	if flowErr != nil {
		return flowErr
	}

	if r.output != "" {
		if err := osutil.WriteJSON(r.output, output); err != nil {
			return fmt.Errorf("failed to save output: %w", err)
		}
	}
	return nil
}

func (r *Runner) runBatch(ctx context.Context, tasks []batchTask) error {
	log.Printf("found %d targets", len(tasks))

	totalTasks := len(tasks)
	completed, err := r.completedTaskIDs()
	if err != nil {
		return fmt.Errorf("failed to check completed targets: %w", err)
	}
	tasks = slices.DeleteFunc(tasks, func(task batchTask) bool {
		return completed[task.ID]
	})

	log.Printf("%d targets pending execution (%d already completed)",
		len(tasks), totalTasks-len(tasks))
	if len(tasks) == 0 {
		log.Printf("all targets have already completed")
		return nil
	}

	var (
		eg    errgroup.Group
		mu    sync.Mutex
		stats = make(map[string]int)
	)
	eg.SetLimit(r.parallel)
	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		eg.Go(func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			state, err := r.executeBatchTask(ctx, task)
			if err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			mu.Lock()
			stats[state]++
			mu.Unlock()
			return nil
		})
	}

	waitErr := eg.Wait()
	var summary []string
	for _, state := range batchStates {
		if count := stats[state]; count > 0 {
			summary = append(summary, fmt.Sprintf("%d %s", count, state))
		}
	}
	if len(summary) == 0 {
		log.Printf("execution finished: 0 targets executed")
	} else {
		log.Printf("execution finished: %s", strings.Join(summary, ", "))
	}
	return waitErr
}

func (r *Runner) executeBatchTask(ctx context.Context, task batchTask) (string, error) {
	startTime := time.Now()
	inputs, err := loadTaskInputs(task.Path)
	if err != nil {
		log.Printf("failed to read task file %s: %v", task.Path, err)
		return stateError, nil
	}

	inProgressHTML := r.targetPath(stateInProgress, task.ID, ".html")
	defer os.Remove(inProgressHTML)
	inProgressLog := r.targetPath(stateInProgress, task.ID, ".log")
	defer os.Remove(inProgressLog)

	taskLogf, closeLog, err := openTaskLog(inProgressLog)
	if err != nil {
		return stateError, err
	}
	defer closeLog()

	var spans []*trajectory.Span
	onEvent := func(span *trajectory.Span) error {
		spans = appendOrUpdateSpan(spans, span)
		saveHTML(inProgressHTML, spans)
		return nil
	}

	log.Printf("starting target %s", task.ID)

	outputs, flowErr := r.flow.Execute(ctx, inputs, aflow.ExecuteOptions{
		Provider:   r.provider,
		Workdir:    r.workdir,
		Cache:      r.cache,
		OnEvent:    onEvent,
		Debug:      r.debug,
		TokenLimit: r.tokenLimit,
		Logf:       taskLogf,
	})
	closeLog()
	if ctx.Err() != nil {
		return stateError, ctx.Err()
	}

	endTime := time.Now()
	state := classifyResultState(outputs, flowErr)

	if err := r.exporter.ExportSpans(inputs, spans); err != nil {
		return state, fmt.Errorf("failed to export corpus for %s: %w", task.ID, err)
	}

	res := batchResult{
		ID:         task.ID,
		State:      state,
		Outputs:    outputs,
		DurationMs: endTime.Sub(startTime).Milliseconds(),
	}
	if flowErr != nil {
		res.Error = flowErr.Error()
	}
	if err := r.saveResult(res, spans); err != nil {
		log.Printf("failed to write result file for %s: %v", task.ID, err)
	}

	duration := endTime.Sub(startTime).Round(time.Second)
	if flowErr != nil {
		log.Printf("completed target %s: state=%s in %v (error: %v)", task.ID, state, duration, flowErr)
	} else {
		log.Printf("completed target %s: state=%s in %v", task.ID, state, duration)
	}
	return state, nil
}

func (r *Runner) targetPath(state, id, ext string) string {
	return filepath.Join(r.workdir, "trajectories", state, id+ext)
}

func openTaskLog(path string) (func(int, string, ...any), func(), error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create log file: %w", err)
	}
	logger := log.New(f, "", log.Ldate|log.Ltime)
	return func(v int, format string, args ...any) {
			logger.Printf("[%d] %s", v, fmt.Sprintf(format, args...))
		}, sync.OnceFunc(func() {
			f.Close()
		}), nil
}

func (r *Runner) saveResult(res batchResult, spans []*trajectory.Span) error {
	if err := osutil.MkdirAll(filepath.Dir(r.targetPath(res.State, res.ID, ".json"))); err != nil {
		return err
	}
	saveHTML(r.targetPath(res.State, res.ID, ".html"), spans)
	inProgressLog := r.targetPath(stateInProgress, res.ID, ".log")
	finalLog := r.targetPath(res.State, res.ID, ".log")
	if err := os.Rename(inProgressLog, finalLog); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to move log file: %w", err)
	}
	return osutil.WriteJSON(r.targetPath(res.State, res.ID, ".json"), res)
}

func (r *Runner) completedTaskIDs() (map[string]bool, error) {
	completed := make(map[string]bool)
	for _, state := range batchStates {
		entries, err := os.ReadDir(filepath.Join(r.workdir, "trajectories", state))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				completed[strings.TrimSuffix(entry.Name(), ".json")] = true
			}
		}
	}
	return completed, nil
}

func findTaskFiles(path string) ([]batchTask, bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if !fi.IsDir() {
		return []batchTask{{
			ID:   strings.TrimSuffix(filepath.Base(path), ".json"),
			Path: path,
		}}, false, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, false, err
	}
	var tasks []batchTask
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			tasks = append(tasks, batchTask{
				ID:   strings.TrimSuffix(entry.Name(), ".json"),
				Path: filepath.Join(path, entry.Name()),
			})
		}
	}
	return tasks, true, nil
}

func classifyResultState(outputs map[string]any, flowErr error) string {
	switch {
	case flowErr != nil:
		return stateError
	case outputs["Success"] == true:
		return stateSuccess
	default:
		return stateGiveUp
	}
}

func saveHTML(path string, spans []*trajectory.Span) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	nonNil := spans
	if slices.Contains(spans, nil) {
		nonNil = slices.DeleteFunc(slices.Clone(spans), func(s *trajectory.Span) bool {
			return s == nil
		})
	}
	_ = aflowhtml.RenderReport(f, nonNil)
}

func appendOrUpdateSpan(spans []*trajectory.Span, span *trajectory.Span) []*trajectory.Span {
	if span.Seq >= len(spans) {
		spans = slices.Grow(spans, span.Seq+1-len(spans))
		spans = spans[:span.Seq+1]
	}
	spans[span.Seq] = span
	return spans
}
