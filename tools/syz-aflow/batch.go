// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"golang.org/x/sync/errgroup"
)

const (
	stateSuccess    = "success"
	stateGiveUp     = "giveup"
	stateError      = "error"
	stateInProgress = "in_progress"
)

var (
	batchStates = []string{stateSuccess, stateGiveUp, stateError}
	// The file extensions written while a task is still running.
	inProgressExts = []string{".html", ".log"}
)

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

// findTaskFiles returns the list of tasks to execute. If path is a directory,
// each *.json file in it is a separate task and the run is a batch one.
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

func validateBatchMode(isBatch bool, args RunnerArgs) error {
	if args.Parallel < 1 {
		return fmt.Errorf("-parallel must be at least 1")
	}
	if !isBatch {
		if args.Parallel != 1 {
			return fmt.Errorf("-parallel can only be used in batch execution")
		}
		return nil
	}
	// Result classification relies on the Success/GiveUp outputs of the workflow.
	if args.FlowName != string(ai.WorkflowSeedGenFileLine) {
		return fmt.Errorf("batch execution is currently only supported for %q workflow",
			ai.WorkflowSeedGenFileLine)
	}
	if args.Workdir == "" {
		return fmt.Errorf("-workdir must be specified for batch execution")
	}
	if args.HTML != "" || args.Output != "" {
		return fmt.Errorf("-html and -output cannot be used in batch execution" +
			" (trajectories are saved to workdir/trajectories/)")
	}
	return nil
}

func (r *Runner) runBatch(ctx context.Context, tasks []batchTask) error {
	for _, state := range append(slices.Clone(batchStates), stateInProgress) {
		if err := osutil.MkdirAll(filepath.Join(r.workdir, "trajectories", state)); err != nil {
			return err
		}
	}
	log.Printf("found %d tasks", len(tasks))
	totalTasks := len(tasks)
	tasks, resumedCount, err := r.prepareBatchTasks(tasks)
	if err != nil {
		return err
	}
	log.Printf("%d tasks pending execution (%d already completed, %d resumed)",
		len(tasks), totalTasks-len(tasks), resumedCount)
	if len(tasks) == 0 {
		log.Printf("all tasks have already completed")
		return nil
	}

	// Workflow failures are recorded as task results, so the only errors that
	// abort the batch are the ones that prevent saving results at all.
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(r.parallel)
	var (
		mu    sync.Mutex
		stats = make(map[string]int)
	)
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
		log.Printf("execution finished: 0 tasks executed")
	} else {
		log.Printf("execution finished: %s", strings.Join(summary, ", "))
	}
	return waitErr
}

func (r *Runner) executeBatchTask(ctx context.Context, task batchTask) (string, error) {
	startTime := time.Now()
	inputs, err := loadTaskInputs(task.Path)
	if err != nil {
		return stateError, fmt.Errorf("failed to read task file %s: %w", task.Path, err)
	}

	// Note: the in-progress files are not removed if the run is aborted, so that
	// the next run could identify and prioritize such tasks.
	inProgressHTML := r.taskPath(stateInProgress, task.ID, ".html")
	var spans []*trajectory.Span
	onEvent := func(span *trajectory.Span) error {
		spans = appendOrUpdateSpan(spans, span)
		saveHTML(inProgressHTML, spans)
		return nil
	}
	taskLogf, closeLog, err := openTaskLog(r.taskPath(stateInProgress, task.ID, ".log"))
	if err != nil {
		return stateError, err
	}
	defer closeLog()

	log.Printf("starting task %s", task.ID)
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

	duration := time.Since(startTime)
	state := classifyResultState(outputs, flowErr)
	res := batchResult{
		ID:         task.ID,
		State:      state,
		Outputs:    outputs,
		DurationMs: duration.Milliseconds(),
	}
	if flowErr != nil {
		res.Error = flowErr.Error()
	}
	if err := r.saveResult(res, spans); err != nil {
		return stateError, fmt.Errorf("failed to write result file for %s: %w", task.ID, err)
	}

	duration = duration.Round(time.Second)
	if flowErr != nil {
		log.Printf("completed task %s: state=%s in %v (error: %v)", task.ID, state, duration, flowErr)
	} else {
		log.Printf("completed task %s: state=%s in %v", task.ID, state, duration)
	}
	return state, nil
}

func (r *Runner) taskPath(state, id, ext string) string {
	return filepath.Join(r.workdir, "trajectories", state, id+ext)
}

func (r *Runner) saveResult(res batchResult, spans []*trajectory.Span) error {
	if err := osutil.MkdirAll(filepath.Dir(r.taskPath(res.State, res.ID, ".json"))); err != nil {
		return err
	}
	saveHTML(r.taskPath(res.State, res.ID, ".html"), spans)
	inProgressHTML := r.taskPath(stateInProgress, res.ID, ".html")
	if err := os.Remove(inProgressHTML); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove in-progress html: %w", err)
	}
	inProgressLog := r.taskPath(stateInProgress, res.ID, ".log")
	if err := os.Rename(inProgressLog, r.taskPath(res.State, res.ID, ".log")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to move log file: %w", err)
	}
	// The result file marks the task as completed, so write it only once everything else is in place.
	return osutil.WriteJSON(r.taskPath(res.State, res.ID, ".json"), res)
}

func openTaskLog(path string) (func(int, string, ...any), func(), error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create log file: %w", err)
	}
	logger := log.New(f, "", log.Ldate|log.Ltime)
	logf := func(v int, format string, args ...any) {
		logger.Printf("[%d] "+format, append([]any{v}, args...)...)
	}
	return logf, sync.OnceFunc(func() { f.Close() }), nil
}

// prepareBatchTasks returns the pending tasks in the execution order: the tasks aborted during
// the previous run come first (so that they are resumed from the still warm LLM cache), the rest
// follow in random order. It also returns the number of the resumed tasks.
//
// The random order makes the intermediate results of a long batch run representative
// of the whole task set, so that the run can be stopped early if needed.
func (r *Runner) prepareBatchTasks(tasks []batchTask) ([]batchTask, int, error) {
	completed, err := r.taskIDs(batchStates, ".json")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to check completed tasks: %w", err)
	}
	inProgress, err := r.taskIDs([]string{stateInProgress}, inProgressExts...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to check in-progress tasks: %w", err)
	}
	var aborted, rest []batchTask
	for _, task := range tasks {
		switch {
		case completed[task.ID]:
		case inProgress[task.ID]:
			aborted = append(aborted, task)
		default:
			rest = append(rest, task)
		}
	}
	// Remove the leftovers of the tasks that were aborted after their results had been saved.
	for id := range inProgress {
		if !completed[id] {
			continue
		}
		for _, ext := range inProgressExts {
			path := r.taskPath(stateInProgress, id, ext)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("failed to remove stale file %v: %v", path, err)
			}
		}
	}
	rand.Shuffle(len(rest), func(i, j int) {
		rest[i], rest[j] = rest[j], rest[i]
	})
	return append(aborted, rest...), len(aborted), nil
}

// taskIDs collects the IDs of the tasks that have files with the given extensions in the
// trajectory directories of the given states.
func (r *Runner) taskIDs(states []string, exts ...string) (map[string]bool, error) {
	ids := make(map[string]bool)
	for _, state := range states {
		entries, err := os.ReadDir(filepath.Join(r.workdir, "trajectories", state))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := filepath.Ext(entry.Name())
			if slices.Contains(exts, ext) {
				ids[strings.TrimSuffix(entry.Name(), ext)] = true
			}
		}
	}
	return ids, nil
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
