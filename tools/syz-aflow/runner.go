// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	aflowhtml "github.com/google/syzkaller/pkg/aflow/trajectory/html"
	"github.com/google/syzkaller/pkg/osutil"
)

type RunnerArgs struct {
	FlowName   string
	Provider   string
	Model      string
	Workdir    string
	CacheSize  uint64
	Debug      bool
	TokenLimit int
	Parallel   int
	HTML       string
	Output     string
	Corpus     string
}

// Runner holds the state that is shared across workflow executions:
// the workflow itself, the LLM provider, and the cache.
type Runner struct {
	flow       *aflow.Flow
	provider   backend.Provider
	cache      *aflow.Cache
	workdir    string
	debug      bool
	tokenLimit int
	parallel   int
	html       string
	output     string
	corpusPath string
	corpus     *corpusWriter
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
	cache, err := aflow.NewCache(filepath.Join(args.Workdir, "cache"), args.CacheSize)
	if err != nil {
		return nil, err
	}
	provider, err := factory(ctx, args.Model)
	if err != nil {
		return nil, err
	}
	return &Runner{
		flow:       flow,
		provider:   provider,
		cache:      cache,
		workdir:    args.Workdir,
		debug:      args.Debug,
		tokenLimit: args.TokenLimit,
		parallel:   args.Parallel,
		html:       args.HTML,
		output:     args.Output,
		corpusPath: args.Corpus,
	}, nil
}

func (r *Runner) Close() {
	if r.provider != nil {
		r.provider.Close()
		r.provider = nil
	}
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

func (r *Runner) runSingle(ctx context.Context, inputFile string) error {
	inputs, err := loadTaskInputs(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read -input file: %w", err)
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

	output, err := r.flow.Execute(ctx, inputs, aflow.ExecuteOptions{
		Provider:   r.provider,
		Workdir:    r.workdir,
		Cache:      r.cache,
		OnEvent:    onEvent,
		Debug:      r.debug,
		TokenLimit: r.tokenLimit,
	})
	if err != nil {
		return err
	}
	if r.output != "" {
		if err := osutil.WriteJSON(r.output, output); err != nil {
			return fmt.Errorf("failed to save output: %w", err)
		}
	}
	return nil
}

func saveHTML(path string, spans []*trajectory.Span) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("failed to create HTML file: %v", err)
		return
	}
	defer f.Close()
	nonNil := spans
	if slices.Contains(spans, nil) {
		nonNil = slices.DeleteFunc(slices.Clone(spans), func(s *trajectory.Span) bool {
			return s == nil
		})
	}
	if err := aflowhtml.RenderReport(f, nonNil); err != nil {
		log.Printf("failed to render trajectory: %v", err)
	}
}

// appendOrUpdateSpan stores the span at the index of its Seq, growing
// the slice if necessary. Span updates (e.g. on finish) replace the
// previously stored span with the same Seq.
func appendOrUpdateSpan(spans []*trajectory.Span, span *trajectory.Span) []*trajectory.Span {
	if span.Seq >= len(spans) {
		spans = slices.Grow(spans, span.Seq+1-len(spans))
		spans = spans[:span.Seq+1]
	}
	spans[span.Seq] = span
	return spans
}
