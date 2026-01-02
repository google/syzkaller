// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"google.golang.org/genai"
)

// https://ai.google.dev/gemini-api/docs/models
const DefaultModel = "gemini-3-pro-preview"

func (flow *Flow) Execute(c context.Context, model, workdir string, inputs map[string]any,
	cache *Cache, onEvent onEvent) (map[string]any, error) {
	if err := flow.checkInputs(inputs); err != nil {
		return nil, fmt.Errorf("flow inputs are missing: %w", err)
	}
	ctx := &Context{
		Context: c,
		Workdir: osutil.Abs(workdir),
		cache:   cache,
		state:   maps.Clone(inputs),
		onEvent: onEvent,
	}
	defer ctx.close()
	if s := c.Value(stubContextKey); s != nil {
		ctx.stubContext = *s.(*stubContext)
	}
	if ctx.timeNow == nil {
		ctx.timeNow = time.Now
	}
	if ctx.generateContent == nil {
		var err error
		ctx.generateContent, err = contentGenerator(c, model)
		if err != nil {
			return nil, err
		}
	}
	span := &trajectory.Span{
		Type: trajectory.SpanFlow,
		Name: flow.Name,
	}
	if err := ctx.startSpan(span); err != nil {
		return nil, err
	}
	flowErr := flow.Root.execute(ctx)
	if flowErr == nil {
		span.Results = flow.extractOutputs(ctx.state)
	}
	if err := ctx.finishSpan(span, flowErr); err != nil {
		return nil, err
	}
	if ctx.spanNesting != 0 {
		// Since we finish all spans, even on errors, we should end up at 0.
		panic(fmt.Sprintf("unbalanced spans (%v)", ctx.spanNesting))
	}
	return span.Results, nil
}

type (
	onEvent             func(*trajectory.Span) error
	generateContentFunc func(*genai.GenerateContentConfig, []*genai.Content) (
		*genai.GenerateContentResponse, error)
	contextKeyType int
)

var (
	createClientOnce sync.Once
	createClientErr  error
	client           *genai.Client
	modelList        = make(map[string]bool)
	stubContextKey   = contextKeyType(1)
)

func contentGenerator(ctx context.Context, model string) (generateContentFunc, error) {
	const modelPrefix = "models/"
	createClientOnce.Do(func() {
		if os.Getenv("GOOGLE_API_KEY") == "" {
			createClientErr = fmt.Errorf("set GOOGLE_API_KEY env var to use with Gemini" +
				" (see https://ai.google.dev/gemini-api/docs/api-key)")
			return
		}
		client, createClientErr = genai.NewClient(ctx, nil)
		if createClientErr != nil {
			return
		}
		for m, err := range client.Models.All(ctx) {
			if err != nil {
				createClientErr = err
				return
			}
			modelList[strings.TrimPrefix(m.Name, modelPrefix)] = m.Thinking
		}
	})
	if createClientErr != nil {
		return nil, createClientErr
	}
	thinking, ok := modelList[model]
	if !ok {
		models := slices.Collect(maps.Keys(modelList))
		slices.Sort(models)
		return nil, fmt.Errorf("model %q does not exist (models: %v)", model, models)
	}
	return func(cfg *genai.GenerateContentConfig, req []*genai.Content) (*genai.GenerateContentResponse, error) {
		if thinking {
			cfg.ThinkingConfig = &genai.ThinkingConfig{
				// We capture them in the trajectory for analysis.
				IncludeThoughts: true,
				// Enable "dynamic thinking" ("the model will adjust the budget based on the complexity of the request").
				// See https://ai.google.dev/gemini-api/docs/thinking#set-budget
				// However, thoughts output also consumes total output token budget.
				// We may consider adjusting ThinkingLevel parameter.
				ThinkingBudget: genai.Ptr[int32](-1),
			}
		}
		return client.Models.GenerateContent(ctx, modelPrefix+model, req, cfg)
	}, nil
}

type Context struct {
	Context     context.Context
	Workdir     string
	cache       *Cache
	cachedDirs  []string
	state       map[string]any
	onEvent     onEvent
	spanSeq     int
	spanNesting int
	stubContext
}

type stubContext struct {
	timeNow         func() time.Time
	generateContent generateContentFunc
}

func (ctx *Context) Cache(typ, desc string, populate func(string) error) (string, error) {
	dir, err := ctx.cache.Create(typ, desc, populate)
	if err != nil {
		return "", err
	}
	ctx.cachedDirs = append(ctx.cachedDirs, dir)
	return dir, nil
}

func (ctx *Context) close() {
	for _, dir := range ctx.cachedDirs {
		ctx.cache.Release(dir)
	}
}

func (ctx *Context) startSpan(span *trajectory.Span) error {
	span.Seq = ctx.spanSeq
	ctx.spanSeq++
	span.Nesting = ctx.spanNesting
	ctx.spanNesting++
	span.Started = ctx.timeNow()
	return ctx.onEvent(span)
}

func (ctx *Context) finishSpan(span *trajectory.Span, spanErr error) error {
	ctx.spanNesting--
	if ctx.spanNesting < 0 {
		panic("unbalanced spans")
	}
	span.Finished = ctx.timeNow()
	if spanErr != nil {
		span.Error = spanErr.Error()
	}
	err := ctx.onEvent(span)
	if spanErr != nil {
		err = spanErr
	}
	return err
}
