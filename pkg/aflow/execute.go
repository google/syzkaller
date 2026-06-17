// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
)

// Execute executes the given AI workflow with provided inputs and returns workflow outputs.
// The workdir argument should point to a dir owned by aflow to store private data,
// it can be shared across parallel executions in the same process, and preferably
// preserved across process restarts for caching purposes.
func (flow *Flow) Execute(ctx context.Context, provider backend.Provider, workdir string, inputs map[string]any,
	cache *Cache, onEvent onEvent) (map[string]any, error) {
	convertedInputs, err := flow.checkInputs(inputs)
	if err != nil {
		return nil, fmt.Errorf("flow inputs are missing: %w", err)
	}
	inputs = convertedInputs
	inputs = maps.Clone(inputs)
	maps.Insert(inputs, maps.All(flow.Consts))
	llmClient, err := provider.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LLM client: %w", err)
	}

	c := &Context{
		Context:  ctx,
		Workdir:  osutil.Abs(workdir),
		provider: provider,
		cache:    cache,
		state:    inputs,
		onEvent:  onEvent,
	}

	defer c.Close()
	if s := ctx.Value(stubContextKey); s != nil {
		c.stubContext = *s.(*stubContext)
	}
	if c.timeNow == nil {
		c.timeNow = time.Now
	}
	if c.sleep == nil {
		c.sleep = time.Sleep
	}
	if c.generateContent == nil {
		c.generateContent = func(model string, cfg *backend.GenerateConfig,
			req []*backend.Message) (*backend.GenerateResponse, error) {
			return llmClient.GenerateContent(c.Context, model, cfg, req)
		}
	}
	span := &trajectory.Span{
		Type: trajectory.SpanFlow,
		Name: flow.Name,
	}
	if err := c.startSpan(span); err != nil {
		return nil, err
	}
	flowErr := flow.Root.execute(c)
	if flowErr == nil {
		span.Results = flow.extractOutputs(c.state)
	}
	if err := c.finishSpan(span, flowErr); err != nil {
		return nil, err
	}
	if c.spanNesting != 0 {
		// Since we finish all spans, even on errors, we should end up at 0.
		panic(fmt.Sprintf("unbalanced spans (%v)", c.spanNesting))
	}
	return span.Results, nil
}

// FlowError creates an error that denotes failure of the flow itself,
// rather than an infrastructure error. A flow errors mean an expected
// condition in the flow when it cannot continue, and cannot produce
// expected outputs. For example, if we are doing something with the kernel,
// but the kernel build fails. Flow errors shouldn't be flagged in
// infrastructure monitoring.
func FlowError(err error) error {
	return &flowError{err}
}

func IsFlowError(err error) bool {
	var flowErr *flowError
	return errors.As(err, &flowErr)
}

type flowError struct {
	error
}

func (e *flowError) Unwrap() error {
	return e.error
}

func IsModelQuotaError(err error) string {
	if quotaErr, ok := errors.AsType[*modelQuotaError](err); ok {
		return quotaErr.model
	}
	return ""
}

type modelQuotaError struct {
	model string
}

func (err *modelQuotaError) Error() string {
	return fmt.Sprintf("model %q is over daily quota", err.model)
}

func isInputTokenOverflowError(err error) bool {
	var overflowErr *backend.InputTokenOverflowError
	return errors.As(err, &overflowErr)
}

func isOutputTokenOverflowError(err error) bool {
	var overflowErr *backend.OutputTokenOverflowError
	return errors.As(err, &overflowErr)
}

// QuotaResetTime returns the time when RPD quota will be reset
// for a quota overflow happened at time t.
func QuotaResetTime(t time.Time) time.Time {
	// Requests per day (RPD) quotas reset at midnight Pacific time:
	// https://ai.google.dev/gemini-api/docs/rate-limits
	// To account for potential delays in the reset logic, we add small delta (5 mins)
	// to that to avoid situation when we reset it at exactly midnight locally,
	// but it's not reset on the server yet.
	// The assumption is also that any rate limiting errors in the very beginning
	// of the day (within first seconds/minutes), actually belong to the previous day
	// (we couldn't overflow the quota within that period).
	t = t.In(pacificLoc)
	resetTime := time.Date(t.Year(), t.Month(), t.Day(), 0, 5, 0, 0, pacificLoc)
	if t.After(resetTime) {
		resetTime = resetTime.Add(24 * time.Hour)
		if t.After(resetTime) {
			panic(fmt.Sprintf("%v > %v", t, resetTime))
		}
	}
	return resetTime.UTC()
}

var pacificLoc = func() *time.Location {
	loc, err := time.LoadLocation("US/Pacific")
	if err != nil {
		panic(err)
	}
	return loc
}()

type (
	onEvent        func(*trajectory.Span) error
	contextKeyType int
)

var (
	stubContextKey = contextKeyType(1)
)

type Context struct {
	Context     context.Context
	Workdir     string
	provider    backend.Provider
	cache       *Cache
	cachedDirs  []string
	tempDirs    []string
	state       map[string]any
	onEvent     onEvent
	spanSeq     int
	spanNesting int
	stubContext
}

type stubContext struct {
	timeNow         func() time.Time
	sleep           func(time.Duration)
	generateContent func(string, *backend.GenerateConfig, []*backend.Message) (
		*backend.GenerateResponse, error)
}

func (ctx *Context) Cache(typ, desc string, populate func(string) error) (string, error) {
	dir, err := ctx.cache.Create(typ, desc, populate)
	if err != nil {
		return "", err
	}
	ctx.cachedDirs = append(ctx.cachedDirs, dir)
	return dir, nil
}

func CacheObject[T any](
	ctx *Context,
	typ,
	desc string,
	populate func() (T, error),
) (obj T, id string, err error) {
	dir, obj, err := cacheCreateObject(ctx.cache, typ, desc, populate)
	if err != nil {
		return obj, "", err
	}
	ctx.cachedDirs = append(ctx.cachedDirs, dir)
	id = typ + "/" + filepath.Base(dir)
	return obj, id, nil
}

func RetrieveObject[T any](ctx *Context, cachedID string) (T, error) {
	var res T
	if !filepath.IsLocal(cachedID) {
		return res, fmt.Errorf("invalid cached ID (not local): %q", cachedID)
	}
	parts := strings.Split(cachedID, "/")
	if len(parts) != 2 {
		return res, fmt.Errorf("invalid cached ID format: %q", cachedID)
	}
	if parts[0] == "" || parts[1] == "" {
		return res, fmt.Errorf("invalid cached ID: parts cannot be empty")
	}
	return CacheReadObject[T](ctx, parts[0], parts[1], "object")
}

func CacheReadObject[T any](ctx *Context, typ, id, filename string) (T, error) {
	return cacheReadObject[T](ctx.cache, typ, id, filename)
}

// TempDir creates a new temp dir that will be automatically removed
// when the flow finished, or on the next restart.
func (ctx *Context) TempDir() (string, error) {
	dir, err := ctx.cache.TempDir()
	if err != nil {
		return "", err
	}
	ctx.tempDirs = append(ctx.tempDirs, dir)
	return dir, nil
}

func (ctx *Context) Close() {
	for _, dir := range ctx.cachedDirs {
		ctx.cache.Release(dir)
	}
	for _, dir := range ctx.tempDirs {
		os.RemoveAll(dir)
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
