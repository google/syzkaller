// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
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

// Execute executes the given AI workflow with provided inputs and returns workflow outputs.
// The model argument overrides Gemini models used to execute LLM agents,
// if not set, then default models for each agent are used.
// The workdir argument should point to a dir owned by aflow to store private data,
// it can be shared across parallel executions in the same process, and preferably
// preserved across process restarts for caching purposes.
func (flow *Flow) Execute(ctx context.Context, model, workdir string, inputs map[string]any,
	cache *Cache, onEvent onEvent) (map[string]any, error) {
	convertedInputs, err := flow.checkInputs(inputs)
	if err != nil {
		return nil, fmt.Errorf("flow inputs are missing: %w", err)
	}
	inputs = convertedInputs
	inputs = maps.Clone(inputs)
	maps.Insert(inputs, maps.All(flow.Consts))
	c := &Context{
		Context:  ctx,
		Workdir:  osutil.Abs(workdir),
		llmModel: model,
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
	if c.generateContent == nil {
		c.generateContent = c.generateContentGemini
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
	var quotaErr *modelQuotaError
	if errors.As(err, &quotaErr) {
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
	var overflowErr *inputTokenOverflowError
	return errors.As(err, &overflowErr)
}

type inputTokenOverflowError struct {
	error
}

func isOutputTokenOverflowError(err error) bool {
	var overflowErr *outputTokenOverflowError
	return errors.As(err, &overflowErr)
}

type outputTokenOverflowError struct {
	error
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
	createClientOnce sync.Once
	createClientErr  error
	client           *genai.Client
	modelList        map[string]*modelInfo
	modelPathPrefix  string
	stubContextKey   = contextKeyType(1)
)

type modelInfo struct {
	Thinking         bool
	MaxTemperature   float32
	InputTokenLimit  int
	OutputTokenLimit int
}

func (ctx *Context) generateContentGemini(model string, cfg *genai.GenerateContentConfig,
	req []*genai.Content) (*genai.GenerateContentResponse, error) {
	createClientOnce.Do(func() {
		client, modelList, modelPathPrefix, createClientErr = loadModelList(ctx.Context)
	})
	if createClientErr != nil {
		return nil, createClientErr
	}
	info := modelList[model]
	if info == nil {
		models := slices.Collect(maps.Keys(modelList))
		slices.Sort(models)
		return nil, fmt.Errorf("model %q does not exist (models: %v)", model, models)
	}
	// Don't alter the original object (that may affect request caching).
	cfg = osutil.JSONDeepCopy(cfg)
	*cfg.Temperature = min(*cfg.Temperature, info.MaxTemperature)
	if !info.Thinking {
		cfg.ThinkingConfig = nil
	}
	// Sometimes LLM requests just hang dead for tens of minutes,
	// abort them after 10 minutes and retry. We don't stream reply tokens,
	// so some large requests can take several minutes.
	timedCtx, cancel := context.WithTimeout(ctx.Context, 10*time.Minute)
	defer cancel()
	resp, err := client.Models.GenerateContent(timedCtx, modelPathPrefix+model, req, cfg)
	if err != nil && timedCtx.Err() == context.DeadlineExceeded {
		return nil, &retryError{time.Second, err}
	}
	return resp, err
}

func loadModelList(ctx context.Context) (*genai.Client, map[string]*modelInfo, string, error) {
	apiKey := os.Getenv("GOOGLE_API_KEY")
	cloudAPIKey := os.Getenv("GOOGLE_VERTEX_API_KEY")
	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if (apiKey != "" && project != "") || (apiKey != "" && cloudAPIKey != "") ||
		(cloudAPIKey != "" && project != "") {
		return nil, nil, "", fmt.Errorf("only one of GOOGLE_API_KEY, GOOGLE_VERTEX_API_KEY, " +
			"or GOOGLE_CLOUD_PROJECT can be set")
	}

	isVertex := cloudAPIKey != "" || project != ""
	if isVertex {
		cfg := &genai.ClientConfig{Backend: genai.BackendVertexAI}
		if cloudAPIKey != "" {
			cfg.APIKey = cloudAPIKey
		} else {
			cfg.Project = project
			location := os.Getenv("GOOGLE_CLOUD_REGION")
			if location == "" {
				location = "global"
			}
			cfg.Location = location
		}
		client, err := genai.NewClient(ctx, cfg)
		if err != nil {
			return nil, nil, "", err
		}
		// Vertex AI's Models.All() endpoint often does not return the same detailed
		// metadata (like InputTokenLimit or SupportedActions) as the Gemini Developer API,
		// or requires special IAM permissions to list the catalog. Therefore, we hardcode
		// the known capabilities for the models we actively use.
		models := map[string]*modelInfo{
			"gemini-3-flash-preview": {
				Thinking:         true,
				MaxTemperature:   2.0,
				InputTokenLimit:  1048576,
				OutputTokenLimit: 65536,
			},
			"gemini-3.1-pro-preview": {
				Thinking:         true,
				MaxTemperature:   2.0,
				InputTokenLimit:  1048576,
				OutputTokenLimit: 65536,
			},
		}
		// Vertex AI backend expects the bare model name, not prefixed with "models/".
		// E.g. "gemini-1.5-pro" instead of "models/gemini-1.5-pro".
		return client, models, "", nil
	} else if apiKey != "" {
		client, err := genai.NewClient(ctx, nil)
		if err != nil {
			return nil, nil, "", err
		}
		models := make(map[string]*modelInfo)
		for m, err := range client.Models.All(ctx) {
			if err != nil {
				return nil, nil, "", err
			}
			if !slices.Contains(m.SupportedActions, "generateContent") ||
				strings.Contains(m.Name, "-image") ||
				strings.Contains(m.Name, "-audio") {
				continue
			}
			models[strings.TrimPrefix(m.Name, "models/")] = &modelInfo{
				Thinking:         m.Thinking,
				MaxTemperature:   m.MaxTemperature,
				InputTokenLimit:  int(m.InputTokenLimit),
				OutputTokenLimit: int(m.OutputTokenLimit),
			}
		}
		// Gemini Developer API expects model names to be prefixed with "models/".
		// E.g. "models/gemini-1.5-pro".
		prefix := "models/"
		return client, models, prefix, nil
	}
	return nil, nil, "", fmt.Errorf("set GOOGLE_API_KEY (Gemini API) " +
		"or GOOGLE_CLOUD_PROJECT/GOOGLE_VERTEX_API_KEY (Vertex AI)")
}

type Context struct {
	Context     context.Context
	Workdir     string
	llmModel    string
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
	generateContent func(string, *genai.GenerateContentConfig, []*genai.Content) (
		*genai.GenerateContentResponse, error)
}

func (ctx *Context) modelName(model string) string {
	if ctx.llmModel != "" {
		return ctx.llmModel
	}
	return model
}

func (ctx *Context) Cache(typ, desc string, populate func(string) error) (string, error) {
	dir, err := ctx.cache.Create(typ, desc, populate)
	if err != nil {
		return "", err
	}
	ctx.cachedDirs = append(ctx.cachedDirs, dir)
	return dir, nil
}

func CacheObject[T any](ctx *Context, typ, desc string, populate func() (T, error)) (T, error) {
	dir, obj, err := cacheCreateObject(ctx.cache, typ, desc, populate)
	if err != nil {
		return obj, err
	}
	ctx.cachedDirs = append(ctx.cachedDirs, dir)
	return obj, nil
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
