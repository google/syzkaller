// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gemini implements an AI backend interfacing with the Gemini API.
package gemini

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/log"
	"google.golang.org/genai"
)

type Provider struct {
	mu              sync.Mutex
	client          *genai.Client
	models          map[string]*modelInfo
	modelPathPrefix string
	modelOverride   string
	err             error
}

type modelInfo struct {
	Thinking         bool
	MaxTemperature   float32
	InputTokenLimit  int
	OutputTokenLimit int
}

type Config struct {
	ModelOverride string
	ClientConfig  *genai.ClientConfig
}

func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	p := &Provider{
		modelOverride: cfg.ModelOverride,
	}
	if err := p.init(ctx, cfg); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) init(ctx context.Context, cfg Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil || p.err != nil {
		return p.err
	}

	client, err := genai.NewClient(ctx, cfg.ClientConfig)
	if err != nil {
		p.err = err
		return err
	}
	p.client = client

	isVertex := cfg.ClientConfig != nil && cfg.ClientConfig.Backend == genai.BackendVertexAI

	if isVertex {
		// Vertex AI's Models.All() endpoint often does not return the same detailed
		// metadata (like InputTokenLimit or SupportedActions) as the Gemini Developer API,
		// or requires special IAM permissions to list the catalog. Therefore, we hardcode
		// the known capabilities for the models we actively use.
		// Vertex AI backend expects the bare model name, not prefixed with "models/".
		// E.g. "gemini-1.5-pro" instead of "models/gemini-1.5-pro".
		p.models = map[string]*modelInfo{
			"gemini-3-flash-preview": {
				Thinking:         true,
				MaxTemperature:   2.0,
				InputTokenLimit:  1048576,
				OutputTokenLimit: 65536,
			},
			"gemini-3.5-flash": {
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
		p.modelPathPrefix = ""
		return nil
	}

	// Gemini API. Unlike Vertex AI, the Gemini Developer API catalog endpoint (Models.All)
	// successfully returns detailed metadata for all models (such as their InputTokenLimit,
	// OutputTokenLimit, and SupportedActions) without requiring any special IAM configurations.
	// Therefore, we query the catalog dynamically here.
	const maxInitRetries = 5

	var models map[string]*modelInfo
	for i := range maxInitRetries {
		models, err = p.queryModelsOnce(ctx, client)
		if err == nil {
			break
		}
		parsedErr := parseLLMError(err, "")
		var retryErr *backend.RetryError
		if !errors.As(parsedErr, &retryErr) {
			break
		}
		if i == maxInitRetries-1 {
			break
		}
		delay := retryErr.Delay
		if retryErr.IsExponential {
			delay = backend.BackoffDuration(i, retryErr.Delay)
		}
		select {
		case <-ctx.Done():
			p.err = ctx.Err()
			return p.err
		case <-time.After(delay):
		}
	}
	if err != nil {
		p.err = err
		return err
	}
	p.models = models
	p.modelPathPrefix = "models/"
	return nil
}

func (p *Provider) queryModelsOnce(ctx context.Context, client *genai.Client) (map[string]*modelInfo, error) {
	models := make(map[string]*modelInfo)
	for m, e := range client.Models.All(ctx) {
		if e != nil {
			return nil, e
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
	return models, nil
}

func (p *Provider) Client(ctx context.Context) (backend.Client, error) {
	return &client{p: p}, nil
}

func (p *Provider) Models(ctx context.Context) ([]string, error) {
	models := slices.Collect(maps.Keys(p.models))
	slices.Sort(models)
	return models, nil
}

func (p *Provider) ResolveModels(category backend.ModelCategory) []string {
	if p.modelOverride != "" {
		return []string{p.modelOverride}
	}
	switch category {
	case backend.BestExpensiveModel:
		return []string{"gemini-3.1-pro-preview"}
	case backend.GoodBalancedModel:
		return []string{"gemini-3.5-flash", "gemini-3-flash-preview"}
	case backend.Temporary35FlashOnlyModel:
		return []string{"gemini-3.5-flash"}
	default:
		return nil
	}
}

func (p *Provider) Close() error {
	return nil
}

type client struct {
	p *Provider
}

func (c *client) GenerateContent(ctx context.Context, model string, cfg *backend.GenerateConfig,
	history []*backend.Message) (*backend.GenerateResponse, error) {
	info := c.p.models[model]
	if info == nil {
		models := slices.Collect(maps.Keys(c.p.models))
		slices.Sort(models)
		return nil, fmt.Errorf("model %q does not exist (models: %v)", model, models)
	}

	genaiCfg := &genai.GenerateContentConfig{}
	if cfg != nil {
		if cfg.Temperature != nil {
			temp := min(*cfg.Temperature, info.MaxTemperature)
			genaiCfg.Temperature = &temp
		}
		if cfg.SystemInstruction != nil {
			genaiCfg.SystemInstruction = toGenaiContent(cfg.SystemInstruction)
		}
		if len(cfg.Tools) > 0 {
			for _, t := range cfg.Tools {
				genaiTool := &genai.Tool{}
				for _, fd := range t.FunctionDeclarations {
					genaiTool.FunctionDeclarations = append(genaiTool.FunctionDeclarations, &genai.FunctionDeclaration{
						Name:                 fd.Name,
						Description:          fd.Description,
						ParametersJsonSchema: fd.ParametersJSONSchema,
						ResponseJsonSchema:   fd.ResponseJSONSchema,
					})
				}
				genaiCfg.Tools = append(genaiCfg.Tools, genaiTool)
			}
		}
		if info.Thinking && cfg.ThinkingLevel != backend.ThinkingLevelMinimal {
			genaiCfg.ThinkingConfig = &genai.ThinkingConfig{}
			genaiCfg.ThinkingConfig.IncludeThoughts = cfg.IncludeThoughts
			switch cfg.ThinkingLevel {
			case backend.ThinkingLevelLow:
				genaiCfg.ThinkingConfig.ThinkingLevel = genai.ThinkingLevelLow
			case backend.ThinkingLevelMedium:
				genaiCfg.ThinkingConfig.ThinkingLevel = genai.ThinkingLevelMedium
			case backend.ThinkingLevelHigh:
				genaiCfg.ThinkingConfig.ThinkingLevel = genai.ThinkingLevelHigh
			}
		}
	}

	var req []*genai.Content
	for _, msg := range history {
		req = append(req, toGenaiContent(msg))
	}

	// Sometimes LLM requests just hang dead for tens of minutes,
	// abort them after 10 minutes and retry. We don't stream reply tokens,
	// so some large requests can take several minutes.
	timedCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	resp, err := c.p.client.Models.GenerateContent(timedCtx, c.p.modelPathPrefix+model, req, genaiCfg)
	if err != nil {
		if timedCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			// The internal 10-minute timeout expired, but the parent context is still alive.
			// This means the LLM request hung. We should retry.
			return nil, &backend.RetryError{Delay: time.Second, Err: err}
		}
		return nil, parseLLMError(err, model)
	}

	if err := parseLLMResp(resp); err != nil {
		return nil, err
	}

	return fromGenaiResponse(resp), nil
}

var rePleaseRetry = regexp.MustCompile(`Please retry in (\d+)s\.`)

func parseLLMError(err error, model string) error {
	var apiErr genai.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	// 499 has server-dependent meaning, but for genapi we observed these
	// when a request was cancelled on some internal error.
	if apiErr.Code == 503 || apiErr.Code == 502 || apiErr.Code == 504 || apiErr.Code == 499 {
		return &backend.RetryError{Delay: time.Second, IsExponential: true, Err: err}
	}
	if apiErr.Code == 429 && strings.Contains(apiErr.Message, "Quota exceeded for metric") {
		if match := rePleaseRetry.FindStringSubmatch(apiErr.Message); match != nil {
			sec, _ := strconv.Atoi(match[1])
			return &backend.RetryError{Delay: time.Duration(sec+1) * time.Second, Err: err}
		}
		if strings.Contains(apiErr.Message, "generate_requests_per_model_per_day") {
			// We can't return modelQuotaError here directly, so we just return a generic error.
			// In aflow, we can check for this specific error string if needed.
			return fmt.Errorf("model %q is over daily quota: %w", model, err)
		}
		return &backend.RetryError{Delay: time.Second, IsExponential: true, Err: err}
	}
	if apiErr.Code == 429 && strings.Contains(apiErr.Message, "You exceeded your current quota") {
		// Unclear what this is, the error does not contain details
		// (see the test for exact error message). But presumably this is some per-minute quota.
		return &backend.RetryError{Delay: time.Minute, Err: err}
	}
	if apiErr.Code == 429 && (strings.Contains(apiErr.Message, "Resource exhausted. Please try again later.") ||
		strings.Contains(apiErr.Message, "Resource has been exhausted")) {
		// Vertex AI specific rate limit error (e.g. RPM/TPM exhausted).
		return &backend.RetryError{Delay: time.Minute, Err: err}
	}
	if apiErr.Code == 400 && strings.Contains(apiErr.Message, "The input token count exceeds the maximum") {
		return &backend.InputTokenOverflowError{Err: err}
	}
	if apiErr.Code == 500 {
		// Let's assume ISE is just something temporal on the server side.
		return &backend.RetryError{Delay: time.Second, IsExponential: true, Err: err}
	}
	return err
}

func parseLLMResp(resp *genai.GenerateContentResponse) error {
	if len(resp.Candidates) == 0 || resp.Candidates[0] == nil {
		if resp.PromptFeedback != nil {
			return fmt.Errorf("request blocked: %v", resp.PromptFeedback.BlockReasonMessage)
		}
		return fmt.Errorf("empty model response")
	}
	candidate := resp.Candidates[0]
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		if candidate.FinishReason == genai.FinishReasonMalformedFunctionCall {
			// Let's consider this as a temp error, and that the next time it won't
			// generate the same buggy output. In either case we have maxLLMRetryIters.
			return &backend.RetryError{Delay: 0, IsExponential: false, Err: errors.New(string(candidate.FinishReason))}
		}
		if candidate.FinishReason == genai.FinishReasonMaxTokens {
			return &backend.OutputTokenOverflowError{Err: errors.New(string(candidate.FinishReason))}
		}
		return fmt.Errorf("%v (%v)", candidate.FinishMessage, candidate.FinishReason)
	}
	// We don't expect to receive these fields now.
	// Note: CitationMetadata may be present sometimes, but we don't have uses for it.
	if candidate.GroundingMetadata != nil || candidate.LogprobsResult != nil {
		return fmt.Errorf("unexpected reply fields (%+v)", *candidate)
	}
	for _, part := range candidate.Content.Parts {
		if part.VideoMetadata != nil || part.InlineData != nil ||
			part.FileData != nil || part.FunctionResponse != nil ||
			part.CodeExecutionResult != nil || part.ExecutableCode != nil {
			return fmt.Errorf("unexpected reply part (%+v)", *part)
		}
	}
	return nil
}

func toGenaiContent(msg *backend.Message) *genai.Content {
	c := &genai.Content{
		Role: string(msg.Role),
	}
	for _, p := range msg.Parts {
		if p.FunctionCall != nil {
			c.Parts = append(c.Parts, &genai.Part{
				FunctionCall: &genai.FunctionCall{
					ID:   p.FunctionCall.ID,
					Name: p.FunctionCall.Name,
					Args: p.FunctionCall.Args,
				},
				ThoughtSignature: p.ThoughtSignature,
			})
		} else if p.FunctionResponse != nil {
			c.Parts = append(c.Parts, &genai.Part{
				FunctionResponse: &genai.FunctionResponse{
					ID:       p.FunctionResponse.ID,
					Name:     p.FunctionResponse.Name,
					Response: p.FunctionResponse.Response,
				},
			})
		} else {
			if p.Text == "" && !p.Thought && len(p.ThoughtSignature) == 0 {
				log.Logf(2, "aflow/gemini: skipping empty text part without thought metadata")
				continue
			}
			text := p.Text
			if text == "" {
				log.Logf(2, "aflow/gemini: replacing empty text part with fallback to initialize proto oneof field")
				text = "<no text generated>"
			}
			c.Parts = append(c.Parts, &genai.Part{
				Text:             text,
				Thought:          p.Thought,
				ThoughtSignature: p.ThoughtSignature,
			})
		}
	}
	return c
}

func fromGenaiResponse(resp *genai.GenerateContentResponse) *backend.GenerateResponse {
	res := &backend.GenerateResponse{}
	if resp.UsageMetadata != nil {
		res.UsageMetadata = &backend.UsageMetadata{
			// We add ToolUsePromptTokenCount just in case, but Gemini does not use/set it.
			InputTokens:          int(resp.UsageMetadata.PromptTokenCount) + int(resp.UsageMetadata.ToolUsePromptTokenCount),
			OutputTokens:         int(resp.UsageMetadata.CandidatesTokenCount),
			OutputThoughtsTokens: int(resp.UsageMetadata.ThoughtsTokenCount),
		}
	}
	if len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
		for _, p := range resp.Candidates[0].Content.Parts {
			if p.FunctionCall != nil {
				res.Parts = append(res.Parts, backend.Part{
					FunctionCall: &backend.FunctionCall{
						ID:   p.FunctionCall.ID,
						Name: p.FunctionCall.Name,
						Args: p.FunctionCall.Args,
					},
					ThoughtSignature: p.ThoughtSignature,
				})
			} else {
				res.Parts = append(res.Parts, backend.Part{
					Text:             p.Text,
					Thought:          p.Thought,
					ThoughtSignature: p.ThoughtSignature,
				})
			}
		}
	}
	return res
}
