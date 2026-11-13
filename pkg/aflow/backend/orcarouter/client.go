// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package orcarouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

const (
	// requestTimeout matches the Gemini backend: a request that hangs this long
	// is aborted and retried.
	requestTimeout = 10 * time.Minute
	// maxResponseBytes bounds a single inference response.
	maxResponseBytes = 16 << 20
)

type client struct {
	p      *Provider
	apiKey string
}

type chatRequest struct {
	Model            string        `json:"model"`
	Messages         []chatMessage `json:"messages"`
	Tools            []chatTool    `json:"tools,omitempty"`
	ReasoningEffort  string        `json:"reasoning_effort,omitempty"`
	IncludeReasoning bool          `json:"include_reasoning,omitempty"`
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Name       string         `json:"name,omitempty"`
}

type chatToolCall struct {
	ID       string           `json:"id,omitempty"`
	Type     string           `json:"type"`
	Function chatFunctionCall `json:"function"`
}

type chatFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatTool struct {
	Type     string             `json:"type"`
	Function chatFunctionSchema `json:"function"`
}

type chatFunctionSchema struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   *chatUsage   `json:"usage"`
	Error   *struct {
		Message string          `json:"message"`
		Code    json.RawMessage `json:"code"`
	} `json:"error"`
}

type chatChoice struct {
	Message      chatReply `json:"message"`
	FinishReason string    `json:"finish_reason"`
}

type chatReply struct {
	Content          string `json:"content"`
	ReasoningContent string `json:"reasoning_content"`
	Refusal          string `json:"refusal"`
	ToolCalls        []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}

type chatUsage struct {
	PromptTokens      int `json:"prompt_tokens"`
	CompletionTokens  int `json:"completion_tokens"`
	CompletionDetails struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

// GenerateContent implements backend.Client.
func (c *client) GenerateContent(ctx context.Context, model string, cfg *backend.GenerateConfig,
	history []*backend.Message) (*backend.GenerateResponse, error) {
	if model == "" {
		model = DefaultModel
	}
	if err := c.p.validateModel(model); err != nil {
		return nil, err
	}
	request, err := buildChatRequest(model, cfg, history, c.p.modelInfo(model))
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("orcarouter: failed to encode request: %w", err)
	}

	timedCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(timedCtx, http.MethodPost,
		c.p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.p.httpClient.Do(httpReq)
	if err != nil {
		if timedCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			// The request hung; the parent context is still alive, so retry.
			return nil, &backend.RetryError{Delay: time.Second, Err: err}
		}
		return nil, fmt.Errorf("orcarouter: chat request failed: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("orcarouter: failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		err := httpStatusError(resp.StatusCode, fmt.Sprintf("request returned %d", resp.StatusCode), responseBody)
		if retryErr := new(backend.RetryError); errors.As(err, &retryErr) {
			if delay := retryAfterDelay(resp); delay > 0 {
				retryErr.Delay = delay
				retryErr.IsExponential = false
			}
		}
		return nil, err
	}
	return parseChatResponse(responseBody, model)
}

func buildChatRequest(model string, cfg *backend.GenerateConfig, history []*backend.Message,
	info *ModelInfo) (*chatRequest, error) {
	request := &chatRequest{Model: model}
	if cfg != nil && cfg.SystemInstruction != nil {
		if text := messageText(cfg.SystemInstruction); text != "" {
			request.Messages = append(request.Messages, chatMessage{Role: "system", Content: text})
		}
	}
	for _, msg := range history {
		request.Messages = append(request.Messages, convertMessage(msg)...)
	}
	if len(request.Messages) == 0 {
		return nil, errors.New("orcarouter: request has no messages")
	}
	if cfg != nil {
		request.Tools = convertTools(cfg.Tools)
		if info != nil {
			if cfg.ThinkingLevel > backend.ThinkingLevelMinimal &&
				containsString(info.SupportedParameters, "reasoning_effort") {
				request.ReasoningEffort = reasoningEffort(cfg.ThinkingLevel)
			}
			if cfg.IncludeThoughts && containsString(info.SupportedParameters, "include_reasoning") {
				request.IncludeReasoning = true
			}
		}
	}
	return request, nil
}

func convertMessage(msg *backend.Message) []chatMessage {
	role := "user"
	if msg.Role == backend.RoleModel {
		role = "assistant"
	}
	var text []string
	var calls []chatToolCall
	var toolMessages []chatMessage
	for _, part := range msg.Parts {
		switch {
		case part.FunctionCall != nil:
			args, err := json.Marshal(part.FunctionCall.Args)
			if err != nil || len(args) == 0 {
				args = []byte("{}")
			}
			calls = append(calls, chatToolCall{
				ID:   part.FunctionCall.ID,
				Type: "function",
				Function: chatFunctionCall{
					Name:      part.FunctionCall.Name,
					Arguments: string(args),
				},
			})
		case part.FunctionResponse != nil:
			payload, err := json.Marshal(part.FunctionResponse.Response)
			if err != nil || len(payload) == 0 {
				payload = []byte("{}")
			}
			toolMessages = append(toolMessages, chatMessage{
				Role:       "tool",
				Content:    string(payload),
				ToolCallID: part.FunctionResponse.ID,
				Name:       part.FunctionResponse.Name,
			})
		case part.Text != "" && !part.Thought:
			text = append(text, part.Text)
		}
	}
	var out []chatMessage
	if len(text) != 0 || len(calls) != 0 {
		out = append(out, chatMessage{Role: role, Content: strings.Join(text, "\n"), ToolCalls: calls})
	}
	return append(out, toolMessages...)
}

func messageText(msg *backend.Message) string {
	var text []string
	for _, part := range msg.Parts {
		if part.Text != "" && !part.Thought {
			text = append(text, part.Text)
		}
	}
	return strings.Join(text, "\n")
}

func convertTools(tools []*backend.Tool) []chatTool {
	var result []chatTool
	for _, tool := range tools {
		for _, declaration := range tool.FunctionDeclarations {
			if declaration == nil {
				continue
			}
			result = append(result, chatTool{
				Type: "function",
				Function: chatFunctionSchema{
					Name:        declaration.Name,
					Description: declaration.Description,
					Parameters:  declaration.ParametersJSONSchema,
				},
			})
		}
	}
	return result
}

func reasoningEffort(level backend.ThinkingLevel) string {
	switch level {
	case backend.ThinkingLevelLow:
		return "low"
	case backend.ThinkingLevelMedium:
		return "medium"
	case backend.ThinkingLevelHigh:
		return "high"
	default:
		return ""
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func parseChatResponse(body []byte, model string) (*backend.GenerateResponse, error) {
	var resp chatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("orcarouter: failed to parse response: %w", err)
	}
	if len(resp.Choices) == 0 {
		if resp.Error != nil {
			return nil, fmt.Errorf("orcarouter: model %q failed: %s", model, truncate(resp.Error.Message, 500))
		}
		return nil, fmt.Errorf("orcarouter: model %q returned an empty response", model)
	}
	choice := resp.Choices[0]
	switch choice.FinishReason {
	case "length":
		return nil, &backend.OutputTokenOverflowError{Err: errors.New("output token limit reached")}
	case "content_filter":
		return nil, &backend.BlockedError{Err: errors.New("response blocked by content filter")}
	}
	if choice.Message.Refusal != "" {
		return nil, &backend.BlockedError{Err: errors.New("model refused the request")}
	}
	result := &backend.GenerateResponse{}
	if resp.Usage != nil {
		result.UsageMetadata = &backend.UsageMetadata{
			InputTokens:          resp.Usage.PromptTokens,
			OutputTokens:         resp.Usage.CompletionTokens,
			OutputThoughtsTokens: resp.Usage.CompletionDetails.ReasoningTokens,
		}
	}
	if choice.Message.ReasoningContent != "" {
		result.Parts = append(result.Parts, backend.Part{Text: choice.Message.ReasoningContent, Thought: true})
	}
	if choice.Message.Content != "" {
		result.Parts = append(result.Parts, backend.Part{Text: choice.Message.Content})
	}
	for _, call := range choice.Message.ToolCalls {
		args := map[string]any{}
		if strings.TrimSpace(call.Function.Arguments) != "" {
			if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
				return nil, fmt.Errorf("orcarouter: model %q returned malformed tool arguments: %w", model, err)
			}
		}
		result.Parts = append(result.Parts, backend.Part{
			FunctionCall: &backend.FunctionCall{
				ID:   call.ID,
				Name: call.Function.Name,
				Args: args,
			},
		})
	}
	if len(result.Parts) == 0 {
		return nil, &backend.RetryError{Delay: 0, Err: fmt.Errorf("orcarouter: model %q returned no content", model)}
	}
	return result, nil
}
