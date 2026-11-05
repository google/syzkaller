// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package orcarouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAPIKey is a fake credential. No real key is used anywhere in the suite.
const testAPIKey = "test-orcarouter-key-not-real"

const testCatalog = `{"data":[
 {"id":"vendor/text-chat","supported_endpoint_types":["openai"],
  "architecture":{"input_modalities":["text"],"output_modalities":["text"]},
  "context_length":131072},
 {"id":"vendor/image-chat","supported_endpoint_types":["openai","anthropic"],
  "architecture":{"input_modalities":["text","image"],"output_modalities":["text"]}},
 {"id":"vendor/embedding","supported_endpoint_types":["embeddings"],
  "architecture":{"input_modalities":["text"],"output_modalities":["embedding"]}},
 {"id":"vendor/image-gen","supported_endpoint_types":["image-generation"],
  "architecture":{"input_modalities":["text"],"output_modalities":["image"]}},
 {"id":"vendor/video","supported_endpoint_types":["openai-video"],
  "architecture":{"input_modalities":["text"],"output_modalities":["video"]}},
 {"id":"vendor/rerank","supported_endpoint_types":["jina-rerank"],
  "architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
 {"id":"vendor/audio-only","supported_endpoint_types":["openai"],
  "architecture":{"input_modalities":["audio"],"output_modalities":["text"]}},
 {"id":"vendor/no-metadata"},
 {"id":"orcarouter/auto","supported_endpoint_types":["openai","openai-response","anthropic","gemini"]},
 {"id":"orca/orcacyber-ultra-1.0","supported_endpoint_types":["openai"],
  "architecture":{"input_modalities":["text"],"output_modalities":["text"]}},
 {"id":"orca/orcacyber-zero-1.5","supported_endpoint_types":["openai"],
  "architecture":{"input_modalities":["text"],"output_modalities":["text"]}}
]}`

func newTestProvider(t *testing.T, handler http.HandlerFunc) *Provider {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	provider, err := NewProvider(context.Background(), Config{
		APIKeys:          []string{testAPIKey},
		BaseURL:          server.URL + "/v1",
		HTTPClient:       server.Client(),
		DiscoveryTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	return provider
}

func serveCatalog(t *testing.T) *Provider {
	t.Helper()
	return newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, "Bearer "+testAPIKey, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, err := io.WriteString(w, testCatalog)
		assert.NoError(t, err)
	})
}

func TestParseAPIKeys(t *testing.T) {
	assert.Empty(t, ParseAPIKeys(""))
	assert.Empty(t, ParseAPIKeys(" \n\t\n"))
	assert.Equal(t, []string{"a", "b"}, ParseAPIKeys(" a \n\nb\n"))
}

func TestResolveBaseURL(t *testing.T) {
	t.Setenv("ORCA_API_BASE_URL", "")
	t.Setenv("ORCA_BASE_URL", "")
	base, err := ResolveBaseURL("")
	require.NoError(t, err)
	assert.Equal(t, DefaultBaseURL, base)

	t.Setenv("ORCA_BASE_URL", "https://shared.example/v1")
	base, err = ResolveBaseURL("")
	require.NoError(t, err)
	assert.Equal(t, "https://shared.example/v1", base)

	t.Setenv("ORCA_API_BASE_URL", "https://api.example/v1")
	base, err = ResolveBaseURL("https://explicit.example/v1")
	require.NoError(t, err)
	assert.Equal(t, "https://explicit.example/v1", base)

	_, err = ResolveBaseURL("http://api.example/v1")
	require.ErrorContains(t, err, "https")

	base, err = ResolveBaseURL("http://127.0.0.1:8080/v1")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/v1", base)

	_, err = ResolveBaseURL("http://localhost:8080/v1")
	require.NoError(t, err)

	_, err = ResolveBaseURL("https://user:pass@example.com/v1")
	require.Error(t, err)
}

func TestModelDiscoveryFiltersCapabilities(t *testing.T) {
	provider := serveCatalog(t)
	models, err := provider.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{
		"orca/orcacyber-ultra-1.0",
		"orca/orcacyber-zero-1.5",
		"orcarouter/auto",
		"vendor/image-chat",
		"vendor/text-chat",
	}, models)
	source, statusErr := provider.CatalogStatus()
	assert.Equal(t, catalogSourceLive, source)
	assert.NoError(t, statusErr)
}

func TestCapabilityFilters(t *testing.T) {
	raw, err := parseCatalog([]byte(testCatalog))
	require.NoError(t, err)
	tests := map[Capability][]string{
		CapabilityChat: {"orca/orcacyber-ultra-1.0", "orca/orcacyber-zero-1.5",
			"orcarouter/auto", "vendor/image-chat", "vendor/text-chat"},
		CapabilityEmbedding: {"vendor/embedding"},
		CapabilityImage:     {"vendor/image-gen"},
		CapabilityVideo:     {"vendor/video"},
		CapabilityRerank:    {"vendor/rerank"},
	}
	for capability, want := range tests {
		got, _ := filterCatalog(raw, capability)
		assert.Equal(t, want, got, "capability %v", capability)
	}
}

func TestCatalogFallbackOnError(t *testing.T) {
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"backend down"}}`, http.StatusInternalServerError)
	})
	models, err := provider.Models(context.Background())
	require.Error(t, err)
	assert.NotEmpty(t, models)
	assert.Contains(t, models, DefaultModel)
	assert.Contains(t, models, CyberUltraModel)
	source, statusErr := provider.CatalogStatus()
	assert.Equal(t, catalogSourceSeed, source)
	assert.Error(t, statusErr)
}

func TestCatalogAuthError(t *testing.T) {
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := io.WriteString(w, `{"error":{"code":"invalid_api_key","message":"bad key"}}`)
		assert.NoError(t, err)
	})
	_, err := provider.Models(context.Background())
	require.Error(t, err)
	var authErr *AuthError
	require.ErrorAs(t, err, &authErr)
	assert.NotContains(t, err.Error(), testAPIKey)
}

func TestResolveModels(t *testing.T) {
	provider := serveCatalog(t)
	require.Equal(t, []string{CyberUltraModel, CyberZeroModel, DefaultModel},
		provider.ResolveModels(backend.DeepReasoningModel))
	require.Equal(t, []string{DefaultModel, CyberUltraModel},
		provider.ResolveModels(backend.CoreModel))
	require.Equal(t, []string{DefaultModel}, provider.ResolveModels("unknown"))

	override, err := NewProvider(context.Background(), Config{
		APIKeys: []string{testAPIKey}, ModelOverride: "vendor/custom",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"vendor/custom"}, override.ResolveModels(backend.CoreModel))
}

func TestResolveModelsFiltersUnavailable(t *testing.T) {
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, `{"data":[
		 {"id":"vendor/only","supported_endpoint_types":["openai"]}]}`)
		assert.NoError(t, err)
	})
	assert.Equal(t, []string{"vendor/only"}, provider.ResolveModels(backend.DeepReasoningModel))
}

func TestGenerateContentRequestAndResponse(t *testing.T) {
	var captured chatRequest
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, err := io.WriteString(w, testCatalog)
			assert.NoError(t, err)
			return
		}
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "Bearer "+testAPIKey, r.Header.Get("Authorization"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &captured))
		w.Header().Set("Content-Type", "application/json")
		_, err = io.WriteString(w, `{"choices":[{"message":{
			"content":"done","reasoning_content":"thinking",
			"tool_calls":[{"id":"call-1","type":"function",
			  "function":{"name":"do_it","arguments":"{\"ok\":true}"}}]},
			"finish_reason":"tool_calls"}],
			"usage":{"prompt_tokens":10,"completion_tokens":5,
			  "completion_tokens_details":{"reasoning_tokens":2}}}`)
		assert.NoError(t, err)
	})
	_, err := provider.Models(context.Background())
	require.NoError(t, err)

	cfg := &backend.GenerateConfig{
		SystemInstruction: &backend.Message{Parts: []backend.Part{{Text: "be useful"}}},
		Tools: []*backend.Tool{{FunctionDeclarations: []*backend.FunctionDeclaration{{
			Name:        "do_it",
			Description: "does it",
		}}}},
	}
	history := []*backend.Message{
		{Role: backend.RoleUser, Parts: []backend.Part{{Text: "hello"}}},
		{Role: backend.RoleModel, Parts: []backend.Part{
			{Thought: true, Text: "internal"},
			{FunctionCall: &backend.FunctionCall{ID: "call-1", Name: "do_it", Args: map[string]any{"x": 1}}},
		}},
		{Role: backend.RoleUser, Parts: []backend.Part{
			{FunctionResponse: &backend.FunctionResponse{
				ID: "call-1", Name: "do_it", Response: map[string]any{"ok": true},
			}},
		}},
	}
	client, err := provider.Client(context.Background())
	require.NoError(t, err)
	response, err := client.GenerateContent(context.Background(), "vendor/text-chat", cfg, history)
	require.NoError(t, err)

	assert.Equal(t, "vendor/text-chat", captured.Model)
	require.Len(t, captured.Messages, 4)
	assert.Equal(t, chatMessage{Role: "system", Content: "be useful"}, captured.Messages[0])
	assert.Equal(t, chatMessage{Role: "user", Content: "hello"}, captured.Messages[1])
	require.Len(t, captured.Messages[2].ToolCalls, 1)
	assert.Equal(t, "do_it", captured.Messages[2].ToolCalls[0].Function.Name)
	assert.Equal(t, "assistant", captured.Messages[2].Role)
	assert.Equal(t, "tool", captured.Messages[3].Role)
	assert.Equal(t, "call-1", captured.Messages[3].ToolCallID)
	require.Len(t, captured.Tools, 1)
	assert.Equal(t, "do_it", captured.Tools[0].Function.Name)
	assert.Empty(t, captured.ReasoningEffort, "model does not declare reasoning_effort")

	require.NotNil(t, response.UsageMetadata)
	assert.Equal(t, 10, response.UsageMetadata.InputTokens)
	assert.Equal(t, 5, response.UsageMetadata.OutputTokens)
	assert.Equal(t, 2, response.UsageMetadata.OutputThoughtsTokens)
	require.Len(t, response.Parts, 3)
	assert.True(t, response.Parts[0].Thought)
	assert.Equal(t, "thinking", response.Parts[0].Text)
	assert.Equal(t, "done", response.Parts[1].Text)
	require.NotNil(t, response.Parts[2].FunctionCall)
	assert.Equal(t, "do_it", response.Parts[2].FunctionCall.Name)
	assert.Equal(t, map[string]any{"ok": true}, response.Parts[2].FunctionCall.Args)
}

func TestGenerateContentReasoningEffort(t *testing.T) {
	var captured chatRequest
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, err := io.WriteString(w, `{"data":[{"id":"vendor/reasoning",
			 "supported_endpoint_types":["openai"],"supported_parameters":["reasoning_effort"]}]}`)
			assert.NoError(t, err)
			return
		}
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &captured))
		_, err = io.WriteString(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`)
		assert.NoError(t, err)
	})
	_, err := provider.Models(context.Background())
	require.NoError(t, err)
	client, err := provider.Client(context.Background())
	require.NoError(t, err)
	_, err = client.GenerateContent(context.Background(), "vendor/reasoning",
		&backend.GenerateConfig{ThinkingLevel: backend.ThinkingLevelHigh},
		[]*backend.Message{{Role: backend.RoleUser, Parts: []backend.Part{{Text: "hi"}}}})
	require.NoError(t, err)
	assert.Equal(t, "high", captured.ReasoningEffort)
}

func TestHTTPErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		check  func(*testing.T, error)
	}{
		{"auth", 401, `{"error":{"code":"invalid_api_key","message":"bad"}}`, func(t *testing.T, err error) {
			var target *AuthError
			require.ErrorAs(t, err, &target)
		}},
		{"access", 403, `{"error":{"code":"model_access_denied","message":"no"}}`, func(t *testing.T, err error) {
			var target *AccessError
			require.ErrorAs(t, err, &target)
		}},
		{"rate limit", 429, `{"error":{"message":"slow down"}}`, func(t *testing.T, err error) {
			var target *backend.RetryError
			require.ErrorAs(t, err, &target)
			assert.Equal(t, 30*time.Second, target.Delay)
		}},
		{"server", 503, `{"error":{"message":"upstream"}}`, func(t *testing.T, err error) {
			var target *backend.RetryError
			require.ErrorAs(t, err, &target)
			assert.True(t, target.IsExponential)
		}},
		{"context overflow", 400, `{"error":{"message":"maximum context length exceeded"}}`,
			func(t *testing.T, err error) {
				var target *backend.InputTokenOverflowError
				require.ErrorAs(t, err, &target)
			}},
		{"bad request", 400, `{"error":{"message":"invalid schema"}}`, func(t *testing.T, err error) {
			require.ErrorContains(t, err, "invalid schema")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/models" {
					_, err := io.WriteString(w, `{"data":[{"id":"vendor/model",
					 "supported_endpoint_types":["openai"]}]}`)
					assert.NoError(t, err)
					return
				}
				w.WriteHeader(test.status)
				_, err := io.WriteString(w, test.body)
				assert.NoError(t, err)
			})
			_, err := provider.Models(context.Background())
			require.NoError(t, err)
			client, err := provider.Client(context.Background())
			require.NoError(t, err)
			_, err = client.GenerateContent(context.Background(), "vendor/model", nil,
				[]*backend.Message{{Role: backend.RoleUser, Parts: []backend.Part{{Text: "hi"}}}})
			require.Error(t, err)
			test.check(t, err)
			assert.NotContains(t, err.Error(), testAPIKey)
		})
	}
}

func TestRetryAfterHeader(t *testing.T) {
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, err := io.WriteString(w, `{"data":[{"id":"vendor/model","supported_endpoint_types":["openai"]}]}`)
			assert.NoError(t, err)
			return
		}
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := provider.Models(context.Background())
	require.NoError(t, err)
	client, err := provider.Client(context.Background())
	require.NoError(t, err)
	_, err = client.GenerateContent(context.Background(), "vendor/model", nil,
		[]*backend.Message{{Role: backend.RoleUser, Parts: []backend.Part{{Text: "hi"}}}})
	var retryErr *backend.RetryError
	require.ErrorAs(t, err, &retryErr)
	assert.Equal(t, 7*time.Second, retryErr.Delay)
}

func TestResponseErrorMapping(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		check func(*testing.T, error)
	}{
		{"output overflow", `{"choices":[{"message":{"content":"x"},"finish_reason":"length"}]}`,
			func(t *testing.T, err error) {
				var target *backend.OutputTokenOverflowError
				require.ErrorAs(t, err, &target)
			}},
		{"content filter", `{"choices":[{"message":{"content":"x"},"finish_reason":"content_filter"}]}`,
			func(t *testing.T, err error) {
				var target *backend.BlockedError
				require.ErrorAs(t, err, &target)
			}},
		{"refusal", `{"choices":[{"message":{"refusal":"no"},"finish_reason":"stop"}]}`,
			func(t *testing.T, err error) {
				var target *backend.BlockedError
				require.ErrorAs(t, err, &target)
			}},
		{"empty", `{}`, func(t *testing.T, err error) {
			require.ErrorContains(t, err, "empty response")
		}},
		{"malformed arguments", `{"choices":[{"message":{"tool_calls":[{"id":"1",
		 "function":{"name":"f","arguments":"{"}}]},"finish_reason":"tool_calls"}]}`,
			func(t *testing.T, err error) {
				require.ErrorContains(t, err, "malformed tool arguments")
			}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/models" {
					_, err := io.WriteString(w, `{"data":[{"id":"vendor/model",
					 "supported_endpoint_types":["openai"]}]}`)
					assert.NoError(t, err)
					return
				}
				_, err := io.WriteString(w, test.body)
				assert.NoError(t, err)
			})
			_, err := provider.Models(context.Background())
			require.NoError(t, err)
			client, err := provider.Client(context.Background())
			require.NoError(t, err)
			_, err = client.GenerateContent(context.Background(), "vendor/model", nil,
				[]*backend.Message{{Role: backend.RoleUser, Parts: []backend.Part{{Text: "hi"}}}})
			require.Error(t, err)
			test.check(t, err)
			assert.NotContains(t, err.Error(), testAPIKey)
		})
	}
}

func TestUnknownModelFailsClosed(t *testing.T) {
	provider := serveCatalog(t)
	_, err := provider.Models(context.Background())
	require.NoError(t, err)
	client, err := provider.Client(context.Background())
	require.NoError(t, err)
	_, err = client.GenerateContent(context.Background(), "vendor/embedding", nil,
		[]*backend.Message{{Role: backend.RoleUser, Parts: []backend.Part{{Text: "hi"}}}})
	require.ErrorContains(t, err, "not in the OrcaRouter text model catalog")
	assert.Contains(t, err.Error(), "vendor/text-chat")
}

func TestNoAPIFailsFast(t *testing.T) {
	_, err := NewProvider(context.Background(), Config{})
	require.Error(t, err)
}

func TestProviderClientRoundRobin(t *testing.T) {
	provider, err := NewProvider(context.Background(), Config{
		APIKeys: []string{"one", "two"}, BaseURL: DefaultBaseURL,
	})
	require.NoError(t, err)
	first, err := provider.Client(context.Background())
	require.NoError(t, err)
	second, err := provider.Client(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, first.(*client).apiKey, second.(*client).apiKey)
	assert.True(t, slices.Contains([]string{"one", "two"}, first.(*client).apiKey))
}

func TestErrorsDoNotContainSecrets(t *testing.T) {
	provider := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := io.WriteString(w, `{"error":{"code":"invalid_api_key","message":"denied"}}`)
		assert.NoError(t, err)
	})
	_, err := provider.Models(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testAPIKey)
	assert.False(t, strings.Contains(err.Error(), "Bearer"))
}

func TestHTTPStatusErrorBoundsMessage(t *testing.T) {
	long := strings.Repeat("x", 1000)
	err := httpStatusError(http.StatusBadRequest, "fallback", []byte(`{"error":{"message":"`+long+`"}}`))
	require.Error(t, err)
	assert.LessOrEqual(t, len(err.Error()), 600)
}

func TestUnexpectedErrorMessageFormat(t *testing.T) {
	// Some gateways wrap errors under a plain string instead of an object.
	err := httpStatusError(http.StatusBadRequest, "fallback", []byte(`{"error":"bad"}`))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "invalid")
}

func TestRetryErrorPreservesCause(t *testing.T) {
	err := httpStatusError(http.StatusServiceUnavailable, "down", nil)
	var retryErr *backend.RetryError
	require.ErrorAs(t, err, &retryErr)
	require.Error(t, errors.Unwrap(retryErr))
}
