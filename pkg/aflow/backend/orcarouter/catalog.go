// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package orcarouter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Capability is a model capability the provider can filter for. syzkaller's
// workflows only submit text chat with tools, so discovery uses
// CapabilityChat, but the filter keeps the other catalog classes explicit and
// testable instead of guessing from model names.
type Capability string

const (
	CapabilityChat      Capability = "chat"
	CapabilityEmbedding Capability = "embedding"
	CapabilityImage     Capability = "image"
	CapabilityVideo     Capability = "video"
	CapabilityRerank    Capability = "rerank"
)

var chatEndpointTypes = map[string]bool{
	"openai":          true,
	"openai-response": true,
	"anthropic":       true,
	"gemini":          true,
}

type catalogResponse struct {
	Data []rawModel `json:"data"`
}

type rawModel struct {
	ID                     string   `json:"id"`
	SupportedEndpointTypes []string `json:"supported_endpoint_types"`
	SupportedParameters    []string `json:"supported_parameters"`
	ContextLength          int      `json:"context_length"`
	MaxCompletionTokens    int      `json:"max_completion_tokens"`
	Architecture           struct {
		InputModalities  []string `json:"input_modalities"`
		OutputModalities []string `json:"output_modalities"`
	} `json:"architecture"`
}

// discover fetches GET /v1/models and returns the text chat models that this
// key can use, together with their capability metadata.
func (p *Provider) discover(ctx context.Context) ([]string, map[string]*ModelInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, p.discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/models", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.key())
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("orcarouter: model discovery request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("orcarouter: failed to read model catalog: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("orcarouter: model discovery failed: %w",
			httpStatusError(resp.StatusCode, fmt.Sprintf("model discovery returned %d", resp.StatusCode), body))
	}
	raw, err := parseCatalog(body)
	if err != nil {
		return nil, nil, err
	}
	models, info := filterCatalog(raw, CapabilityChat)
	if len(models) == 0 {
		return nil, nil, fmt.Errorf("orcarouter: model catalog has no compatible text chat models")
	}
	return models, info, nil
}

func parseCatalog(body []byte) ([]rawModel, error) {
	var resp catalogResponse
	if err := json.Unmarshal(body, &resp); err == nil && resp.Data != nil {
		return boundCatalog(resp.Data), nil
	}
	// Some deployments return a bare array instead of the OpenAI envelope.
	var items []rawModel
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("orcarouter: failed to parse model catalog: %w", err)
	}
	return boundCatalog(items), nil
}

func boundCatalog(models []rawModel) []rawModel {
	if len(models) > maxCatalogModels {
		models = models[:maxCatalogModels]
	}
	return models
}

// filterCatalog keeps the models that match capability and returns their IDs
// together with their metadata. Records without capability metadata fail
// closed: a name is not proof of a capability.
func filterCatalog(raw []rawModel, capability Capability) ([]string, map[string]*ModelInfo) {
	var ids []string
	info := make(map[string]*ModelInfo)
	for _, m := range raw {
		if m.ID == "" || info[m.ID] != nil {
			continue
		}
		if !matchesCapability(&m, capability) {
			continue
		}
		ids = append(ids, m.ID)
		info[m.ID] = &ModelInfo{
			ID:                     m.ID,
			InputModalities:        slices.Clone(m.Architecture.InputModalities),
			OutputModalities:       slices.Clone(m.Architecture.OutputModalities),
			SupportedEndpointTypes: slices.Clone(m.SupportedEndpointTypes),
			SupportedParameters:    slices.Clone(m.SupportedParameters),
			ContextLength:          m.ContextLength,
			MaxCompletionTokens:    m.MaxCompletionTokens,
		}
	}
	sort.Strings(ids)
	return ids, info
}

func matchesCapability(m *rawModel, capability Capability) bool {
	endpoints := m.SupportedEndpointTypes
	switch capability {
	case CapabilityChat:
		if len(endpoints) > 0 &&
			!slices.ContainsFunc(endpoints, func(e string) bool { return chatEndpointTypes[e] }) {
			return false
		}
		if len(m.Architecture.OutputModalities) > 0 &&
			!slices.Contains(m.Architecture.OutputModalities, "text") {
			return false
		}
		if len(m.Architecture.InputModalities) > 0 &&
			!slices.Contains(m.Architecture.InputModalities, "text") {
			return false
		}
		// Fail closed unless the record declares at least one capability field.
		return len(endpoints) > 0 || len(m.Architecture.InputModalities) > 0 ||
			len(m.Architecture.OutputModalities) > 0
	case CapabilityEmbedding:
		return slices.Contains(endpoints, "embeddings")
	case CapabilityImage:
		return slices.Contains(endpoints, "image-generation")
	case CapabilityVideo:
		return slices.Contains(endpoints, "openai-video")
	case CapabilityRerank:
		return slices.Contains(endpoints, "jina-rerank")
	}
	return false
}

// seedModel describes one verified fallback model.
type seedModel struct {
	id              string
	contextLength   int
	maxOutput       int
	reasoningEffort bool
}

var verifiedSeed = []seedModel{
	{id: "openai/gpt-5.5", contextLength: 400000, maxOutput: 128000, reasoningEffort: true},
	{id: "anthropic/claude-opus-4.8", contextLength: 200000, maxOutput: 64000},
	{id: "google/gemini-3.5-flash", contextLength: 1048576, maxOutput: 65536},
	{id: "deepseek/deepseek-v4-pro", contextLength: 1048576, maxOutput: 384000, reasoningEffort: true},
	{id: DefaultModel},
	{id: CyberUltraModel, contextLength: 1048576, maxOutput: 131072},
	{id: CyberZeroModel, contextLength: 1000000, maxOutput: 131072},
}

// seedCatalog returns the verified fallback IDs used when live discovery fails.
func seedCatalog() []string {
	ids := make([]string, 0, len(verifiedSeed))
	for _, model := range verifiedSeed {
		ids = append(ids, model.id)
	}
	return ids
}

// seedModelInfo returns capability metadata for the verified fallback models.
func seedModelInfo() map[string]*ModelInfo {
	info := make(map[string]*ModelInfo, len(verifiedSeed))
	for _, model := range verifiedSeed {
		entry := &ModelInfo{
			ID:                     model.id,
			InputModalities:        []string{"text"},
			OutputModalities:       []string{"text"},
			SupportedEndpointTypes: []string{"openai"},
			ContextLength:          model.contextLength,
			MaxCompletionTokens:    model.maxOutput,
		}
		if model.reasoningEffort {
			entry.SupportedParameters = []string{"reasoning_effort"}
		}
		info[model.id] = entry
	}
	return info
}

// modelInfo returns metadata for a model, falling back to the verified seed.
func (p *Provider) modelInfo(model string) *ModelInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	if info := p.models[model]; info != nil {
		return info
	}
	return seedModelInfo()[model]
}

// describeModels renders a bounded, human-readable list for errors.
func describeModels(models []string) string {
	const limit = 12
	if len(models) <= limit {
		return strings.Join(models, ", ")
	}
	return strings.Join(models[:limit], ", ") + ", ..."
}
