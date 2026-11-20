// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package orcarouter

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiveOrcaRouter exercises the real OrcaRouter inference and catalog
// endpoints through the provider implemented in this package. It is skipped
// when no integration key is present and is the only test that touches the
// network.
func TestLiveOrcaRouter(t *testing.T) {
	apiKey := os.Getenv("ORCAROUTER_API_KEY")
	if apiKey == "" {
		t.Skip("ORCAROUTER_API_KEY is not set")
	}
	baseURL, err := ResolveBaseURL("")
	require.NoError(t, err)
	provider, err := NewProvider(context.Background(), Config{
		APIKeys:          []string{apiKey},
		BaseURL:          baseURL,
		DiscoveryTimeout: time.Minute,
	})
	require.NoError(t, err)
	defer provider.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	models, err := provider.Models(ctx)
	require.NoError(t, err, "live model discovery must succeed")
	require.NotEmpty(t, models)
	source, statusErr := provider.CatalogStatus()
	require.NoError(t, statusErr)
	assert.Equal(t, catalogSourceLive, source)
	t.Logf("live catalog: %d text chat models", len(models))

	// Prefer the dedicated cyber tier; fall back to an explicitly requested
	// model, then to the public model used for connectivity verification.
	candidates := []string{CyberUltraModel, CyberZeroModel}
	if model := os.Getenv("ORCAROUTER_TEST_MODEL"); model != "" {
		candidates = append(candidates, model)
	}
	candidates = append(candidates, "deepseek/deepseek-v4.1-flash")

	client, err := provider.Client(ctx)
	require.NoError(t, err)
	var lastErr error
	for _, model := range candidates {
		if !slices.Contains(models, model) {
			continue
		}
		response, err := client.GenerateContent(ctx, model, &backend.GenerateConfig{},
			[]*backend.Message{{
				Role:  backend.RoleUser,
				Parts: []backend.Part{{Text: "Reply with the single word ok."}},
			}})
		if err != nil {
			lastErr = err
			assert.NotContains(t, err.Error(), apiKey)
			t.Logf("model %s not usable with this key: %v", model, err)
			continue
		}
		require.NotNil(t, response)
		require.NotEmpty(t, response.Parts)
		if response.UsageMetadata != nil {
			t.Logf("live inference ok: model=%s input_tokens=%d output_tokens=%d",
				model, response.UsageMetadata.InputTokens, response.UsageMetadata.OutputTokens)
		} else {
			t.Logf("live inference ok: model=%s", model)
		}
		return
	}
	require.NoError(t, lastErr, "no catalog model was usable with this key")
	t.Fatal("live catalog contained no candidate model")
}
