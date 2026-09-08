// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/backend/gemini"
	"google.golang.org/genai"
)

var flagNoSafetyFilters = flag.Bool("no-safety-filters", false, "disable safety filters for Gemini/Vertex requests")

func init() {
	RegisterProvider("gemini", func(ctx context.Context, model string) (backend.Provider, error) {
		rawKeys := cmp.Or(
			os.Getenv("GEMINI_API_KEYS"),
			os.Getenv("GOOGLE_API_KEYS"),
			os.Getenv("GEMINI_API_KEY"),
			os.Getenv("GOOGLE_API_KEY"),
		)
		keys := parseAPIKeys(rawKeys)
		if len(keys) == 0 {
			return nil, fmt.Errorf("gemini provider requires GEMINI_API_KEYS, GEMINI_API_KEY, " +
				"GOOGLE_API_KEYS, or GOOGLE_API_KEY environment variable to be set")
		}
		var providers []backend.Provider
		for _, key := range keys {
			prov, err := gemini.NewProvider(ctx, gemini.Config{
				ModelOverride:   model,
				NoSafetyFilters: *flagNoSafetyFilters,
				ClientConfig:    &genai.ClientConfig{APIKey: key},
			})
			if err != nil {
				for _, p := range providers {
					p.Close()
				}
				return nil, fmt.Errorf("failed to initialize Gemini provider: %w", err)
			}
			providers = append(providers, prov)
		}
		if len(providers) == 1 {
			return providers[0], nil
		}
		return newRotatingProvider(providers), nil
	})

	RegisterProvider("vertex", func(ctx context.Context, model string) (backend.Provider, error) {
		project := os.Getenv("GOOGLE_CLOUD_PROJECT")
		if project == "" {
			return nil, fmt.Errorf("vertex provider requires GOOGLE_CLOUD_PROJECT environment variable to be set")
		}
		location := cmp.Or(os.Getenv("GOOGLE_CLOUD_REGION"), "global")
		provider, err := gemini.NewProvider(ctx, gemini.Config{
			ModelOverride:   model,
			NoSafetyFilters: *flagNoSafetyFilters,
			ClientConfig: &genai.ClientConfig{
				Backend:  genai.BackendVertexAI,
				Project:  project,
				Location: location,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Vertex provider: %w", err)
		}
		return provider, nil
	})
}

func parseAPIKeys(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

type rotatingProvider struct {
	backend.Provider
	providers  []backend.Provider
	nextClient atomic.Uint64
}

func newRotatingProvider(providers []backend.Provider) *rotatingProvider {
	return &rotatingProvider{
		Provider:  providers[0],
		providers: providers,
	}
}

func (p *rotatingProvider) Client(ctx context.Context) (backend.Client, error) {
	idx := int(p.nextClient.Add(1)-1) % len(p.providers)
	return p.providers[idx].Client(ctx)
}

func (p *rotatingProvider) Close() error {
	var errs []error
	for _, prov := range p.providers {
		errs = append(errs, prov.Close())
	}
	return errors.Join(errs...)
}
