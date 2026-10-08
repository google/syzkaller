// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/backend/gemini"
)

var flagNoSafetyFilters = flag.Bool("no-safety-filters", false, "disable safety filters for Gemini/Vertex requests")

func init() {
	RegisterProvider("gemini", func(ctx context.Context, model string) (backend.Provider, error) {
		apiKeys := gemini.ParseAPIKeys(cmp.Or(os.Getenv("GOOGLE_API_KEY"), os.Getenv("GEMINI_API_KEY")))
		if len(apiKeys) == 0 {
			return nil, fmt.Errorf("gemini provider requires GOOGLE_API_KEY or GEMINI_API_KEY environment variable to be set")
		}
		provider, err := gemini.NewProvider(ctx, gemini.Config{
			ModelOverride:   model,
			NoSafetyFilters: *flagNoSafetyFilters,
			APIKeys:         apiKeys,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Gemini provider: %w", err)
		}
		return provider, nil
	})

	RegisterProvider("vertex", func(ctx context.Context, model string) (backend.Provider, error) {
		project := os.Getenv("GOOGLE_CLOUD_PROJECT")
		if project == "" {
			return nil, fmt.Errorf("vertex provider requires GOOGLE_CLOUD_PROJECT environment variable to be set")
		}
		location := os.Getenv("GOOGLE_CLOUD_REGION")
		if location == "" {
			location = "global"
		}
		provider, err := gemini.NewProvider(ctx, gemini.Config{
			ModelOverride:   model,
			NoSafetyFilters: *flagNoSafetyFilters,
			VertexProject:   project,
			VertexLocation:  location,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Vertex provider: %w", err)
		}
		return provider, nil
	})
}
