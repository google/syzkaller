// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/backend/orcarouter"
)

func init() {
	RegisterProvider("orcarouter", func(ctx context.Context, model string) (backend.Provider, error) {
		apiKeys := orcarouter.ParseAPIKeys(os.Getenv("ORCAROUTER_API_KEY"))
		if len(apiKeys) == 0 {
			return nil, fmt.Errorf("orcarouter provider requires ORCAROUTER_API_KEY environment variable to be set")
		}
		provider, err := orcarouter.NewProvider(ctx, orcarouter.Config{
			ModelOverride: model,
			APIKeys:       apiKeys,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OrcaRouter provider: %w", err)
		}
		return provider, nil
	})
}
