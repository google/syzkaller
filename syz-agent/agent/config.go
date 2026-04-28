// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gcpsecret"
)

type Config struct {
	HTTP            string          `json:"http"`
	MCP             bool            `json:"mcp"` // Start MCP server on the HTTP address, and don't connect to dashboard.
	DashboardAddr   string          `json:"dashboard_addr"`
	DashboardClient string          `json:"dashboard_client"` // Global non-namespace client.
	DashboardKey    string          `json:"dashboard_key"`
	SyzkallerRepo   string          `json:"syzkaller_repo"`
	SyzkallerBranch string          `json:"syzkaller_branch"`
	KernelConfig    string          `json:"kernel_config"`
	Target          string          `json:"target"`
	Image           string          `json:"image"`
	Type            string          `json:"type"`
	VM              json.RawMessage `json:"vm"`
	CacheSize       uint64          `json:"cache_size"`
	FixedBaseCommit string          `json:"fixed_base_commit"`
	FixedRepository string          `json:"repo"`
	Model           string          `json:"model"`
	Workflows       []string        `json:"workflows"`
	GeminiAPIKey    string          `json:"gemini_api_key"`

	kernelConfigData string
}

func loadConfig(configFile string) (*Config, error) {
	cfg := &Config{
		SyzkallerRepo:   "https://github.com/google/syzkaller.git",
		SyzkallerBranch: "master",
		CacheSize:       1 << 40, // 1TB
		GeminiAPIKey:    "env:GOOGLE_API_KEY",
	}
	if err := config.LoadFile(configFile, cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	resolvedDashKey, err := gcpsecret.Resolve(context.Background(), cfg.DashboardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DashboardKey: %w", err)
	}
	cfg.DashboardKey = resolvedDashKey

	resolvedDashClient, err := gcpsecret.Resolve(context.Background(), cfg.DashboardClient)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DashboardClient: %w", err)
	}
	cfg.DashboardClient = resolvedDashClient

	resolvedGeminiKey, err := gcpsecret.Resolve(context.Background(), cfg.GeminiAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve GeminiAPIKey: %w", err)
	}
	if resolvedGeminiKey != "" {
		os.Setenv("GOOGLE_API_KEY", resolvedGeminiKey)
	}
	cfg.GeminiAPIKey = resolvedGeminiKey

	return cfg, nil
}
