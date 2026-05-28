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
	"github.com/google/syzkaller/pkg/mgrconfig"
)

type TargetConfig struct {
	KernelConfig string          `json:"kernel_config"`
	Image        string          `json:"image"`
	Type         string          `json:"type"`
	VM           json.RawMessage `json:"vm"`
	StraceBin    string          `json:"strace_bin"`

	TargetOS         string `json:"-"`
	TargetArch       string `json:"-"`
	TargetVMArch     string `json:"-"`
	kernelConfigData string `json:"-"`
}

type Config struct {
	HTTP string `json:"http"`
	// Start MCP server on the HTTP address, and don't connect to dashboard.
	MCP           bool   `json:"mcp"`
	DashboardAddr string `json:"dashboard_addr"`
	// Global non-namespace client.
	DashboardClient string                   `json:"dashboard_client"`
	DashboardKey    string                   `json:"dashboard_key"`
	SyzkallerRepo   string                   `json:"syzkaller_repo"`
	SyzkallerBranch string                   `json:"syzkaller_branch"`
	Targets         map[string]*TargetConfig `json:"targets"`
	CacheSize       uint64                   `json:"cache_size"`
	Model           string                   `json:"model"`
	Workflows       []string                 `json:"workflows"`
	GeminiAPIKey    string                   `json:"gemini_api_key"`
	CloudProject    string                   `json:"cloud_project"`
}

func loadConfig(configFile string) (*Config, error) {
	cfg := &Config{
		SyzkallerRepo:   "https://github.com/google/syzkaller.git",
		SyzkallerBranch: "master",
		CacheSize:       1 << 40, // 1TB
		GeminiAPIKey:    "env:GOOGLE_API_KEY",
		CloudProject:    "env:GOOGLE_CLOUD_PROJECT",
	}
	if err := config.LoadFile(configFile, cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("at least one target must be specified in config")
	}
	for target, tcfg := range cfg.Targets {
		osVal, vmarch, arch, _, _, err := mgrconfig.SplitTarget(target)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent target %q: %w", target, err)
		}
		tcfg.TargetOS = osVal
		tcfg.TargetArch = arch
		tcfg.TargetVMArch = vmarch

		if len(tcfg.VM) == 0 {
			continue
		}
		var vmCfg map[string]any
		if err := json.Unmarshal(tcfg.VM, &vmCfg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal VM config for target %q: %w", target, err)
		}
		if gcsPath, ok := vmCfg["gcs_path"].(string); ok {
			resolvedPath, err := gcpsecret.Resolve(context.Background(), gcsPath)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve gcs_path for target %q: %w", target, err)
			}
			vmCfg["gcs_path"] = resolvedPath
		}
		tcfg.VM, err = json.Marshal(vmCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal VM config for target %q: %w", target, err)
		}
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

	resolvedCloudProject, err := gcpsecret.Resolve(context.Background(), cfg.CloudProject)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CloudProject: %w", err)
	}
	if resolvedCloudProject != "" {
		os.Setenv("GOOGLE_CLOUD_PROJECT", resolvedCloudProject)
	}
	cfg.CloudProject = resolvedCloudProject

	return cfg, nil
}
