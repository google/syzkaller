// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/google/syzkaller/pkg/aflow/flow/reproc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	if os.Getenv("GOOGLE_CLOUD_PROJECT") == "" {
		os.Setenv("GOOGLE_CLOUD_PROJECT", "test-project")
	}
}

func TestConfigPlainValues(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "syz-agent-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	confFile := filepath.Join(tmpDir, "config.json")
	content := `{
		"targets": {
			"linux/amd64": {
				"image": "image1"
			}
		},
		"dashboard_client": "test-dashboard-client",
		"dashboard_key": "test-dashboard-key",
		"gemini_api_key": "test-gemini-key"
	}`
	err = os.WriteFile(confFile, []byte(content), 0644)
	assert.NoError(t, err)

	cfg, err := loadConfig(confFile)
	assert.NoError(t, err)

	assert.Equal(t, "test-dashboard-client", cfg.DashboardClient)
	assert.Equal(t, "test-dashboard-key", cfg.DashboardKey)
	assert.Equal(t, "test-gemini-key", cfg.GeminiAPIKey)
	assert.True(t, cfg.SafetyFilters)
}

func TestConfigEnvResolution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "syz-agent-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	confFile := filepath.Join(tmpDir, "config.json")
	content := `{
		"targets": {
			"linux/amd64": {
				"image": "image1"
			}
		},
		"dashboard_client": "env:CLIENT_ENV",
		"dashboard_key": "env:DASHBOARD_ENV",
		"gemini_api_key": "env:GEMINI_ENV"
	}`
	err = os.WriteFile(confFile, []byte(content), 0644)
	assert.NoError(t, err)

	os.Setenv("CLIENT_ENV", "resolved-client")
	os.Setenv("DASHBOARD_ENV", "resolved-dashboard")
	os.Setenv("GEMINI_ENV", "resolved-gemini")

	cfg, err := loadConfig(confFile)
	assert.NoError(t, err)

	assert.Equal(t, "resolved-client", cfg.DashboardClient)
	assert.Equal(t, "resolved-dashboard", cfg.DashboardKey)
	assert.Equal(t, "resolved-gemini", cfg.GeminiAPIKey)
}

func TestConfigBackendRoutingValidation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "syz-agent-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	confFile := filepath.Join(tmpDir, "config.json")

	writeConfig := func(t *testing.T, extra string) {
		content := `{
			"targets": {
				"linux/amd64": {
					"image": "image1"
				}
			},
			"dashboard_client": "client",
			"dashboard_key": "key"` + extra + `
		}`
		err := os.WriteFile(confFile, []byte(content), 0644)
		assert.NoError(t, err)
	}

	t.Run("valid configuration", func(t *testing.T) {
		writeConfig(t, `,
			"workflow_backends": {
				"repro-c": "vertex"
			},
			"default_backend": "gemini"`)

		cfg, err := loadConfig(confFile)
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"repro-c": "vertex"}, cfg.WorkflowBackends)
		assert.Equal(t, "gemini", cfg.DefaultBackend)
	})

	t.Run("invalid default backend", func(t *testing.T) {
		writeConfig(t, `,
			"default_backend": "invalid"`)

		_, err = loadConfig(confFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `default_backend must be one of`)
	})

	t.Run("invalid backend type in mapping", func(t *testing.T) {
		writeConfig(t, `,
			"workflow_backends": {
				"repro-c": "invalid"
			}`)

		_, err = loadConfig(confFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `has invalid backend type "invalid"`)
	})

	t.Run("valid workflow in mapping", func(t *testing.T) {
		writeConfig(t, `,
			"workflow_backends": {
				"repro-c": "vertex"
			}`)

		cfg, err := loadConfig(confFile)
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"repro-c": "vertex"}, cfg.WorkflowBackends)
	})

	t.Run("unregistered workflow in mapping", func(t *testing.T) {
		writeConfig(t, `,
			"workflow_backends": {
				"nonexistent-workflow": "vertex"
			}`)

		_, err = loadConfig(confFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `is not a registered workflow`)
	})
}

func TestConfigSafetyFilters(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "syz-agent-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	confFile := filepath.Join(tmpDir, "config.json")
	writeConfig := func(val string) {
		content := `{
			"targets": {"linux/amd64": {"image": "image1"}},
			"dashboard_client": "test-client",
			"dashboard_key": "test-key",
			"safety_filters": ` + val + `
		}`
		err := os.WriteFile(confFile, []byte(content), 0644)
		assert.NoError(t, err)
	}

	t.Run("explicitly disabled", func(t *testing.T) {
		writeConfig("false")
		cfg, err := loadConfig(confFile)
		assert.NoError(t, err)
		assert.False(t, cfg.SafetyFilters)
	})

	t.Run("explicitly enabled", func(t *testing.T) {
		writeConfig("true")
		cfg, err := loadConfig(confFile)
		assert.NoError(t, err)
		assert.True(t, cfg.SafetyFilters)
	})
}

func TestTargetConfig(t *testing.T) {
	amd64Qemu := &TargetConfig{TargetOS: "linux", TargetArch: "amd64", TargetVMArch: "amd64", Type: "qemu"}
	amd64GCE := &TargetConfig{TargetOS: "linux", TargetArch: "amd64", TargetVMArch: "amd64", Type: "gce"}
	arm64GCE := &TargetConfig{TargetOS: "linux", TargetArch: "arm64", TargetVMArch: "arm64", Type: "gce"}
	cfg := &Config{
		Targets: map[string]*TargetConfig{
			"linux/amd64-qemu": amd64Qemu,
			"linux/amd64-gce":  amd64GCE,
			"linux/arm64":      arm64GCE,
		},
	}

	t.Run("explicit qemu", func(t *testing.T) {
		got, err := cfg.targetConfig(map[string]any{
			"TargetOS":   "linux",
			"TargetArch": "amd64",
			"VMType":     "qemu",
		})
		require.NoError(t, err)
		assert.Same(t, amd64Qemu, got)
	})

	t.Run("explicit gce", func(t *testing.T) {
		got, err := cfg.targetConfig(map[string]any{
			"TargetOS":   "linux",
			"TargetArch": "amd64",
			"VMType":     "gce",
		})
		require.NoError(t, err)
		assert.Same(t, amd64GCE, got)
	})

	t.Run("empty VMType prefers qemu when available", func(t *testing.T) {
		got, err := cfg.targetConfig(map[string]any{
			"TargetOS":   "linux",
			"TargetArch": "amd64",
		})
		require.NoError(t, err)
		assert.Same(t, amd64Qemu, got)
	})

	t.Run("unmatched VMType falls back to available target", func(t *testing.T) {
		got, err := cfg.targetConfig(map[string]any{
			"TargetOS":   "linux",
			"TargetArch": "arm64",
			"VMType":     "qemu",
		})
		require.NoError(t, err)
		assert.Same(t, arm64GCE, got)
	})

	t.Run("unmatched VMType prefers qemu among multiple targets", func(t *testing.T) {
		got, err := cfg.targetConfig(map[string]any{
			"TargetOS":   "linux",
			"TargetArch": "amd64",
			"VMType":     "adb",
		})
		require.NoError(t, err)
		assert.Same(t, amd64Qemu, got)
	})

	t.Run("unsupported arch returns error", func(t *testing.T) {
		_, err := cfg.targetConfig(map[string]any{
			"TargetOS":   "linux",
			"TargetArch": "riscv64",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `TargetArch "riscv64"`)
	})
}
