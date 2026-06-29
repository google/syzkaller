// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/google/syzkaller/pkg/aflow/flow/reproc"
	"github.com/stretchr/testify/assert"
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
