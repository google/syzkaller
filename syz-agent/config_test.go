// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigPlainValues(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "syz-agent-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	confFile := filepath.Join(tmpDir, "config.json")
	content := `{
		"dashboard_key": "test-dashboard-key",
		"gemini_api_key": "test-gemini-key"
	}`
	err = os.WriteFile(confFile, []byte(content), 0644)
	assert.NoError(t, err)

	cfg, err := loadConfig(confFile)
	assert.NoError(t, err)

	assert.Equal(t, "test-dashboard-key", cfg.DashboardKey)
	assert.Equal(t, "test-gemini-key", cfg.GeminiAPIKey)
}

func TestConfigEnvResolution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "syz-agent-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	confFile := filepath.Join(tmpDir, "config.json")
	content := `{
		"dashboard_key": "env:DASHBOARD_ENV",
		"gemini_api_key": "env:GEMINI_ENV"
	}`
	err = os.WriteFile(confFile, []byte(content), 0644)
	assert.NoError(t, err)

	os.Setenv("DASHBOARD_ENV", "resolved-dashboard")
	os.Setenv("GEMINI_ENV", "resolved-gemini")

	cfg, err := loadConfig(confFile)
	assert.NoError(t, err)

	assert.Equal(t, "resolved-dashboard", cfg.DashboardKey)
	assert.Equal(t, "resolved-gemini", cfg.GeminiAPIKey)
}
