// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	if _, err := loadConfig("testdata/example.cfg"); err != nil {
		t.Fatalf("failed to load: %v", err)
	}
}

func TestBaselineCanInference(t *testing.T) {
	dir := t.TempDir()
	kernelConfig := filepath.Join(dir, "kernel.config")
	kernelBaseConfig := filepath.Join(dir, "kernel-base.config")
	osutil.WriteFile(kernelConfig, nil)
	osutil.WriteFile(kernelBaseConfig, nil)
	assert.Equal(t, kernelBaseConfig, inferBaselineConfig(kernelConfig))
}

func TestBaselineCannotInference(t *testing.T) {
	dir := t.TempDir()
	kernelConfig := filepath.Join(dir, "kernel.config")
	osutil.WriteFile(kernelConfig, nil)
	assert.Equal(t, "", inferBaselineConfig(kernelConfig))
}
