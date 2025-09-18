// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzconfig

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var flagWrite = flag.Bool("write", false, "overwrite out.txt files")

func TestSingularFocus(t *testing.T) {
	focusMap := map[string]struct{}{}
	for _, target := range api.FuzzTargets {
		for _, campaign := range target.Campaigns {
			if campaign.Focus != "" {
				focusMap[campaign.Focus] = struct{}{}
			}
		}
	}
	for focus := range focusMap {
		t.Run(focus, func(t *testing.T) {
			cfg := &api.FuzzConfig{Focus: []string{focus}}
			runTest(t, cfg, filepath.Join("testdata", "singular", focus))
		})
	}
}

func TestNoFocus(t *testing.T) {
	runTest(t, &api.FuzzConfig{}, filepath.Join("testdata", "singular", "default"))
}

func TestMultipleFocus(t *testing.T) {
	runTest(t, &api.FuzzConfig{
		Focus: []string{api.FocusBPF, api.FocusIoUring},
	}, filepath.Join("testdata", "mixed", "bpf_io_uring"))
}

func runTest(t *testing.T, cfg *api.FuzzConfig, baseName string) {
	base, err := GenerateBase(cfg)
	require.NoError(t, err)
	compareOrSave(t, baseName+".base.cfg", base)

	patched, err := GeneratePatched(cfg)
	require.NoError(t, err)
	compareOrSave(t, baseName+".patched.cfg", patched)
}

func compareOrSave(t *testing.T, fileName string, mgrCfg *mgrconfig.Config) {
	targetJSON, err := json.MarshalIndent(mgrCfg, "", "\t")
	require.NoError(t, err)
	if *flagWrite {
		err = os.WriteFile(fileName, targetJSON, 0644)
		require.NoError(t, err)
		return
	}

	var raw json.RawMessage
	err = config.LoadFile(fileName, &raw)
	require.NoError(t, err)

	cfg, err := mgrconfig.LoadPartialData(raw)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	resultJSON, err := json.MarshalIndent(cfg, "", "\t")
	require.NoError(t, err)
	assert.Equal(t, targetJSON, resultJSON)
}
