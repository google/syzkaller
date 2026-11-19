// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	if _, err := loadConfig("testdata/example.cfg"); err != nil {
		t.Fatalf("failed to load: %v", err)
	}
}

func TestExtractBuildEnv(t *testing.T) {
	assert.Equal(t, dashapi.BuildEnv{
		VMType:      "gce",
		MachineType: "e2-standard-2",
	}, extractBuildEnv(&mgrconfig.Config{
		Type: "gce",
		VM:   json.RawMessage(`{"count": 5, "machine_type": "e2-standard-2", "gcs_path": "syzkaller/disks"}`),
	}))
	assert.Equal(t, dashapi.BuildEnv{
		VMType:   "qemu",
		QemuArgs: "-enable-kvm -machine q35",
	}, extractBuildEnv(&mgrconfig.Config{
		Type: "qemu",
		VM:   json.RawMessage(`{"count": 2, "qemu_args": "-enable-kvm -machine q35"}`),
	}))
}
