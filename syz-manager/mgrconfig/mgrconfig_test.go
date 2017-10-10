// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/vm/gce"
	"github.com/google/syzkaller/vm/qemu"
)

func TestCanned(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.cfg"))
	if err != nil || len(files) == 0 {
		t.Fatalf("failed to read input files: %v", err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			cfg := new(Config)
			if err := config.LoadFile(file, cfg); err != nil {
				t.Fatal(err)
			}
			var vmCfg interface{}
			switch cfg.Type {
			case "qemu":
				vmCfg = new(qemu.Config)
			case "gce":
				vmCfg = new(gce.Config)
			default:
				t.Fatalf("unknown VM type: %v", cfg.Type)
			}
			if err := config.LoadData(cfg.VM, vmCfg); err != nil {
				t.Fatalf("failed to load %v config: %v", cfg.Type, err)
			}
		})
	}
}
