// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"testing"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/vm/qemu"
)

func TestCanned(t *testing.T) {
	cfg := new(Config)
	if err := config.LoadFile("testdata/qemu.cfg", cfg); err != nil {
		t.Fatal(err)
	}
	var vmCfg interface{}
	switch cfg.Type {
	case "qemu":
		vmCfg = new(qemu.Config)
	default:
		t.Fatalf("unknown VM type: %v", cfg.Type)
	}
	if err := config.LoadData(cfg.VM, vmCfg); err != nil {
		t.Fatalf("failed to load %v config: %v", cfg.Type, err)
	}
}
