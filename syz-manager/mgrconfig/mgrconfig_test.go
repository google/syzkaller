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

func TestMatchSyscall(t *testing.T) {
	tests := []struct {
		pattern string
		call    string
		result  bool
	}{
		{"foo", "foo", true},
		{"foo", "bar", false},
		{"foo", "foo$BAR", true},
		{"foo*", "foo", true},
		{"foo*", "foobar", true},
		{"foo*", "foo$BAR", true},
		{"foo$*", "foo", false},
		{"foo$*", "foo$BAR", true},
	}
	for i, test := range tests {
		res := matchSyscall(test.call, test.pattern)
		if res != test.result {
			t.Errorf("#%v: pattern=%q call=%q want=%v got=%v",
				i, test.pattern, test.call, test.result, res)
		}
	}
}
