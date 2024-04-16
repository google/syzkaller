// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

func TestHostMachineInfo(t *testing.T) {
	checker, files := hostChecker()
	dups := make(map[string]bool)
	for _, file := range files {
		if file.Name[0] != '/' || file.Name[len(file.Name)-1] == '/' || strings.Contains(file.Name, "\\") {
			t.Errorf("malformed file %q", file.Name)
		}
		// Reading duplicate files leads to duplicate work.
		if dups[file.Name] {
			t.Errorf("duplicate file %q", file.Name)
		}
		dups[file.Name] = true
		if file.Error != "" {
			t.Logf("failed to read %q: %s", file.Name, file.Error)
		}
	}
	modules, info, err := checker.MachineInfo(files)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("machine info:\n%s", info)
	for _, module := range modules {
		t.Logf("module %q: addr 0x%x size %v", module.Name, module.Addr, module.Size)
	}
}

func hostChecker() (*Checker, []host.FileInfo) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     runtime.GOOS,
			TargetArch:   runtime.GOARCH,
			TargetVMArch: runtime.GOARCH,
		},
	}
	checker := New(cfg)
	files := host.ReadFiles(checker.RequiredFiles())
	return checker, files
}
