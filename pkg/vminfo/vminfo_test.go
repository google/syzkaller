// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestHostMachineInfo(t *testing.T) {
	checker, files := hostChecker(t)
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

func hostChecker(t *testing.T) (*Checker, []host.FileInfo) {
	cfg := testConfig(t, runtime.GOOS, runtime.GOARCH)
	checker := New(cfg)
	files := host.ReadFiles(checker.RequiredFiles())
	return checker, files
}

func testConfig(t *testing.T, OS, arch string) *mgrconfig.Config {
	target, err := prog.GetTarget(OS, arch)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &mgrconfig.Config{
		Sandbox: ipc.FlagsToSandbox(0),
		Derived: mgrconfig.Derived{
			TargetOS:     OS,
			TargetArch:   arch,
			TargetVMArch: arch,
			Target:       target,
			SysTarget:    targets.Get(OS, arch),
		},
	}
	for id := range target.Syscalls {
		if !target.Syscalls[id].Attrs.Disabled {
			cfg.Syscalls = append(cfg.Syscalls, id)
		}
	}
	return cfg
}
