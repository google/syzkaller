// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
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

func TestSyscalls(t *testing.T) {
	t.Parallel()
	for _, arches := range targets.List {
		for _, target := range arches {
			target := target
			if target.OS == targets.Linux {
				continue // linux has own TestLinuxSyscalls test
			}
			t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
				t.Parallel()
				cfg := testConfig(t, target.OS, target.Arch)
				checker := New(cfg)
				_, checkProgs := checker.StartCheck()
				results := createSuccessfulResults(t, cfg.Target, checkProgs)
				enabled, disabled, err := checker.FinishCheck(nil, results)
				if err != nil {
					t.Fatal(err)
				}
				for call, reason := range disabled {
					t.Errorf("disabled call %v: %v", call.Name, reason)
				}
				if len(enabled) != len(cfg.Syscalls) {
					t.Errorf("enabled only %v calls out of %v", len(enabled), len(cfg.Syscalls))
				}
			})
		}
	}
}

func createSuccessfulResults(t *testing.T, target *prog.Target,
	progs []rpctype.ExecutionRequest) []rpctype.ExecutionResult {
	var results []rpctype.ExecutionResult
	for _, req := range progs {
		p, err := target.DeserializeExec(req.ProgData, nil)
		if err != nil {
			t.Fatal(err)
		}
		res := rpctype.ExecutionResult{
			ID: req.ID,
			Info: ipc.ProgInfo{
				Calls: make([]ipc.CallInfo, len(p.Calls)),
			},
		}
		results = append(results, res)
	}
	return results
}

func hostChecker(t *testing.T) (*Checker, []flatrpc.FileInfo) {
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
