// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
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
	modules, info, err := checker.MachineInfo(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("machine info:\n%s", info)
	for _, module := range modules {
		t.Logf("module %q: addr 0x%x size %v", module.Name, module.Addr, module.Size)
	}
}

func TestFreeBSDParseModules(t *testing.T) {
	kldstatOutput := []byte(`Id Refs Address                Size Name
 1   97 0xffffffff80200000  25166b0 kernel
 2    1 0xffffffff82717000   673a88 zfs.ko
 3    1 0xffffffff82d8c000   3835e8 vmm.ko
 4    1 0xffffffff83a20000     36f8 fdescfs.ko
 5    1 0xffffffff83a24000     3160 amdtemp.ko
`)
	f := freebsd{}
	cmdResults := map[string][]byte{
		"kldstat": kldstatOutput,
	}
	modules, err := f.parseModules(nil, cmdResults)
	if err != nil {
		t.Fatal(err)
	}
	expected := []*KernelModule{
		{Name: "", Addr: 0xffffffff80200000, Size: 0x25166b0},
		{Name: "zfs", Addr: 0xffffffff82717000, Size: 0x673a88},
		{Name: "vmm", Addr: 0xffffffff82d8c000, Size: 0x3835e8},
		{Name: "fdescfs", Addr: 0xffffffff83a20000, Size: 0x36f8},
		{Name: "amdtemp", Addr: 0xffffffff83a24000, Size: 0x3160},
	}
	require.Equal(t, expected, modules)
}

func TestFreeBSDParseModulesEmpty(t *testing.T) {
	f := freebsd{}
	modules, err := f.parseModules(nil, nil)
	require.NoError(t, err)
	require.Nil(t, modules)
}

func TestSyscalls(t *testing.T) {
	t.Parallel()
	for _, arches := range targets.List {
		for _, target := range arches {
			if target.OS == targets.Linux {
				continue // linux has own TestLinuxSyscalls test
			}
			t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
				t.Parallel()
				cfg := testConfig(t, target.OS, target.Arch)
				checker := New(cfg)
				stop := make(chan struct{})
				go createSuccessfulResults(checker, stop)
				enabled, disabled, _, err := checker.Run(context.Background(), nil, allFeatures())
				close(stop)
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

func allFeatures() []*flatrpc.FeatureInfo {
	var features []*flatrpc.FeatureInfo
	for feat := range flatrpc.EnumNamesFeature {
		features = append(features, &flatrpc.FeatureInfo{
			Id: feat,
		})
	}
	return features
}

func createSuccessfulResults(source queue.Source, stop chan struct{}) {
	var count int
	for {
		select {
		case <-stop:
			return
		case <-time.After(time.Millisecond):
		}
		req := source.Next()
		if req == nil {
			continue
		}
		count++
		if count > 1000 {
			// This is just a sanity check that we don't do something stupid accidentally.
			// If it grows above the limit intentionally, the limit can be increased.
			// Currently we have 641 (when we failed to properly dedup syscall tests, it was 4349).
			panic("too many test programs")
		}
		res := &queue.Result{
			Status: queue.Success,
		}
		switch req.Type {
		case flatrpc.RequestTypeProgram:
			res.Info = &flatrpc.ProgInfo{}
			for range req.Prog.Calls {
				res.Info.Calls = append(res.Info.Calls, &flatrpc.CallInfo{
					Cover:  []uint64{1},
					Signal: []uint64{1},
					Comps:  []*flatrpc.Comparison{{Op1: 1, Op2: 2}},
				})
			}
		case flatrpc.RequestTypeGlob:
			res.Output = []byte("/some/file\n")
		}
		req.Done(res)
	}
}

func hostChecker(t *testing.T) (*Checker, []*flatrpc.FileInfo) {
	cfg := testConfig(t, runtime.GOOS, runtime.GOARCH)
	checker := New(cfg)
	files := readFiles(checker.RequiredFiles())
	return checker, files
}

func testConfig(t *testing.T, OS, arch string) *Config {
	target, err := prog.GetTarget(OS, arch)
	if err != nil {
		t.Fatal(err)
	}
	var syscalls []int
	for id := range target.Syscalls {
		if !target.Syscalls[id].Attrs.Disabled {
			syscalls = append(syscalls, id)
		}
	}
	return &Config{
		Target:   target,
		Features: flatrpc.AllFeatures,
		Sandbox:  flatrpc.ExecEnvSandboxNone,
		Syscalls: syscalls,
	}
}

func readFiles(files []string) []*flatrpc.FileInfo {
	var res []*flatrpc.FileInfo
	for _, glob := range files {
		glob = filepath.FromSlash(glob)
		if !strings.Contains(glob, "*") {
			res = append(res, readFile(glob))
			continue
		}
		matches, err := filepath.Glob(glob)
		if err != nil {
			res = append(res, &flatrpc.FileInfo{
				Name:  glob,
				Error: err.Error(),
			})
			continue
		}
		for _, file := range matches {
			res = append(res, readFile(file))
		}
	}
	return res
}

func readFile(file string) *flatrpc.FileInfo {
	data, err := os.ReadFile(file)
	exists, errStr := true, ""
	if err != nil {
		exists, errStr = !os.IsNotExist(err), err.Error()
	}
	return &flatrpc.FileInfo{
		Name:   file,
		Exists: exists,
		Error:  errStr,
		Data:   data,
	}
}
