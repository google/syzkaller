// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
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
				stop := make(chan struct{})
				go createSuccessfulResults(checker, stop)
				enabled, disabled, _, err := checker.Run(nil, allFeatures())
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
		req, stop := source.Next()
		if req == nil {
			if stop {
				break
			}
			continue
		}
		count++
		if count > 1000 {
			// This is just a sanity check that we don't do something stupid accidentally.
			// If it grows above the limit intentionally, the limit can be increased.
			// Currently we have 641 (when we failed to properly dedup syscall tests, it was 4349).
			panic("too many test programs")
		}
		info := &flatrpc.ProgInfo{}
		for range req.Prog.Calls {
			info.Calls = append(info.Calls, &flatrpc.CallInfo{
				Cover:  []uint64{1},
				Signal: []uint64{1},
				Comps:  []*flatrpc.Comparison{{Op1: 1, Op2: 2}},
			})
		}
		req.Done(&queue.Result{
			Status: queue.Success,
			Info:   info,
		})
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
