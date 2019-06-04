// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package runtest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	_ "github.com/google/syzkaller/sys/test/gen" // pull in the test target
)

func Test(t *testing.T) {
	switch runtime.GOOS {
	case "openbsd":
		t.Skipf("broken on %v", runtime.GOOS)
	}
	for _, sysTarget := range targets.List["test"] {
		sysTarget1 := targets.Get(sysTarget.OS, sysTarget.Arch)
		t.Run(sysTarget1.Arch, func(t *testing.T) {
			t.Parallel()
			test(t, sysTarget1)
		})
	}
}

func test(t *testing.T, sysTarget *targets.Target) {
	target, err := prog.GetTarget(sysTarget.OS, sysTarget.Arch)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Short() && target.PtrSize == 4 {
		// Building 32-bit binaries fails on travis (see comments in Makefile).
		t.Skip("skipping in short mode")
	}
	executor, err := csource.BuildFile(target, filepath.FromSlash("../../executor/executor.cc"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(executor)
	features, err := host.Check(target)
	if err != nil {
		t.Fatalf("failed to detect host features: %v", err)
	}
	calls, _, err := host.DetectSupportedSyscalls(target, "none")
	if err != nil {
		t.Fatalf("failed to detect supported syscalls: %v", err)
	}
	enabledCalls := map[string]map[*prog.Syscall]bool{
		"":     calls,
		"none": calls,
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Setup(target, features, featureFlags, executor); err != nil {
		t.Fatal(err)
	}
	requests := make(chan *RunRequest, 2*runtime.GOMAXPROCS(0))
	go func() {
		for req := range requests {
			RunTest(req, executor)
			close(req.Done)
		}
	}()
	ctx := &Context{
		Dir:          filepath.Join("..", "..", "sys", target.OS, "test"),
		Target:       target,
		Features:     features,
		EnabledCalls: enabledCalls,
		Requests:     requests,
		LogFunc: func(text string) {
			t.Helper()
			t.Logf(text)
		},
		Retries: 7, // empirical number that seem to reduce flakes to zero
		Verbose: true,
	}
	if err := ctx.Run(); err != nil {
		t.Fatal(err)
	}
}
