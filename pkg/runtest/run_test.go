// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package runtest

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	_ "github.com/google/syzkaller/sys/test/gen" // pull in the test target
)

// Can be used as:
// go test -v -run=Test/64_fork ./pkg/runtest -filter=nonfailing
// to select a subset of tests to run.
var flagFilter = flag.String("filter", "", "prefix to match test file names")

var flagDebug = flag.Bool("debug", false, "include debug output from the executor")

func Test(t *testing.T) {
	switch runtime.GOOS {
	case targets.OpenBSD:
		t.Skipf("broken on %v", runtime.GOOS)
	}
	// Test only one target in short mode (each takes 5+ seconds to run).
	shortTarget := targets.Get(targets.TestOS, targets.TestArch64)
	for _, sysTarget := range targets.List[targets.TestOS] {
		if testing.Short() && sysTarget != shortTarget {
			continue
		}
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
	executor := csource.BuildExecutor(t, target, "../../", "-fsanitize-coverage=trace-pc")
	calls := make(map[*prog.Syscall]bool)
	for _, call := range target.Syscalls {
		calls[call] = true
	}
	enabledCalls := map[string]map[*prog.Syscall]bool{
		"":     calls,
		"none": calls,
	}
	ctx := &Context{
		Dir:          filepath.Join("..", "..", "sys", target.OS, targets.TestOS),
		Target:       target,
		Tests:        *flagFilter,
		Features:     0,
		EnabledCalls: enabledCalls,
		LogFunc: func(text string) {
			t.Helper()
			t.Logf(text)
		},
		Retries: 7, // empirical number that seem to reduce flakes to zero
		Verbose: true,
		Debug:   *flagDebug,
	}

	executorCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			select {
			case <-time.After(time.Millisecond):
			case <-executorCtx.Done():
				return
			}
			req := ctx.Next()
			if req == nil {
				continue
			}
			if req.BinaryFile != "" {
				req.Done(runTestC(req))
			} else {
				req.Done(runTest(req, executor))
			}
		}
	}()
	if err := ctx.Run(); err != nil {
		t.Fatal(err)
	}
}

func runTest(req *queue.Request, executor string) *queue.Result {
	cfg := new(ipc.Config)
	sysTarget := targets.Get(req.Prog.Target.OS, req.Prog.Target.Arch)
	cfg.UseShmem = sysTarget.ExecutorUsesShmem
	cfg.UseForkServer = sysTarget.ExecutorUsesForkServer
	cfg.Timeouts = sysTarget.Timeouts(1)
	cfg.Executor = executor
	env, err := ipc.MakeEnv(cfg, 0)
	if err != nil {
		return &queue.Result{
			Status: queue.ExecFailure,
			Err:    fmt.Errorf("failed to create ipc env: %w", err),
		}
	}
	defer env.Close()
	ret := &queue.Result{Status: queue.Success}
	for run := 0; run < req.Repeat; run++ {
		if run%2 == 0 {
			// Recreate Env every few iterations, this allows to cover more paths.
			env.ForceRestart()
		}
		output, info, hanged, err := env.Exec(&req.ExecOpts, req.Prog)
		ret.Output = append(ret.Output, output...)
		if err != nil {
			return &queue.Result{
				Status: queue.ExecFailure,
				Err:    fmt.Errorf("run %v: failed to run: %w", run, err),
			}
		}
		if hanged {
			return &queue.Result{
				Status: queue.ExecFailure,
				Err:    fmt.Errorf("run %v: hanged", run),
			}
		}
		if run == 0 {
			ret.Info = info
		} else {
			ret.Info.Calls = append(ret.Info.Calls, info.Calls...)
		}
	}
	return ret
}

func runTestC(req *queue.Request) *queue.Result {
	tmpDir, err := os.MkdirTemp("", "syz-runtest")
	if err != nil {
		return &queue.Result{
			Status: queue.ExecFailure,
			Err:    fmt.Errorf("failed to create temp dir: %w", err),
		}
	}
	defer os.RemoveAll(tmpDir)
	cmd := osutil.Command(req.BinaryFile)
	cmd.Dir = tmpDir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	res := &queue.Result{}
	res.Output, res.Err = osutil.Run(20*time.Second, cmd)
	var verr *osutil.VerboseError
	if errors.As(res.Err, &verr) {
		// The process can legitimately do something like exit_group(1).
		// So we ignore the error and rely on the rest of the checks (e.g. syscall return values).
		res.Err = nil
		res.Output = verr.Output
	}
	return res
}

func TestParsing(t *testing.T) {
	t.Parallel()
	// Test only one target in race mode (we have gazillion of auto-generated Linux test).
	raceTarget := targets.Get(targets.TestOS, targets.TestArch64)
	for OS, arches := range targets.List {
		if testutil.RaceEnabled && OS != raceTarget.OS {
			continue
		}
		dir := filepath.Join("..", "..", "sys", OS, "test")
		if !osutil.IsExist(dir) {
			continue
		}
		files, err := progFileList(dir, "")
		if err != nil {
			t.Fatal(err)
		}
		for arch := range arches {
			if testutil.RaceEnabled && arch != raceTarget.Arch {
				continue
			}
			target, err := prog.GetTarget(OS, arch)
			if err != nil {
				t.Fatal(err)
			}
			sysTarget := targets.Get(target.OS, target.Arch)
			t.Run(fmt.Sprintf("%v/%v", target.OS, target.Arch), func(t *testing.T) {
				t.Parallel()
				for _, file := range files {
					p, requires, _, err := parseProg(target, dir, file)
					if err != nil {
						t.Errorf("failed to parse %v: %v", file, err)
					}
					if p == nil {
						continue
					}
					if runtime.GOOS != sysTarget.BuildOS {
						continue // we need at least preprocessor binary to generate sources
					}
					// syz_mount_image tests are very large and this test takes too long.
					// syz-imagegen that generates does some of this testing (Deserialize/SerializeForExec).
					if requires["manual"] {
						continue
					}
					if _, err = csource.Write(p, csource.ExecutorOpts); err != nil {
						t.Errorf("failed to generate C source for %v: %v", file, err)
					}
				}
			})
		}
	}
}

func TestRequires(t *testing.T) {
	{
		requires := parseRequires([]byte("# requires: manual arch=amd64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
	{
		requires := parseRequires([]byte("# requires: -arch=arm64 manual -arch=riscv64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
}
