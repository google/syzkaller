// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package runtest

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
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
	features, err := host.Check(target)
	if err != nil {
		t.Fatalf("failed to detect host features: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, c := range target.Syscalls {
		enabled[c] = true
	}
	calls, _, err := host.DetectSupportedSyscalls(target, "none", enabled)
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
			if req.Bin != "" {
				runTestC(req)
			} else {
				runTest(req, executor)
			}
			close(req.Done)
		}
	}()
	ctx := &Context{
		Dir:          filepath.Join("..", "..", "sys", target.OS, targets.TestOS),
		Target:       target,
		Tests:        *flagFilter,
		Features:     features.ToFlatRPC(),
		EnabledCalls: enabledCalls,
		Requests:     requests,
		LogFunc: func(text string) {
			t.Helper()
			t.Logf(text)
		},
		Retries: 7, // empirical number that seem to reduce flakes to zero
		Verbose: true,
		Debug:   *flagDebug,
	}
	if err := ctx.Run(); err != nil {
		t.Fatal(err)
	}
}

func runTest(req *RunRequest, executor string) {
	cfg := new(ipc.Config)
	sysTarget := targets.Get(req.P.Target.OS, req.P.Target.Arch)
	cfg.UseShmem = sysTarget.ExecutorUsesShmem
	cfg.UseForkServer = sysTarget.ExecutorUsesForkServer
	cfg.Timeouts = sysTarget.Timeouts(1)
	cfg.Executor = executor
	env, err := ipc.MakeEnv(cfg, 0)
	if err != nil {
		req.Err = fmt.Errorf("failed to create ipc env: %w", err)
		return
	}
	defer env.Close()
	for run := 0; run < req.Repeat; run++ {
		if run%2 == 0 {
			// Recreate Env every few iterations, this allows to cover more paths.
			env.ForceRestart()
		}
		output, info, hanged, err := env.Exec(&req.Opts, req.P)
		req.Output = append(req.Output, output...)
		if err != nil {
			req.Err = fmt.Errorf("run %v: failed to run: %w", run, err)
			return
		}
		if hanged {
			req.Err = fmt.Errorf("run %v: hanged", run)
			return
		}
		if run == 0 {
			req.Info = *info
		} else {
			req.Info.Calls = append(req.Info.Calls, info.Calls...)
		}
	}
}

func runTestC(req *RunRequest) {
	tmpDir, err := os.MkdirTemp("", "syz-runtest")
	if err != nil {
		req.Err = fmt.Errorf("failed to create temp dir: %w", err)
		return
	}
	defer os.RemoveAll(tmpDir)
	cmd := osutil.Command(req.Bin)
	cmd.Dir = tmpDir
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	req.Output, req.Err = osutil.Run(20*time.Second, cmd)
	var verr *osutil.VerboseError
	if errors.As(req.Err, &verr) {
		// The process can legitimately do something like exit_group(1).
		// So we ignore the error and rely on the rest of the checks (e.g. syscall return values).
		req.Err = nil
		req.Output = verr.Output
	}
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
