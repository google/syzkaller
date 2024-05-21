// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"flag"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/sys/targets"
)

func TestExecprogCmd(t *testing.T) {
	// IMPORTANT: if this test fails, do not fix it by changing flags here!
	// See comment in TestFuzzerCmd.
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flagOS := flags.String("os", runtime.GOOS, "target os")
	flagArch := flags.String("arch", "", "target arch")
	flagRepeat := flags.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs := flags.Int("procs", 1, "number of parallel processes to execute programs")
	flagFaultCall := flags.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth := flags.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagExecutor := flags.String("executor", "./syz-executor", "path to executor binary")
	flagThreaded := flags.Bool("threaded", true, "use threaded mode in executor")
	// In the older syzkaller versions `collide` flag defaulted to `true`, but in this
	// test we can change it to false (new default), because syzkaller always explicitly
	// sets this flag and never relies on the default value.
	flagCollide := flags.Bool("collide", false, "collide syscalls to provoke data races")
	flagSignal := flags.Bool("cover", false, "collect feedback signals (coverage)")
	flagSandbox := flags.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace/android)")
	flagSlowdown := flags.Int("slowdown", 1, "")
	cmdLine := ExecprogCmd(os.Args[0], "/myexecutor", targets.FreeBSD, targets.I386,
		"namespace", 3, true, false, true, 7, 2, 3, true, 10, "myprog")
	args := strings.Split(cmdLine, " ")[1:]
	if err := tool.ParseFlags(flags, args); err != nil {
		t.Fatal(err)
	}
	if len(flags.Args()) != 1 || flags.Arg(0) != "myprog" {
		t.Errorf("bad args: %q, want: %q", flags.Args(), "myprog")
	}
	if *flagOS != runtime.GOOS {
		t.Errorf("bad os: %q, want: %q", *flagOS, runtime.GOOS)
	}
	if *flagArch != targets.I386 {
		t.Errorf("bad arch: %q, want: %q", *flagArch, targets.I386)
	}
	if *flagRepeat != 0 {
		t.Errorf("bad repeat: %v, want: %v", *flagRepeat, 0)
	}
	if *flagProcs != 7 {
		t.Errorf("bad procs: %v, want: %v", *flagProcs, 7)
	}
	if *flagFaultCall != 2 {
		t.Errorf("bad procs: %v, want: %v", *flagFaultCall, 2)
	}
	if *flagFaultNth != 3 {
		t.Errorf("bad procs: %v, want: %v", *flagFaultNth, 3)
	}
	if *flagExecutor != "/myexecutor" {
		t.Errorf("bad executor: %q, want: %q", *flagExecutor, "/myexecutor")
	}
	if *flagSandbox != "namespace" {
		t.Errorf("bad sandbox: %q, want: %q", *flagSandbox, "namespace")
	}
	if *flagSignal {
		t.Errorf("bad signal: %v, want: %v", *flagSignal, false)
	}
	if *flagThreaded {
		t.Errorf("bad threaded: %v, want: %v", *flagThreaded, false)
	}
	if !*flagCollide {
		t.Errorf("bad collide: %v, want: %v", *flagCollide, true)
	}
	if *flagSlowdown != 10 {
		t.Errorf("bad slowdown: %v, want: %v", *flagSlowdown, 10)
	}
}

func TestRunnerCmd(t *testing.T) {
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flagFwdAddr := flags.String("addr", "", "verifier rpc address")
	flagOS := flags.String("os", "", "target OS")
	flagArch := flags.String("arch", "", "target architecture")
	flagPool := flags.Int("pool", 0, "index of pool that started VM")
	flagVM := flags.Int("vm", 0, "index of VM that started the Runner")
	flagThreaded := flags.Bool("threaded", true, "use threaded mode in executor")
	flagEnv := flags.Bool("new-env", true, "create a new environment for each program")

	cmdLine := RunnerCmd(os.Args[0], "localhost:1234", targets.Linux, targets.AMD64, 0, 0, false, false)
	args := strings.Split(cmdLine, " ")[1:]
	if err := flags.Parse(args); err != nil {
		t.Fatalf("error parsing flags: %v, want: nil", err)
	}

	if got, want := *flagFwdAddr, "localhost:1234"; got != want {
		t.Errorf("bad addr: %q, want: %q", got, want)
	}

	if got, want := *flagOS, targets.Linux; got != want {
		t.Errorf("bad os: %q, want %q", got, want)
	}

	if got, want := *flagArch, targets.AMD64; got != want {
		t.Errorf("bad arch: %q, want: %q", got, want)
	}

	if got, want := *flagPool, 0; got != want {
		t.Errorf("bad pool index: %d, want: %d", got, want)
	}

	if got, want := *flagVM, 0; got != want {
		t.Errorf("bad vm index: %d, want: %d", got, want)
	}

	if got, want := *flagThreaded, false; got != want {
		t.Errorf("bad threaded: %t, want: %t", got, want)
	}

	if got, want := *flagEnv, false; got != want {
		t.Errorf("bad new-env: %t, want: %t", got, want)
	}
}
