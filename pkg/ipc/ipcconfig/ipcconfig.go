// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipcconfig

import (
	"flag"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagExecutor   = flag.String("executor", "./syz-executor", "path to executor binary")
	flagThreaded   = flag.Bool("threaded", true, "use threaded mode in executor")
	flagSignal     = flag.Bool("cover", false, "collect feedback signals (coverage)")
	flagSandbox    = flag.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace/android)")
	flagSandboxArg = flag.Int("sandbox_arg", 0, "argument for sandbox runner to adjust it via config")
	flagDebug      = flag.Bool("debug", false, "debug output from executor")
	flagSlowdown   = flag.Int("slowdown", 1, "execution slowdown caused by emulation/instrumentation")
)

func Default(target *prog.Target) (*ipc.Config, *ipc.ExecOpts, error) {
	sysTarget := targets.Get(target.OS, target.Arch)
	c := &ipc.Config{
		Executor: *flagExecutor,
		Timeouts: sysTarget.Timeouts(*flagSlowdown),
	}
	c.UseShmem = sysTarget.ExecutorUsesShmem
	c.UseForkServer = sysTarget.ExecutorUsesForkServer
	c.RateLimit = sysTarget.HostFuzzer && target.OS != targets.TestOS

	opts := &ipc.ExecOpts{
		ExecFlags: ipc.FlagDedupCover,
	}
	if *flagThreaded {
		opts.ExecFlags |= ipc.FlagThreaded
	}
	if *flagSignal {
		opts.ExecFlags |= ipc.FlagCollectSignal
	}
	if *flagSignal {
		opts.EnvFlags |= ipc.FlagSignal
	}
	if *flagDebug {
		opts.EnvFlags |= ipc.FlagDebug
	}
	sandboxFlags, err := ipc.SandboxToFlags(*flagSandbox)
	if err != nil {
		return nil, nil, err
	}
	opts.SandboxArg = *flagSandboxArg
	opts.EnvFlags |= sandboxFlags
	return c, opts, nil
}
