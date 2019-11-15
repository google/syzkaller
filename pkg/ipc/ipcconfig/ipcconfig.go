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
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagThreaded = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide  = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagSignal   = flag.Bool("cover", false, "collect feedback signals (coverage)")
	flagSandbox  = flag.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace/android)")
	flagDebug    = flag.Bool("debug", false, "debug output from executor")
	flagTimeout  = flag.Duration("timeout", 0, "execution timeout")
)

func Default(target *prog.Target) (*ipc.Config, *ipc.ExecOpts, error) {
	c := &ipc.Config{
		Executor: *flagExecutor,
		Timeout:  *flagTimeout,
	}
	if *flagSignal {
		c.Flags |= ipc.FlagSignal
	}
	if *flagDebug {
		c.Flags |= ipc.FlagDebug
	}
	sandboxFlags, err := ipc.SandboxToFlags(*flagSandbox)
	if err != nil {
		return nil, nil, err
	}
	c.Flags |= sandboxFlags
	sysTarget := targets.Get(target.OS, target.Arch)
	c.UseShmem = sysTarget.ExecutorUsesShmem
	c.UseForkServer = sysTarget.ExecutorUsesForkServer
	opts := &ipc.ExecOpts{
		Flags: ipc.FlagDedupCover,
	}
	if *flagThreaded {
		opts.Flags |= ipc.FlagThreaded
	}
	if *flagCollide {
		opts.Flags |= ipc.FlagCollide
	}

	return c, opts, nil
}
