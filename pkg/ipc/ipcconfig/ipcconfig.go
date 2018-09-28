// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipcconfig

import (
	"flag"
	"fmt"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagThreaded = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide  = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagSignal   = flag.Bool("cover", false, "collect feedback signals (coverage)")
	flagSandbox  = flag.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace/android_untrusted_app)")
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
	sandboxFlags, err := SandboxToFlags(*flagSandbox)
	if err != nil {
		return nil, nil, err
	}
	c.Flags |= sandboxFlags
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.ExecutorUsesShmem {
		c.Flags |= ipc.FlagUseShmem
	}
	if sysTarget.ExecutorUsesForkServer {
		c.Flags |= ipc.FlagUseForkServer
	}

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

func SandboxToFlags(sandbox string) (ipc.EnvFlags, error) {
	switch sandbox {
	case "none":
		return 0, nil
	case "setuid":
		return ipc.FlagSandboxSetuid, nil
	case "namespace":
		return ipc.FlagSandboxNamespace, nil
	case "android_untrusted_app":
		return ipc.FlagSandboxAndroidUntrustedApp, nil
	default:
		return 0, fmt.Errorf("sandbox must contain one of none/setuid/namespace/android_untrusted_app")
	}
}

func FlagsToSandbox(flags ipc.EnvFlags) string {
	if flags&ipc.FlagSandboxSetuid != 0 {
		return "setuid"
	} else if flags&ipc.FlagSandboxNamespace != 0 {
		return "namespace"
	} else if flags&ipc.FlagSandboxAndroidUntrustedApp != 0 {
		return "android_untrusted_app"
	}
	return "none"
}
