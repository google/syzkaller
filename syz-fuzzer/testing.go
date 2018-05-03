// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func testImage(hostAddr string, target *prog.Target, sandbox string) {
	log.Logf(0, "connecting to host at %v", hostAddr)
	conn, err := net.Dial("tcp", hostAddr)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	conn.Close()

	log.Logf(0, "checking config...")
	config, execOpts, err := ipc.DefaultConfig()
	if err != nil {
		log.Fatalf("failed to create ipc config: %v", err)
	}
	if kcov, _ := checkCompsSupported(); !kcov && config.Flags&ipc.FlagSignal != 0 {
		log.Fatalf("coverage is not supported by kernel")
	}
	if config.Flags&ipc.FlagSandboxNamespace != 0 && !osutil.IsExist("/proc/self/ns/user") {
		log.Fatalf("/proc/self/ns/user is not present for namespace sandbox")
	}
	calls, _, err := host.DetectSupportedSyscalls(target, sandbox)
	if err != nil {
		log.Fatalf("failed to detect supported syscalls: %v", err)
	}
	calls, _ = target.TransitivelyEnabledCalls(calls)
	log.Logf(0, "enabled syscalls: %v", len(calls))
	if calls[target.SyscallMap["syz_emit_ethernet"]] ||
		calls[target.SyscallMap["syz_extract_tcp_res"]] {
		config.Flags |= ipc.FlagEnableTun
	}

	log.Logf(0, "testing simple program...")
	env, err := ipc.MakeEnv(config, 0)
	if err != nil {
		log.Fatalf("failed to create ipc env: %v", err)
	}
	p := target.GenerateSimpleProg()
	output, info, failed, hanged, err := env.Exec(execOpts, p)
	if err != nil {
		log.Fatalf("execution failed: %v\n%s", err, output)
	}
	if hanged {
		log.Fatalf("program hanged:\n%s", output)
	}
	if failed {
		log.Fatalf("program failed:\n%s", output)
	}
	if len(info) == 0 {
		log.Fatalf("no calls executed:\n%s", output)
	}
	if info[0].Errno != 0 {
		log.Fatalf("simple call failed: %v\n%s", info[0].Errno, output)
	}
	if config.Flags&ipc.FlagSignal != 0 && len(info[0].Signal) == 0 {
		log.Fatalf("got no coverage:\n%s", output)
	}
}
