// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

type checkArgs struct {
	target         *prog.Target
	sandbox        string
	gitRevision    string
	targetRevision string
	enabledCalls   []int
	ipcConfig      *ipc.Config
	ipcExecOpts    *ipc.ExecOpts
}

func testImage(hostAddr string, args *checkArgs) {
	log.Logf(0, "connecting to host at %v", hostAddr)
	conn, err := net.Dial("tcp", hostAddr)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	conn.Close()
	if _, err := checkMachine(args); err != nil {
		log.Fatalf("%v", err)
	}
}

func checkMachine(args *checkArgs) (*rpctype.CheckArgs, error) {
	if err := checkRevisions(args); err != nil {
		return nil, err
	}
	features, err := host.Check()
	if err != nil {
		return nil, err
	}
	if feat := features[host.FeatureCoverage]; !feat.Enabled &&
		args.ipcConfig.Flags&ipc.FlagSignal != 0 {
		return nil, fmt.Errorf("coverage is not supported (%v)", feat.Reason)
	}
	if feat := features[host.FeatureSandboxSetuid]; !feat.Enabled &&
		args.ipcConfig.Flags&ipc.FlagSandboxSetuid != 0 {
		return nil, fmt.Errorf("sandbox=setuid is not supported (%v)", feat.Reason)
	}
	if feat := features[host.FeatureSandboxNamespace]; !feat.Enabled &&
		args.ipcConfig.Flags&ipc.FlagSandboxNamespace != 0 {
		return nil, fmt.Errorf("sandbox=namespace is not supported (%v)", feat.Reason)
	}
	if err := checkSimpleProgram(args); err != nil {
		return nil, err
	}
	enabledCalls, disabledCalls, err := buildCallList(args.target, args.enabledCalls, args.sandbox)
	if err != nil {
		return nil, err
	}
	res := &rpctype.CheckArgs{
		EnabledCalls:  enabledCalls,
		DisabledCalls: disabledCalls,
		Features:      features,
	}
	return res, nil
}

func checkRevisions(args *checkArgs) error {
	log.Logf(0, "checking revisions...")
	out, err := osutil.RunCmd(time.Minute, "", args.ipcConfig.Executor, "version")
	if err != nil {
		return fmt.Errorf("failed to run executor version: %v", err)
	}
	vers := strings.Split(strings.TrimSpace(string(out)), " ")
	if len(vers) != 4 {
		return fmt.Errorf("executor version returned bad result: %q", string(out))
	}
	if args.target.Arch != vers[1] {
		return fmt.Errorf("mismatching target/executor arches: %v vs %v", args.target.Arch, vers[1])
	}
	if sys.GitRevision != vers[3] {
		return fmt.Errorf("mismatching fuzzer/executor git revisions: %v vs %v",
			sys.GitRevision, vers[3])
	}
	if args.gitRevision != "" && args.gitRevision != sys.GitRevision {
		return fmt.Errorf("mismatching manager/fuzzer git revisions: %v vs %v",
			args.gitRevision, sys.GitRevision)
	}
	if args.target.Revision != vers[2] {
		return fmt.Errorf("mismatching fuzzer/executor system call descriptions: %v vs %v",
			args.target.Revision, vers[2])
	}
	if args.targetRevision != "" && args.targetRevision != args.target.Revision {
		return fmt.Errorf("mismatching manager/fuzzer system call descriptions: %v vs %v",
			args.targetRevision, args.target.Revision)
	}
	return nil
}

func checkSimpleProgram(args *checkArgs) error {
	log.Logf(0, "testing simple program...")
	env, err := ipc.MakeEnv(args.ipcConfig, 0)
	if err != nil {
		return fmt.Errorf("failed to create ipc env: %v", err)
	}
	p := args.target.GenerateSimpleProg()
	output, info, failed, hanged, err := env.Exec(args.ipcExecOpts, p)
	if err != nil {
		return fmt.Errorf("program execution failed: %v\n%s", err, output)
	}
	if hanged {
		return fmt.Errorf("program hanged:\n%s", output)
	}
	if failed {
		return fmt.Errorf("program failed:\n%s", output)
	}
	if len(info) == 0 {
		return fmt.Errorf("no calls executed:\n%s", output)
	}
	if info[0].Errno != 0 {
		return fmt.Errorf("simple call failed: %+v\n%s", info[0], output)
	}
	if args.ipcConfig.Flags&ipc.FlagSignal != 0 && len(info[0].Signal) < 2 {
		return fmt.Errorf("got no coverage:\n%s", output)
	}
	if len(info[0].Signal) < 1 {
		return fmt.Errorf("got no fallback coverage:\n%s", output)
	}
	return nil
}

func buildCallList(target *prog.Target, enabledCalls []int, sandbox string) (
	enabled []int, disabled []rpctype.SyscallReason, err error) {
	calls := make(map[*prog.Syscall]bool)
	if len(enabledCalls) != 0 {
		for _, n := range enabledCalls {
			if n >= len(target.Syscalls) {
				return nil, nil, fmt.Errorf("unknown enabled syscall %v", n)
			}
			calls[target.Syscalls[n]] = true
		}
	} else {
		for _, c := range target.Syscalls {
			calls[c] = true
		}
	}
	_, unsupported, err := host.DetectSupportedSyscalls(target, sandbox)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect host supported syscalls: %v", err)
	}
	for c := range calls {
		if reason, ok := unsupported[c]; ok {
			log.Logf(1, "unsupported syscall: %v: %v", c.Name, reason)
			disabled = append(disabled, rpctype.SyscallReason{
				ID:     c.ID,
				Reason: reason,
			})
			delete(calls, c)
		}
	}
	_, unsupported = target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if reason, ok := unsupported[c]; ok {
			log.Logf(1, "transitively unsupported: %v: %v", c.Name, reason)
			disabled = append(disabled, rpctype.SyscallReason{
				ID:     c.ID,
				Reason: reason,
			})
			delete(calls, c)
		}
	}
	if len(calls) == 0 {
		return nil, nil, fmt.Errorf("all system calls are disabled")
	}
	for c := range calls {
		enabled = append(enabled, c.ID)
	}
	return enabled, disabled, nil
}
