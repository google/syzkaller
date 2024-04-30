// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

type checkArgs struct {
	target         *prog.Target
	sandbox        string
	gitRevision    string
	targetRevision string
	ipcConfig      *ipc.Config
	ipcExecOpts    *ipc.ExecOpts
	featureFlags   map[string]csource.Feature
}

func testImage(hostAddr string, args *checkArgs) {
	log.Logf(0, "connecting to host at %v", hostAddr)
	conn, err := rpctype.Dial(hostAddr, args.ipcConfig.Timeouts.Scale)
	if err != nil {
		log.SyzFatalf("BUG: failed to connect to host: %v", err)
	}
	conn.Close()
	if err := checkRevisions(args); err != nil {
		log.SyzFatalf("BUG: %v", err)
	}
	if _, err := checkMachine(args); err != nil {
		log.SyzFatalf("BUG: %v", err)
	}
	if err := buildCallList(args.target, args.sandbox); err != nil {
		log.SyzFatalf("BUG: %v", err)
	}
}

func checkMachineHeartbeats(done chan bool) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			fmt.Printf("executing program\n")
		}
	}
}

func checkMachine(args *checkArgs) (*rpctype.CheckArgs, error) {
	log.Logf(0, "checking machine...")
	// Machine checking can be very slow on some machines (qemu without kvm, KMEMLEAK linux, etc),
	// so print periodic heartbeats for vm.MonitorExecution so that it does not decide that we are dead.
	done := make(chan bool)
	defer close(done)
	go checkMachineHeartbeats(done)
	features, err := host.Check(args.target)
	if err != nil {
		return nil, err
	}
	if feat := features[host.FeatureCoverage]; !feat.Enabled &&
		args.ipcExecOpts.EnvFlags&ipc.FlagSignal != 0 {
		return nil, fmt.Errorf("coverage is not supported (%v)", feat.Reason)
	}
	if feat := features[host.FeatureSandboxSetuid]; !feat.Enabled &&
		args.ipcExecOpts.EnvFlags&ipc.FlagSandboxSetuid != 0 {
		return nil, fmt.Errorf("sandbox=setuid is not supported (%v)", feat.Reason)
	}
	if feat := features[host.FeatureSandboxNamespace]; !feat.Enabled &&
		args.ipcExecOpts.EnvFlags&ipc.FlagSandboxNamespace != 0 {
		return nil, fmt.Errorf("sandbox=namespace is not supported (%v)", feat.Reason)
	}
	if feat := features[host.FeatureSandboxAndroid]; !feat.Enabled &&
		args.ipcExecOpts.EnvFlags&ipc.FlagSandboxAndroid != 0 {
		return nil, fmt.Errorf("sandbox=android is not supported (%v)", feat.Reason)
	}
	args.ipcExecOpts.EnvFlags |= ipc.FeaturesToFlags(features, nil)
	if err := checkSimpleProgram(args, features); err != nil {
		return nil, err
	}
	res := &rpctype.CheckArgs{
		Features: features,
	}
	return res, nil
}

func checkRevisions(args *checkArgs) error {
	log.Logf(0, "checking revisions...")
	arch, syzRev, gitRev, err := executorVersion(args.ipcConfig.Executor)
	if err != nil {
		return err
	}
	if args.target.Arch != arch {
		return fmt.Errorf("mismatching target/executor arches: %v vs %v", args.target.Arch, arch)
	}
	if prog.GitRevision != gitRev {
		return fmt.Errorf("mismatching fuzzer/executor git revisions: %v vs %v",
			prog.GitRevision, gitRev)
	}
	if args.gitRevision != prog.GitRevision {
		return fmt.Errorf("mismatching manager/fuzzer git revisions: %v vs %v",
			args.gitRevision, prog.GitRevision)
	}
	if args.target.Revision != syzRev {
		return fmt.Errorf("mismatching fuzzer/executor system call descriptions: %v vs %v",
			args.target.Revision, syzRev)
	}
	if args.target.Revision != args.targetRevision {
		return fmt.Errorf("mismatching fuzzer/manager system call descriptions: %v vs %v",
			args.target.Revision, args.targetRevision)
	}
	return nil
}

func executorVersion(bin string) (string, string, string, error) {
	args := strings.Split(bin, " ")
	args = append(args, "version")
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Stderr = io.Discard
	if _, err := cmd.StdinPipe(); err != nil { // for the case executor is wrapped with ssh
		return "", "", "", err
	}
	out, err := osutil.Run(time.Minute, cmd)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to run executor version: %w", err)
	}
	// Executor returns OS, arch, descriptions hash, git revision.
	vers := strings.Split(strings.TrimSpace(string(out)), " ")
	if len(vers) != 4 {
		return "", "", "", fmt.Errorf("executor version returned bad result: %q", string(out))
	}
	return vers[1], vers[2], vers[3], nil
}

func checkSimpleProgram(args *checkArgs, features *host.Features) error {
	log.Logf(0, "testing simple program...")
	if err := host.Setup(args.target, features, args.featureFlags, args.ipcConfig.Executor); err != nil {
		return fmt.Errorf("host setup failed: %w", err)
	}
	env, err := ipc.MakeEnv(args.ipcConfig, 0)
	if err != nil {
		return fmt.Errorf("failed to create ipc env: %w", err)
	}
	defer env.Close()
	p := args.target.DataMmapProg()
	output, info, hanged, err := env.Exec(args.ipcExecOpts, p)
	if err != nil {
		return fmt.Errorf("program execution failed: %w\n%s", err, output)
	}
	if hanged {
		return fmt.Errorf("program hanged:\n%s", output)
	}
	if len(info.Calls) == 0 {
		return fmt.Errorf("no calls executed:\n%s", output)
	}
	if info.Calls[0].Errno != 0 {
		return fmt.Errorf("simple call failed: %+v\n%s", info.Calls[0], output)
	}
	if args.ipcExecOpts.EnvFlags&ipc.FlagSignal != 0 && len(info.Calls[0].Signal) < 2 {
		return fmt.Errorf("got no coverage:\n%s", output)
	}
	return nil
}

func buildCallList(target *prog.Target, sandbox string) error {
	log.Logf(0, "building call list...")
	calls := make(map[*prog.Syscall]bool)
	for _, c := range target.Syscalls {
		calls[c] = true
	}

	_, unsupported, err := host.DetectSupportedSyscalls(target, sandbox, calls)
	if err != nil {
		return fmt.Errorf("failed to detect host supported syscalls: %w", err)
	}
	for c := range calls {
		if reason, ok := unsupported[c]; ok {
			// Note: if we print call name followed by ':', it may be detected
			// as a kernel crash if the call ends with "BUG" or "INFO".
			log.Logf(1, "unsupported syscall: %v(): %v", c.Name, reason)
			delete(calls, c)
		}
	}
	_, unsupported = target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if reason, ok := unsupported[c]; ok {
			log.Logf(1, "transitively unsupported: %v(): %v", c.Name, reason)
			delete(calls, c)
		}
	}
	if len(calls) == 0 {
		return fmt.Errorf("all system calls are disabled")
	}
	return nil
}
