// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/runtest"
	"github.com/google/syzkaller/prog"
)

type checkArgs struct {
	target         *prog.Target
	sandbox        string
	gitRevision    string
	targetRevision string
	enabledCalls   []int
	allSandboxes   bool
	ipcConfig      *ipc.Config
	ipcExecOpts    *ipc.ExecOpts
	featureFlags   map[string]csource.Feature
}

func testImage(hostAddr string, args *checkArgs) {
	log.Logf(0, "connecting to host at %v", hostAddr)
	conn, err := rpctype.Dial(hostAddr)
	if err != nil {
		log.Fatalf("BUG: failed to connect to host: %v", err)
	}
	conn.Close()
	if _, err := checkMachine(args); err != nil {
		log.Fatalf("BUG: %v", err)
	}
}

func runTest(target *prog.Target, manager *rpctype.RPCClient, name, executor string) {
	pollReq := &rpctype.RunTestPollReq{Name: name}
	for {
		req := new(rpctype.RunTestPollRes)
		if err := manager.Call("Manager.Poll", pollReq, req); err != nil {
			log.Fatalf("Manager.Poll call failed: %v", err)
		}
		if len(req.Bin) == 0 && len(req.Prog) == 0 {
			return
		}
		test := convertTestReq(target, req)
		if test.Err == nil {
			runtest.RunTest(test, executor)
		}
		reply := &rpctype.RunTestDoneArgs{
			Name:   name,
			ID:     req.ID,
			Output: test.Output,
			Info:   test.Info,
		}
		if test.Err != nil {
			reply.Error = test.Err.Error()
		}
		if err := manager.Call("Manager.Done", reply, nil); err != nil {
			log.Fatalf("Manager.Done call failed: %v", err)
		}
	}
}

func convertTestReq(target *prog.Target, req *rpctype.RunTestPollRes) *runtest.RunRequest {
	test := &runtest.RunRequest{
		Cfg:    req.Cfg,
		Opts:   req.Opts,
		Repeat: req.Repeat,
	}
	if len(req.Bin) != 0 {
		bin, err := osutil.TempFile("syz-runtest")
		if err != nil {
			test.Err = err
			return test
		}
		if err := osutil.WriteExecFile(bin, req.Bin); err != nil {
			test.Err = err
			return test
		}
		test.Bin = bin
	}
	if len(req.Prog) != 0 {
		p, err := target.Deserialize(req.Prog, prog.NonStrict)
		if err != nil {
			test.Err = err
			return test
		}
		test.P = p
	}
	return test
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
	if err := checkRevisions(args); err != nil {
		return nil, err
	}
	features, err := host.Check(args.target)
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
	if feat := features[host.FeatureSandboxAndroid]; !feat.Enabled &&
		args.ipcConfig.Flags&ipc.FlagSandboxAndroid != 0 {
		return nil, fmt.Errorf("sandbox=android is not supported (%v)", feat.Reason)
	}
	if err := checkSimpleProgram(args, features); err != nil {
		return nil, err
	}
	return checkCalls(args, features)
}

func checkCalls(args *checkArgs, features *host.Features) (*rpctype.CheckArgs, error) {
	res := &rpctype.CheckArgs{
		Features:      features,
		EnabledCalls:  make(map[string][]int),
		DisabledCalls: make(map[string][]rpctype.SyscallReason),
	}
	sandboxes := []string{args.sandbox}
	if args.allSandboxes {
		if args.sandbox != "none" {
			sandboxes = append(sandboxes, "none")
		}
		if args.sandbox != "setuid" && features[host.FeatureSandboxSetuid].Enabled {
			sandboxes = append(sandboxes, "setuid")
		}
		if args.sandbox != "namespace" && features[host.FeatureSandboxNamespace].Enabled {
			sandboxes = append(sandboxes, "namespace")
		}
		// TODO: Add "android" sandbox here when needed. Will require fixing runtests.
	}
	for _, sandbox := range sandboxes {
		enabledCalls, disabledCalls, err := buildCallList(args.target, args.enabledCalls, sandbox)
		res.EnabledCalls[sandbox] = enabledCalls
		res.DisabledCalls[sandbox] = disabledCalls
		if err != nil {
			return res, err
		}
	}
	if args.allSandboxes {
		var enabled []int
		for _, id := range res.EnabledCalls["none"] {
			switch args.target.Syscalls[id].Name {
			default:
				enabled = append(enabled, id)
			case "syz_emit_ethernet", "syz_extract_tcp_res":
				// Tun is not setup without sandbox, this is a hacky way to workaround this.
			}
		}
		res.EnabledCalls[""] = enabled
	}
	return res, nil
}

func checkRevisions(args *checkArgs) error {
	log.Logf(0, "checking revisions...")
	executorArgs := strings.Split(args.ipcConfig.Executor, " ")
	executorArgs = append(executorArgs, "version")
	cmd := osutil.Command(executorArgs[0], executorArgs[1:]...)
	cmd.Stderr = ioutil.Discard
	if _, err := cmd.StdinPipe(); err != nil { // for the case executor is wrapped with ssh
		return err
	}
	out, err := osutil.Run(time.Minute, cmd)
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
	if prog.GitRevision != vers[3] {
		return fmt.Errorf("mismatching fuzzer/executor git revisions: %v vs %v",
			prog.GitRevision, vers[3])
	}
	if args.gitRevision != "" && args.gitRevision != prog.GitRevision {
		return fmt.Errorf("mismatching manager/fuzzer git revisions: %v vs %v",
			args.gitRevision, prog.GitRevision)
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

func checkSimpleProgram(args *checkArgs, features *host.Features) error {
	log.Logf(0, "testing simple program...")
	if err := host.Setup(args.target, features, args.featureFlags, args.ipcConfig.Executor); err != nil {
		return fmt.Errorf("host setup failed: %v", err)
	}
	env, err := ipc.MakeEnv(args.ipcConfig, 0)
	if err != nil {
		return fmt.Errorf("failed to create ipc env: %v", err)
	}
	defer env.Close()
	p := args.target.DataMmapProg()
	output, info, hanged, err := env.Exec(args.ipcExecOpts, p)
	if err != nil {
		return fmt.Errorf("program execution failed: %v\n%s", err, output)
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
	if args.ipcConfig.Flags&ipc.FlagSignal != 0 && len(info.Calls[0].Signal) < 2 {
		return fmt.Errorf("got no coverage:\n%s", output)
	}
	if len(info.Calls[0].Signal) < 1 {
		return fmt.Errorf("got no fallback coverage:\n%s", output)
	}
	return nil
}

func buildCallList(target *prog.Target, enabledCalls []int, sandbox string) (
	enabled []int, disabled []rpctype.SyscallReason, err error) {
	log.Logf(0, "building call list...")
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
	for c := range calls {
		enabled = append(enabled, c.ID)
	}
	if len(calls) == 0 {
		return enabled, disabled, fmt.Errorf("all system calls are disabled")
	}
	return enabled, disabled, nil
}
