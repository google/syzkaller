// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type checkArgs struct {
	target         *prog.Target
	sandbox        string
	gitRevision    string
	targetRevision string
	ipcConfig      *ipc.Config
	ipcExecOpts    *ipc.ExecOpts
}

func testImage(hostAddr string, args *checkArgs) {
	// gVisor uses "stdin" for communication, which is not a real tcp address.
	if hostAddr != "stdin" {
		log.Logf(0, "connecting to host at %v", hostAddr)
		timeout := time.Minute * args.ipcConfig.Timeouts.Scale
		conn, err := net.DialTimeout("tcp", hostAddr, timeout)
		if err != nil {
			log.SyzFatalf("failed to connect to host: %v", err)
		}
		conn.Close()
	}
	if err := checkRevisions(args); err != nil {
		log.SyzFatal(err)
	}
	if err := checkSimpleProgram(args); err != nil {
		log.SyzFatal(err)
	}
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

func checkSimpleProgram(args *checkArgs) error {
	log.Logf(0, "testing simple program...")
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
