// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
)

type LocalConfig struct {
	Config
	// syz-executor binary.
	Executor string
	// Temp dir where to run executor process, it's up to the caller to clean it up if necessary.
	Dir string
	// Handle ctrl+C and exit.
	HandleInterrupts bool
	// Run executor under gdb.
	GDB         bool
	MaxSignal   []uint64
	CoverFilter []uint64
	// RunLocal exits when the context is cancelled.
	Context        context.Context
	MachineChecked func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source
}

func RunLocal(cfg *LocalConfig) error {
	if cfg.VMArch == "" {
		cfg.VMArch = cfg.Target.Arch
	}
	cfg.UseCoverEdges = true
	cfg.FilterSignal = true
	cfg.RPC = ":0"
	cfg.PrintMachineCheck = log.V(1)
	cfg.Stats = NewStats()
	ctx := &local{
		cfg:       cfg,
		setupDone: make(chan bool),
	}
	serv := newImpl(cfg.Context, &cfg.Config, ctx)
	if err := serv.Listen(); err != nil {
		return err
	}
	defer serv.Close()
	ctx.serv = serv
	// setupDone synchronizes assignment to ctx.serv and read of ctx.serv in MachineChecked
	// for the race detector b/c it does not understand the synchronization via TCP socket connect/accept.
	close(ctx.setupDone)

	id := 0
	connErr := serv.CreateInstance(id, nil, nil)
	defer serv.ShutdownInstance(id, true)

	bin := cfg.Executor
	args := []string{"runner", fmt.Sprint(id), "localhost", fmt.Sprint(serv.Port())}
	if cfg.GDB {
		bin = "gdb"
		args = append([]string{
			"--return-child-result",
			"--ex=handle SIGPIPE nostop",
			"--args",
			cfg.Executor,
		}, args...)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = cfg.Dir
	if cfg.Debug || cfg.GDB {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if cfg.GDB {
		cmd.Stdin = os.Stdin
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executor: %w", err)
	}
	res := make(chan error, 1)
	go func() { res <- cmd.Wait() }()
	shutdown := make(chan struct{})
	if cfg.HandleInterrupts {
		osutil.HandleInterrupts(shutdown)
	}
	var cmdErr error
	select {
	case <-shutdown:
	case <-cfg.Context.Done():
	case <-connErr:
	case err := <-res:
		cmdErr = fmt.Errorf("executor process exited: %w", err)
	}
	if cmdErr == nil {
		cmd.Process.Kill()
		<-res
	}
	return cmdErr
}

type local struct {
	cfg       *LocalConfig
	serv      Server
	setupDone chan bool
}

func (ctx *local) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
	<-ctx.setupDone
	ctx.serv.TriagedCorpus()
	return ctx.cfg.MachineChecked(features, syscalls)
}

func (ctx *local) BugFrames() ([]string, []string) {
	return nil, nil
}

func (ctx *local) MaxSignal() signal.Signal {
	return signal.FromRaw(ctx.cfg.MaxSignal, 0)
}

func (ctx *local) CoverageFilter(modules []*vminfo.KernelModule) []uint64 {
	return ctx.cfg.CoverFilter
}
