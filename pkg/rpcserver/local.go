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
	"golang.org/x/sync/errgroup"
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
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	cfg.UseCoverEdges = true
	cfg.FilterSignal = true
	cfg.RPC = ":0"
	cfg.PrintMachineCheck = log.V(1)
	cfg.Stats = NewStats()
	localCtx := &local{
		cfg:       cfg,
		setupDone: make(chan bool),
	}
	serv := newImpl(&cfg.Config, localCtx)
	if err := serv.Listen(); err != nil {
		return err
	}
	defer serv.Close()
	localCtx.serv = serv
	// setupDone synchronizes assignment to ctx.serv and read of ctx.serv in MachineChecked
	// for the race detector b/c it does not understand the synchronization via TCP socket connect/accept.
	close(localCtx.setupDone)

	cancelCtx, cancel := context.WithCancel(cfg.Context)
	eg, ctx := errgroup.WithContext(cancelCtx)

	const id = 0
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
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = cfg.Dir
	if cfg.Debug || cfg.GDB {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if cfg.GDB {
		cmd.Stdin = os.Stdin
	}
	eg.Go(func() error {
		return serv.Serve(ctx)
	})
	eg.Go(func() error {
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start executor: %w", err)
		}
		err := cmd.Wait()
		// Note that we ignore the error if we killed the process by closing the context.
		if err == nil || ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("executor process exited: %w", err)
	})

	shutdown := make(chan struct{})
	if cfg.HandleInterrupts {
		osutil.HandleInterrupts(shutdown)
	}
	select {
	case <-ctx.Done():
	case <-shutdown:
	case <-connErr:
	}
	cancel()
	return eg.Wait()
}

type local struct {
	cfg       *LocalConfig
	serv      Server
	setupDone chan bool
}

func (ctx *local) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	<-ctx.setupDone
	ctx.serv.TriagedCorpus()
	return ctx.cfg.MachineChecked(features, syscalls), nil
}

func (ctx *local) BugFrames() ([]string, []string) {
	return nil, nil
}

func (ctx *local) MaxSignal() signal.Signal {
	return signal.FromRaw(ctx.cfg.MaxSignal, 0)
}

func (ctx *local) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	return ctx.cfg.CoverFilter, nil
}
