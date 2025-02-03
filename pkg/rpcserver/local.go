// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"context"
	"fmt"
	"io"
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
	GDB bool
	// Can be used to intercept stdout/stderr output.
	OutputWriter   io.Writer
	MaxSignal      []uint64
	CoverFilter    []uint64
	MachineChecked func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source
}

func RunLocal(ctx context.Context, cfg *LocalConfig) error {
	localCtx, ctx, err := setupLocal(ctx, cfg)
	if err != nil {
		return err
	}
	defer localCtx.serv.Close()
	// groupCtx will be cancelled once any goroutine returns an error.
	eg, groupCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return localCtx.RunInstance(groupCtx, 0)
	})
	eg.Go(func() error {
		return localCtx.serv.Serve(groupCtx)
	})
	return eg.Wait()
}

func setupLocal(ctx context.Context, cfg *LocalConfig) (*local, context.Context, error) {
	if cfg.VMArch == "" {
		cfg.VMArch = cfg.Target.Arch
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
		return nil, nil, err
	}
	localCtx.serv = serv
	// setupDone synchronizes assignment to ctx.serv and read of ctx.serv in MachineChecked
	// for the race detector b/c it does not understand the synchronization via TCP socket connect/accept.
	close(localCtx.setupDone)

	if cfg.HandleInterrupts {
		ctx = cancelOnInterrupts(ctx)
	}
	return localCtx, ctx, nil
}

func cancelOnInterrupts(ctx context.Context) context.Context {
	ret, cancel := context.WithCancel(ctx)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		select {
		case <-ctx.Done():
			// Prevent goroutine leakage.
		case <-shutdown:
			cancel()
		}
	}()
	return ret
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

func (ctx *local) Serve(context context.Context) error {
	return ctx.serv.Serve(context)
}

func (ctx *local) RunInstance(baseCtx context.Context, id int) error {
	connErr := ctx.serv.CreateInstance(id, nil, nil)
	defer ctx.serv.ShutdownInstance(id, true)

	cfg := ctx.cfg
	bin := cfg.Executor
	args := []string{"runner", fmt.Sprint(id), "localhost", fmt.Sprint(ctx.serv.Port())}
	if cfg.GDB {
		bin = "gdb"
		args = append([]string{
			"--return-child-result",
			"--ex=handle SIGPIPE nostop",
			"--args",
			cfg.Executor,
		}, args...)
	}
	cmd := exec.CommandContext(baseCtx, bin, args...)
	cmd.Dir = cfg.Dir
	if cfg.OutputWriter != nil {
		cmd.Stdout = cfg.OutputWriter
		cmd.Stderr = cfg.OutputWriter
	} else if cfg.Debug || cfg.GDB {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if cfg.GDB {
		cmd.Stdin = os.Stdin
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start executor: %w", err)
	}
	var retErr error
	select {
	case <-baseCtx.Done():
	case err := <-connErr:
		if err != nil {
			retErr = fmt.Errorf("connection error: %w", err)
		}
		cmd.Process.Kill()
	}
	err := cmd.Wait()
	if retErr == nil {
		retErr = fmt.Errorf("executor process exited: %w", err)
	}
	// Note that we ignore the error if we killed the process because of the context.
	if baseCtx.Err() == nil {
		return retErr
	}
	return nil
}
