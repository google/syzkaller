// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/vmimpl"
	"golang.org/x/sync/errgroup"
)

type LocalConfig struct {
	Target      *prog.Target
	ExecutorBin string
	Dir         string
	Source      queue.Source
}

type localManager struct {
	backend Server
	source  queue.Source
}

func (m *localManager) BugFrames() ([]string, []string) { return nil, nil }

func (m *localManager) MaxSignal() signal.Signal { return signal.Signal{} }

func (m *localManager) CoverageFilter([]*vminfo.KernelModule) ([]uint64, error) {
	return nil, nil
}

func (m *localManager) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) error {
	if m.source != nil {
		m.backend.SetSource(m.source)
	}
	return nil
}

// RunLocal is a convenience wrapper for running a local mock VM via the execbackend abstraction.
// It executes the syz-executor binary as a standard host process, returning its output reports.
func RunLocal(ctx context.Context, cfg LocalConfig) ([]*report.Report, error) {
	sysTarget := targets.Get(cfg.Target.OS, cfg.Target.Arch)
	timeouts := sysTarget.Timeouts(1)
	timeouts.VMRunningTime = time.Minute
	timeouts.Scale = 1

	mgrCfg := &mgrconfig.Config{
		Type:    "local",
		Sandbox: "none",
		Cover:   true,
		Procs:   4,
		Workdir: cfg.Dir,
		Derived: mgrconfig.Derived{
			TargetOS:     cfg.Target.OS,
			TargetVMArch: cfg.Target.Arch,
			SysTarget:    sysTarget,
			Timeouts:     timeouts,
			ExecutorBin:  cfg.ExecutorBin,
			Target:       cfg.Target,
		},
		RPC: ":0",
	}

	pool, err := vm.Create(mgrCfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm pool: %w", err)
	}

	inst, err := pool.Create(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create vm instance: %w", err)
	}
	defer inst.Close()

	mgrWrapper := &localManager{
		source: cfg.Source,
	}

	rpcCfg := &rpcserver.RemoteConfig{
		Config:  mgrCfg,
		Manager: mgrWrapper,
		Stats:   rpcserver.NewStats(),
		Debug:   true,
	}

	backend, err := New(rpcCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create execbackend: %w", err)
	}
	mgrWrapper.backend = backend

	if err := backend.Setup(); err != nil {
		return nil, fmt.Errorf("failed to setup execbackend: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	eg, egCtx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return backend.Serve(egCtx)
	})

	reporter, err := report.NewReporter(&mgrconfig.Config{
		Type: "qemu",
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: cfg.Target.Arch,
			SysTarget:    sysTarget,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter: %w", err)
	}

	reps, err := backend.RunRequests(egCtx, inst, reporter, nil)
	cancel()
	if serveErr := eg.Wait(); serveErr != nil {
		return nil, serveErr
	}

	return reps, err
}

func init() {
	vmimpl.Register("local", vmimpl.Type{
		Ctor: func(env *vmimpl.Env) (vmimpl.Pool, error) {
			return &localPool{env: env}, nil
		},
	})
}

type localPool struct {
	env *vmimpl.Env
}

func (p *localPool) Count() int {
	return 1
}

func (p *localPool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	return &localVM{workdir: workdir}, nil
}

type localVM struct {
	workdir string
}

func (v *localVM) Copy(hostSrc string) (string, error) {
	return hostSrc, nil
}

func (v *localVM) Forward(port int) (string, error) {
	return fmt.Sprintf("localhost:%v", port), nil
}

func (v *localVM) Run(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
	parts := strings.Fields(command)
	cmd := osutil.CommandContext(ctx, parts[0], parts[1:]...)

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, nil, err
	}

	// Close our copy of the write end so the pipe closes when the child exits.
	pw.Close()

	merger := vmimpl.NewOutputMerger(nil)
	merger.Add("output", vmimpl.OutputStdout, pr)

	return vmimpl.Multiplex(ctx, cmd, merger, vmimpl.MultiplexConfig{
		Scale: 1, // we don't have a slowdown factor in local config, so scale=1 is safe
	})
}

func (v *localVM) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (v *localVM) Close() error {
	return nil
}
