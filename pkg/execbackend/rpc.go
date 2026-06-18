// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/google/syzkaller/vm/vmimpl"
)

type rpcBackend struct {
	rpcserver.Server
	cfg *mgrconfig.Config
}

func New(cfg *rpcserver.RemoteConfig) (Server, error) {
	rpcServ, err := rpcserver.New(cfg)
	if err != nil {
		return nil, err
	}
	return &rpcBackend{
		Server: rpcServ,
		cfg:    cfg.Config,
	}, nil
}

func (b *rpcBackend) RunRequests(ctx context.Context, inst *vm.Instance,
	reporter *report.Reporter, updInfo dispatcher.UpdateInfo) (
	[]*report.Report, error) {
	var err error
	var fwdAddr string
	if !b.cfg.VMLess {
		fwdAddr, err = inst.Forward(b.Port())
		if err != nil {
			return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
		}
	}

	executorBin := b.cfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(b.cfg.ExecutorBin)
		if err != nil {
			return nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	var cmd string
	if b.cfg.VMLess {
		// Just a placeholder, actually VMLess uses local.go.
	} else {
		host, port, err := net.SplitHostPort(fwdAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse manager's address")
		}
		cmd = fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	}

	injectExec := make(chan bool, 10)
	rpcUpdInfo := func(cb func(info *rpcserver.RunnerInfo)) {
		if updInfo != nil {
			updInfo(func(info *dispatcher.Info) {
				runnerInfo := &rpcserver.RunnerInfo{
					Status:         info.Status,
					DetailedStatus: info.DetailedStatus,
					MachineInfo:    info.MachineInfo,
				}
				cb(runnerInfo)
				info.Status = runnerInfo.Status
				info.DetailedStatus = runnerInfo.DetailedStatus
				info.MachineInfo = runnerInfo.MachineInfo
			})
		}
	}

	b.CreateInstance(inst.Index(), injectExec, rpcUpdInfo)

	ctxTimeout, cancel := context.WithTimeout(ctx, b.cfg.Timeouts.VMRunningTime)
	defer cancel()

	start := time.Now()
	_, reps, err := inst.Run(ctxTimeout, reporter, cmd,
		vm.WithExitCondition(vm.ExitTimeout),
		vm.WithInjectExecuting(injectExec),
		vm.WithEarlyFinishCb(func() {
			b.StopFuzzing(inst.Index())
		}))

	if err != nil {
		if errors.Is(err, vmimpl.ErrPreempted) {
			log.Logf(0, "VM %v: preempted while executing", inst.Index())
		} else {
			err = fmt.Errorf("failed to run fuzzer: %w", err)
		}
	} else if len(reps) == 0 {
		log.Logf(0, "VM %v: running for %v, restarting", inst.Index(), time.Since(start))
	}

	// Fetch executor info and clean up instance.
	var extraExecs []report.ExecutorInfo
	if len(reps) != 0 && reps[0] != nil && reps[0].Executor != nil {
		extraExecs = []report.ExecutorInfo{*reps[0].Executor}
	}
	execRecords, machineInfo := b.ShutdownInstance(inst.Index(), len(reps) != 0, extraExecs...)

	if len(reps) != 0 && reps[0] != nil {
		vmInfo, infoErr := inst.Info()
		if infoErr != nil {
			vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", infoErr))
		}
		if len(vmInfo) != 0 {
			machineInfo = append(append(vmInfo, '\n'), machineInfo...)
		}
		rpcserver.PrependExecuting(reps[0], execRecords)
		reps[0].MachineInfo = machineInfo
	}

	return reps, err
}
