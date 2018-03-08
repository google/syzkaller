// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
	"github.com/google/syzkaller/vm"
)

// bootInstance boots one VM using the provided config.
// Returns either instance and reporter, or report with boot failure, or error.
func bootInstance(mgrcfg *mgrconfig.Config) (*vm.Instance, report.Reporter, *report.Report, error) {
	reporter, err := report.NewReporter(mgrcfg.TargetOS, mgrcfg.Kernel_Src,
		filepath.Dir(mgrcfg.Vmlinux), nil, mgrcfg.ParsedIgnores)
	if err != nil {
		return nil, nil, nil, err
	}
	vmEnv := mgrconfig.CreateVMEnv(mgrcfg, false)
	vmPool, err := vm.Create(mgrcfg.Type, vmEnv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create VM pool: %v", err)
	}
	inst, err := vmPool.Create(0)
	if err != nil {
		if bootErr, ok := err.(vm.BootErrorer); ok {
			title, output := bootErr.BootError()
			rep := reporter.Parse(output)
			if rep == nil {
				rep = &report.Report{
					Title:  title,
					Output: output,
				}
			}
			if err := reporter.Symbolize(rep); err != nil {
				// TODO(dvyukov): send such errors to dashboard.
				Logf(0, "failed to symbolize report: %v", err)
			}
			return nil, nil, rep, nil
		}
		return nil, nil, nil, fmt.Errorf("failed to create VM: %v", err)
	}
	return inst, reporter, nil, nil
}

// testInstance tests basic operation of the provided VM
// (that we can copy binaries, run binaries, they can connect to host, run syzkaller programs, etc).
// It either returns crash report if there is a kernel bug,
// or err if there is an internal problem, or all nil's if testing succeeded.
func testInstance(inst *vm.Instance, reporter report.Reporter, mgrcfg *mgrconfig.Config) (
	*report.Report, error) {
	ln, err := net.Listen("tcp", ":")
	if err != nil {
		return nil, fmt.Errorf("failed to open listening socket: %v", err)
	}
	defer ln.Close()
	var gotConn uint32
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			atomic.StoreUint32(&gotConn, 1)
		}
	}()
	fwdAddr, err := inst.Forward(ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %v", err)
	}
	fuzzerBin, err := inst.Copy(mgrcfg.SyzFuzzerBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy test binary to VM: %v", err)
	}
	executorBin, err := inst.Copy(mgrcfg.SyzExecutorBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy test binary to VM: %v", err)
	}
	cmd := fmt.Sprintf("%v -test -executor=%v -name=test -arch=%v -manager=%v -cover=%v -sandbox=%v",
		fuzzerBin, executorBin, mgrcfg.TargetArch, fwdAddr, mgrcfg.Cover, mgrcfg.Sandbox)
	outc, errc, err := inst.Run(5*time.Minute, nil, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run binary in VM: %v", err)
	}
	rep := vm.MonitorExecution(outc, errc, reporter, true)
	if rep != nil {
		if err := reporter.Symbolize(rep); err != nil {
			// TODO(dvyukov): send such errors to dashboard.
			Logf(0, "failed to symbolize report: %v", err)
		}
		return rep, nil
	}
	if atomic.LoadUint32(&gotConn) == 0 {
		return nil, fmt.Errorf("test machine failed to connect to host")
	}
	return nil, nil
}
