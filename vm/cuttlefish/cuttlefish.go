// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cuttlefish allows to use Cuttlefish Android emulators hosted on Google Compute Engine
// (GCE) virtual machines as VMs. It is assumed that syz-manager also runs on GCE as VMs are
// created in the current project/zone.
//
// See https://cloud.google.com/compute/docs for details.
// In particular, how to build GCE-compatible images:
// https://cloud.google.com/compute/docs/tutorials/building-images
package cuttlefish

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("cuttlefish", ctor, true)
}

type Pool struct {
	env     *vmimpl.Env
	gcePool vmimpl.Pool
}

type instance struct {
	debug   bool
	gceInst vmimpl.Instance
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	gcePool, err := vmimpl.Types["gce"].Ctor(env)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying GCE pool: %s", err)
	}

	pool := &Pool{
		env:     env,
		gcePool: gcePool,
	}

	return pool, nil
}

func (pool *Pool) Count() int {
	log.Logf(1, "cuttlefish.pool.Count()")
	return pool.gcePool.Count()
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	gceInst, err := pool.gcePool.Create(workdir, index)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying gce instance: %s", err)
	}

	inst := &instance{
		debug:   pool.env.Debug,
		gceInst: gceInst,
	}

	// Start a Cuttlefish device on the GCE instance
	// TODO: pass it the specific kernel artifact using -kernel_path and -initramfs_path flags
	if err := inst.runOnHost(10*time.Minute, "./bin/launch_cvd -daemon"); err != nil {
		return nil, fmt.Errorf("failed to start cuttlefish: %s", err)
	}

	if err := inst.runOnHost(10*time.Minute, "adb wait-for-device"); err != nil {
		return nil, fmt.Errorf("failed while waiting for device: %s", err)
	}

	if err := inst.runOnHost(5*time.Minute, "adb root"); err != nil {
		return nil, fmt.Errorf("failed to get root access to device: %s", err)
	}

	return inst, nil
}

func (inst *instance) runOnHost(timeout time.Duration, cmd string) error {
	outc, errc, err := inst.gceInst.Run(timeout, nil, cmd)
	if err != nil {
		return fmt.Errorf("failed to run command: %s", err)
	}

	for {
		select {
		case <-vmimpl.Shutdown:
			return nil
		case err := <-errc:
			if err != nil {
				return fmt.Errorf("error while running: %s", err)
			}
			return nil
		case out, ok := <-outc:
			if ok && inst.debug {
				log.Logf(1, "%s", out)
			}
		}
	}
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	log.Logf(1, "cuttlefish.instance.Copy(%s)", hostSrc)
	return "", fmt.Errorf("not implemented")
}

func (inst *instance) Forward(port int) (string, error) {
	log.Logf(1, "cuttlefish.instance.Forward(%d)", port)
	return "", fmt.Errorf("not implemented")
}

func (inst *instance) Close() {
	// Stop Cuttlefish before shutting down the GCE instance.
	inst.runOnHost(10*time.Minute, "./bin/stop_cvd")
	inst.gceInst.Close()
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	log.Logf(1, "cuttlefish.instance.Run(%s)", command)
	return nil, nil, fmt.Errorf("not implemented")
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	log.Logf(1, "cuttlefish.instance.Diagnose()")
	return nil, false
}
