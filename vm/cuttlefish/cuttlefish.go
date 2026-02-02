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
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/gce"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	deviceRoot     = "/data/fuzz"
	consoleReadCmd = "tail -f cuttlefish/instances/cvd-1/kernel.log"
)

func init() {
	vmimpl.Register("cuttlefish", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Pool struct {
	env     *vmimpl.Env
	gcePool *gce.Pool
}

type instance struct {
	name    string
	sshKey  string
	sshUser string
	debug   bool
	gceInst vmimpl.Instance
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	gcePool, err := gce.Ctor(env, consoleReadCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying GCE pool: %w", err)
	}

	pool := &Pool{
		env:     env,
		gcePool: gcePool,
	}

	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.gcePool.Count()
}

func (pool *Pool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	gceInst, err := pool.gcePool.Create(ctx, workdir, index)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying gce instance: %w", err)
	}

	inst := &instance{
		name:    fmt.Sprintf("%v-%v", pool.env.Name, index),
		sshKey:  pool.env.SSHKey,
		sshUser: pool.env.SSHUser,
		debug:   pool.env.Debug,
		gceInst: gceInst,
	}

	// Start a Cuttlefish device on the GCE instance.
	if err := inst.runOnHost(10*time.Minute,
		fmt.Sprintf("./bin/launch_cvd -daemon -kernel_path=./bzImage -initramfs_path=./initramfs.img"+
			" --noenable_sandbox -report_anonymous_usage_stats=n --memory_mb=8192")); err != nil {
		return nil, fmt.Errorf("failed to start cuttlefish: %w", err)
	}

	if err := inst.runOnHost(10*time.Minute, "adb wait-for-device"); err != nil {
		return nil, fmt.Errorf("failed while waiting for device: %w", err)
	}

	if err := inst.runOnHost(5*time.Minute, "adb root"); err != nil {
		return nil, fmt.Errorf("failed to get root access to device: %w", err)
	}

	if err := inst.runOnHost(5*time.Minute, fmt.Sprintf("adb shell '"+
		"setprop persist.dbg.keep_debugfs_mounted 1;"+
		"mount -t debugfs debugfs /sys/kernel/debug;"+
		"chmod 0755 /sys/kernel/debug;"+
		"mkdir %s;"+
		"'", deviceRoot)); err != nil {
		return nil, fmt.Errorf("failed to mount debugfs to /sys/kernel/debug: %w", err)
	}

	return inst, nil
}

func (inst *instance) sshArgs(command string) []string {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.sshKey, 22, false), inst.sshUser+"@"+inst.name)
	if inst.sshUser != "root" {
		return append(sshArgs, "sudo", "bash", "-c", "'"+command+"'")
	}
	return append(sshArgs, command)
}

func (inst *instance) runOnHost(timeout time.Duration, command string) error {
	_, err := osutil.RunCmd(timeout, "/root", "ssh", inst.sshArgs(command)...)

	return err
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	gceDst, err := inst.gceInst.Copy(hostSrc)
	if err != nil {
		return "", fmt.Errorf("error copying to worker instance: %w", err)
	}

	deviceDst := filepath.Join(deviceRoot, filepath.Base(hostSrc))
	pushCmd := fmt.Sprintf("adb push %s %s", gceDst, deviceDst)

	if err := inst.runOnHost(5*time.Minute, pushCmd); err != nil {
		return "", fmt.Errorf("error pushing to device: %w", err)
	}

	return deviceDst, nil
}

func (inst *instance) Forward(port int) (string, error) {
	hostForward, err := inst.gceInst.Forward(port)
	if err != nil {
		return "", fmt.Errorf("failed to get IP/port from GCE instance: %w", err)
	}

	// Run socat in the background. This hangs when run from runOnHost().
	cmdStr := fmt.Sprintf("nohup socat TCP-LISTEN:%d,fork TCP:%s", port, hostForward)
	cmdArgs := append([]string{"-f"}, inst.sshArgs(cmdStr)...)
	cmd := exec.Command("ssh", cmdArgs...)
	cmd.Dir = "/root"
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("unable to forward port on host: %w", err)
	}

	for i := 0; i < 100; i++ {
		devicePort := vmimpl.RandomPort()
		cmd := fmt.Sprintf("adb reverse tcp:%d tcp:%d", devicePort, port)
		err = inst.runOnHost(10*time.Second, cmd)
		if err == nil {
			return fmt.Sprintf("127.0.0.1:%d", devicePort), nil
		}
	}

	return "", fmt.Errorf("unable to forward port on device: %w", err)
}

func (inst *instance) Close() error {
	return inst.gceInst.Close()
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	return inst.gceInst.Run(ctx, fmt.Sprintf("adb shell 'cd %s; %s'", deviceRoot, command))
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
