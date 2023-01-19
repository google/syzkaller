// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package starnix

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	var _ vmimpl.Infoer = (*instance)(nil)
	vmimpl.Register("starnix", ctor, true)
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
}

type Pool struct {
	count int
	env   *vmimpl.Env
	cfg   *Config
}

type instance struct {
	fuchsiaDirectory string
	name             string
	index            int
	cfg              *Config
	version          string
	debug            bool
	workdir          string
	port             int
	rpipe            io.ReadCloser
	wpipe            io.WriteCloser
	fuchsiaLogs      *exec.Cmd
	adb              *exec.Cmd
	executor         string
	merger           *vmimpl.OutputMerger
	diagnose         chan bool
}

const ffxBinary = ".jiri_root/bin/ffx"
const targetDir = "/data"

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse starnix vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if _, err := exec.LookPath("adb"); err != nil {
		return nil, err
	}

	pool := &Pool{
		count: cfg.Count,
		env:   env,
		cfg:   cfg,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		fuchsiaDirectory: pool.env.KernelSrc,
		name:             fmt.Sprintf("VM-%v", index),
		index:            index,
		cfg:              pool.cfg,
		debug:            pool.env.Debug,
		workdir:          workdir,
		// This file is auto-generated inside createAdbScript.
		executor: filepath.Join(workdir, "adb_executor.sh"),
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.setFuchsiaVersion(); err != nil {
		return nil, fmt.Errorf(
			"there is an error running ffx commands in the Fuchsia checkout (%q): %v",
			inst.fuchsiaDirectory,
			err)
	}

	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) boot() error {
	inst.port = vmimpl.UnusedTCPPort()
	// Start output merger.
	inst.merger = vmimpl.NewOutputMerger(nil)

	inst.ffx("doctor", "--restart-daemon")

	inst.ffx("emu", "stop", inst.name)

	if err := inst.startFuchsiaVM(); err != nil {
		return fmt.Errorf("could not start Fuchsia VM: %v", err)
	}

	if err := inst.startAdbServerAndConnection(1 * time.Minute); err != nil {
		return fmt.Errorf("could not start and connect to the adb server: %v", err)
	}

	if err := inst.createAdbScript(); err != nil {
		return fmt.Errorf("could not create adb script: %v", err)
	}

	err := inst.startFuchsiaLogs()
	if err != nil {
		return fmt.Errorf("could not start fuchsia logs: %v", err)
	}
	if inst.debug {
		log.Logf(0, "%s booted successfully", inst.name)
	}
	return nil
}

func (inst *instance) Close() {
	inst.ffx("emu", "stop", inst.name)
	if inst.fuchsiaLogs != nil {
		inst.fuchsiaLogs.Process.Kill()
		inst.fuchsiaLogs.Wait()
	}
	if inst.adb != nil {
		inst.adb.Process.Kill()
		inst.adb.Wait()
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
}

func (inst *instance) startFuchsiaVM() error {
	err := inst.ffx("emu", "start", "--headless", "--name", inst.name)
	if err != nil {
		return err
	}
	return nil
}

func (inst *instance) startFuchsiaLogs() error {
	cmd := osutil.Command(ffxBinary, "--target", inst.name, "log")
	cmd.Dir = inst.fuchsiaDirectory
	cmd.Stdout = inst.wpipe
	cmd.Stderr = inst.wpipe
	inst.merger.Add("fuchsia", inst.rpipe)
	inst.fuchsiaLogs = cmd
	return cmd.Start()
}

func (inst *instance) startAdbServerAndConnection(timeout time.Duration) error {
	cmd := osutil.Command(ffxBinary, "--target", inst.name, "starnix", "adb", "-p", fmt.Sprintf("%d", inst.port))
	cmd.Dir = inst.fuchsiaDirectory
	if err := cmd.Start(); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, fmt.Sprintf("the adb bridge is listening on 127.0.0.1:%d", inst.port))
	}
	inst.adb = cmd
	return inst.connectToAdb(timeout)
}

func (inst *instance) connectToAdb(timeout time.Duration) error {
	startTime := time.Now()
	for {
		vmimpl.SleepInterruptible(3 * time.Second)
		if inst.debug {
			log.Logf(0, "attempting to connect to ADB")
		}
		connectOutput, err := osutil.RunCmd(
			2*time.Minute,
			inst.fuchsiaDirectory,
			"adb",
			"connect",
			fmt.Sprintf("127.0.0.1:%d", inst.port))
		if err == nil && strings.HasPrefix(string(connectOutput), "connected to") {
			return nil
		}
		inst.runCommand("adb", "disconnect", fmt.Sprintf("127.0.0.1:%d", inst.port))
		if inst.debug {
			log.Logf(0, "adb connect failed")
		}
		if time.Since(startTime) > timeout {
			return fmt.Errorf("can't connect to ADB server")
		}
	}
}

// Script for telling syz-fuzzer how to connect to syz-executor.
func (inst *instance) createAdbScript() error {
	adbScript := fmt.Sprintf(
		`#!/bin/bash
		adb_port=$1
		fuzzer_args=${@:2}
		adb -s 127.0.0.1:$adb_port shell "cd %s; ./syz-executor $fuzzer_args"`, targetDir)
	return os.WriteFile(inst.executor, []byte(adbScript), 0777)
}

func (inst *instance) ffx(args ...string) error {
	return inst.runCommand(ffxBinary, args...)
}

// Runs a command inside the fuchsia directory.
func (inst *instance) runCommand(cmd string, args ...string) error {
	if inst.debug {
		log.Logf(0, "running command: %s %q", cmd, args)
	}
	output, err := osutil.RunCmd(5*time.Minute, inst.fuchsiaDirectory, cmd, args...)
	if inst.debug {
		log.Logf(0, "%s", output)
	}
	return err
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/starnix: forward port is zero")
	}
	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join(targetDir, base)
	if base == "syz-fuzzer" || base == "syz-execprog" {
		return hostSrc, nil // we will run these on host.
	}

	err := inst.runCommand(
		"adb",
		"-s",
		fmt.Sprintf("127.0.0.1:%d", inst.port),
		"push",
		hostSrc,
		vmDst)
	return vmDst, err
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("adb", rpipe)

	args := strings.Split(command, " ")
	if bin := filepath.Base(args[0]); bin == "syz-fuzzer" || bin == "syz-execprog" {
		for i, arg := range args {
			if strings.HasPrefix(arg, "-executor=") {
				args[i] = fmt.Sprintf("-executor=%s %d", inst.executor, inst.port)
				// TODO(fxbug.dev/120202): reenable threaded mode once clone3 is fixed.
				args = append(args, "-threaded=0")
			}
		}
	}
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Dir = inst.workdir
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Run(); err != nil {
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
	retry:
		select {
		case <-time.After(timeout):
			signal(vmimpl.ErrTimeout)
		case <-stop:
			signal(vmimpl.ErrTimeout)
		case <-inst.diagnose:
			cmd.Process.Kill()
			goto retry
		case err := <-inst.merger.Err:
			cmd.Process.Kill()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		cmd.Wait()
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Info() ([]byte, error) {
	info := fmt.Sprintf("%v\n%v", inst.version, "ffx")
	return []byte(info), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *instance) setFuchsiaVersion() error {
	version, err := osutil.RunCmd(1*time.Minute, inst.fuchsiaDirectory, ffxBinary, "version")
	if err != nil {
		return err
	}
	inst.version = string(version)
	return nil
}
