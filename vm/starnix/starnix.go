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
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	var _ vmimpl.Infoer = (*instance)(nil)
	vmimpl.Register("starnix", ctor, true)
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
	// Location of Fuchsia checkout, for now we need this to run ffx commands.
	Fuchsia string `json:"fuchsia"`
}

type Pool struct {
	count   int
	env     *vmimpl.Env
	cfg     *Config
	version string
}

type instance struct {
	fuchsia          string
	name             string
	index            int
	cfg              *Config
	version          string
	args             []string
	debug            bool
	workdir          string
	timeouts         targets.Timeouts
	port             int
	rpipe            io.ReadCloser
	wpipe            io.WriteCloser
	fuchsiaVmStarted bool
	executor         string
	merger           *vmimpl.OutputMerger
	diagnose         chan bool
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse starnix vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if !osutil.IsDir(cfg.Fuchsia) {
		return nil, fmt.Errorf("%q is not a valid directory", cfg.Fuchsia)
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
	return pool.ctor(workdir, index)
}

func (pool *Pool) ctor(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		fuchsia:  pool.cfg.Fuchsia,
		name:     fmt.Sprintf("VM-%v", index),
		index:    index,
		cfg:      pool.cfg,
		debug:    pool.env.Debug,
		timeouts: pool.env.Timeouts,
		workdir:  workdir,
		// This file is auto-generated inside createAdbScript
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

	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) terminateFuchsiaVm() {
	if inst.debug {
		log.Logf(0, "Terminating Fuchsia VM: %v", inst.name)
	}
	inst.runCommand("ffx", "emu", "stop", inst.name)
}

func (inst *instance) Close() {
	if inst.fuchsiaVmStarted {
		inst.terminateFuchsiaVm()
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

func (inst *instance) startFuchsiaVm() error {
	_, err := inst.runCommand("ffx", "emu", "start", "--headless", "--name", inst.name)
	if err != nil {
		return err
	}
	inst.fuchsiaVmStarted = true
	return nil
}

func (inst *instance) startFuchsiaLogs() error {
	cmd := osutil.Command("ffx", "--target", inst.name, "log")
	cmd.Dir = inst.fuchsia
	cmd.Stdout = inst.wpipe
	cmd.Stderr = inst.wpipe
	inst.merger.Add("fuchsia", inst.rpipe)
	return cmd.Start()
}

func (inst *instance) startAdbServerAndConnection(timeout time.Duration) error {
	cmd := osutil.Command("ffx", "--target", inst.name, "starnix", "adb", "-p", fmt.Sprintf("%d", inst.port))
	cmd.Dir = inst.fuchsia
	if err := cmd.Start(); err != nil {
		return err
	}
	return inst.connectToAdb(timeout)
}

func (inst *instance) connectToAdb(timeout time.Duration) error {
	startTime := time.Now()
	for {
		select {
		case <-time.After(3 * time.Second):
		}
		if inst.debug {
			log.Logf(0, "Attempting to connect to ADB")
		}
		cmd := osutil.Command("adb", "connect", fmt.Sprintf("127.0.0.1:%d", inst.port))
		connect_output, err := cmd.Output()
		if err == nil && strings.HasPrefix(string(connect_output), "connected to") {
			return nil
		}
		cmd = osutil.Command("adb", "disconnect", fmt.Sprintf("127.0.0.1:%d", inst.port))
		cmd.Run()
		if inst.debug {
			log.Logf(0, "adb connect failed")
		}
		if time.Since(startTime) > timeout {
			return fmt.Errorf("Can't connect to ADB server")
		}
	}
}

// Script for telling syz-fuzzer how to connect to syz-executor
func (inst *instance) createAdbScript() error {
	adbScript := fmt.Sprintf(
		`#!/bin/bash
		adb_port=$1
		fuzzer_args=${@:2}
		adb -s 127.0.0.1:$adb_port shell "cd %s; ./syz-executor $fuzzer_args"`, inst.targetDir())
	return os.WriteFile(inst.executor, []byte(adbScript), 0777)
}

func (inst *instance) boot() error {
	inst.port = vmimpl.UnusedTCPPort()
	// Start output merger.
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)

	inst.terminateFuchsiaVm()

	if err := inst.startFuchsiaVm(); err != nil {
		return err
	}

	if err := inst.startAdbServerAndConnection(1 * time.Minute * inst.timeouts.Scale); err != nil {
		return err
	}

	if err := inst.createAdbScript(); err != nil {
		return err
	}

	if err := inst.startFuchsiaLogs(); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, "%s booted successfully, inst.port = %d", inst.name, inst.port)
	}
	return nil
}

// Runs a command inside the fuchsia directory and redirects the output to the
// instance output merger
func (inst *instance) runCommand(args ...string) (*exec.Cmd, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, err
	}
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Dir = inst.fuchsia
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	inst.merger.Add(args[0], rpipe)
	err = cmd.Run()
	wpipe.Close()
	return cmd, err
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/starnix: forward port is zero")
	}
	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *instance) targetDir() string {
	return "/data"
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join(inst.targetDir(), base)
	if base == "syz-fuzzer" || base == "syz-execprog" {
		return hostSrc, nil // we will run these on host
	}

	_, err := inst.runCommand("adb", "-s", fmt.Sprintf("127.0.0.1:%d", inst.port), "push", hostSrc, vmDst)
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
			}
		}
	}
	log.Logf(0, "running command: %#v", args)
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
	info := fmt.Sprintf("%v\n%v %q", inst.version, "Starnix", inst.args)
	return []byte(info), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
