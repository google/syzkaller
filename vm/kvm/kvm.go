// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package kvm provides VMs based on lkvm (kvmtool) virtualization.
// It is not well tested.
package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	hostAddr = "192.168.33.1"
)

func init() {
	vmimpl.Register("kvm", ctor, true)
}

type Config struct {
	Count   int    // number of VMs to use
	Lkvm    string // lkvm binary name
	Kernel  string // e.g. arch/x86/boot/bzImage
	Cmdline string // kernel command line
	CPU     int    // number of VM CPUs
	Mem     int    // amount of VM memory in MBs
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg         *Config
	sandbox     string
	sandboxPath string
	lkvm        *exec.Cmd
	readerC     chan error
	waiterC     chan error
	debug       bool

	mu      sync.Mutex
	outputB []byte
	outputC chan []byte
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count: 1,
		Lkvm:  "lkvm",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse kvm vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}
	if env.Image != "" {
		return nil, fmt.Errorf("lkvm does not support custom images")
	}
	if _, err := exec.LookPath(cfg.Lkvm); err != nil {
		return nil, err
	}
	if !osutil.IsExist(cfg.Kernel) {
		return nil, fmt.Errorf("kernel file '%v' does not exist", cfg.Kernel)
	}
	if cfg.CPU < 1 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("invalid config param cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("invalid config param mem: %v, want [128-1048576]", cfg.Mem)
	}
	cfg.Kernel = osutil.Abs(cfg.Kernel)
	pool := &Pool{
		cfg: cfg,
		env: env,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	sandbox := fmt.Sprintf("syz-%v", index)
	inst := &instance{
		cfg:         pool.cfg,
		sandbox:     sandbox,
		sandboxPath: filepath.Join(os.Getenv("HOME"), ".lkvm", sandbox),
		debug:       pool.env.Debug,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	os.RemoveAll(inst.sandboxPath)
	os.Remove(inst.sandboxPath + ".sock")
	out, err := osutil.Command(inst.cfg.Lkvm, "setup", sandbox).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to lkvm setup: %v\n%s", err, out)
	}
	scriptPath := filepath.Join(workdir, "script.sh")
	if err := osutil.WriteExecFile(scriptPath, []byte(script)); err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}

	inst.lkvm = osutil.Command("taskset", "-c", strconv.Itoa(index%runtime.NumCPU()),
		inst.cfg.Lkvm, "sandbox",
		"--disk", inst.sandbox,
		"--kernel", inst.cfg.Kernel,
		"--params", "slub_debug=UZ "+inst.cfg.Cmdline,
		"--mem", strconv.Itoa(inst.cfg.Mem),
		"--cpus", strconv.Itoa(inst.cfg.CPU),
		"--network", "mode=user",
		"--sandbox", scriptPath,
	)
	inst.lkvm.Stdout = wpipe
	inst.lkvm.Stderr = wpipe
	if err := inst.lkvm.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, fmt.Errorf("failed to start lkvm: %v", err)
	}

	// Start output reading goroutine.
	inst.readerC = make(chan error)
	go func() {
		var buf [64 << 10]byte
		for {
			n, err := rpipe.Read(buf[:])
			if n != 0 {
				if inst.debug {
					os.Stdout.Write(buf[:n])
					os.Stdout.Write([]byte{'\n'})
				}
				inst.mu.Lock()
				inst.outputB = append(inst.outputB, buf[:n]...)
				if inst.outputC != nil {
					select {
					case inst.outputC <- inst.outputB:
						inst.outputB = nil
					default:
					}
				}
				inst.mu.Unlock()
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				rpipe.Close()
				inst.readerC <- err
				return
			}
		}
	}()

	// Wait for the lkvm asynchronously.
	inst.waiterC = make(chan error, 1)
	go func() {
		err := inst.lkvm.Wait()
		wpipe.Close()
		inst.waiterC <- err
	}()

	// Wait for the script to start serving.
	_, errc, err := inst.Run(10*time.Minute, nil, "mount -t debugfs none /sys/kernel/debug/")
	if err == nil {
		err = <-errc
	}
	if err != nil {
		return nil, fmt.Errorf("failed to run script: %v", err)
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) Close() {
	if inst.lkvm != nil {
		inst.lkvm.Process.Kill()
		err := <-inst.waiterC
		inst.waiterC <- err // repost it for waiting goroutines
		<-inst.readerC
	}
	os.RemoveAll(inst.sandboxPath)
	os.Remove(inst.sandboxPath + ".sock")
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", hostAddr, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	dst := filepath.Join(inst.sandboxPath, vmDst)
	if err := osutil.CopyFile(hostSrc, dst); err != nil {
		return "", err
	}
	if err := os.Chmod(dst, 0777); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	outputC := make(chan []byte, 10)
	errorC := make(chan error, 1)
	inst.mu.Lock()
	inst.outputB = nil
	inst.outputC = outputC
	inst.mu.Unlock()

	cmdFile := filepath.Join(inst.sandboxPath, "/syz-cmd")
	tmpFile := cmdFile + "-tmp"
	if err := osutil.WriteExecFile(tmpFile, []byte(command)); err != nil {
		return nil, nil, err
	}
	if err := osutil.Rename(tmpFile, cmdFile); err != nil {
		return nil, nil, err
	}

	signal := func(err error) {
		inst.mu.Lock()
		if inst.outputC == outputC {
			inst.outputB = nil
			inst.outputC = nil
		}
		inst.mu.Unlock()
		errorC <- err
	}

	go func() {
		timeoutTicker := time.NewTicker(timeout)
		secondTicker := time.NewTicker(time.Second)
		var resultErr error
	loop:
		for {
			select {
			case <-timeoutTicker.C:
				resultErr = vmimpl.ErrTimeout
				break loop
			case <-stop:
				resultErr = vmimpl.ErrTimeout
				break loop
			case <-secondTicker.C:
				if !osutil.IsExist(cmdFile) {
					resultErr = nil
					break loop
				}
			case err := <-inst.waiterC:
				inst.waiterC <- err // repost it for Close
				resultErr = fmt.Errorf("lkvm exited")
				break loop
			}
		}
		signal(resultErr)
		timeoutTicker.Stop()
		secondTicker.Stop()
	}()

	return outputC, errorC, nil
}

func (inst *instance) Diagnose() ([]byte, bool) {
	return nil, false
}

const script = `#! /bin/bash
while true; do
	if [ -e "/syz-cmd" ]; then
		/syz-cmd
		rm -f /syz-cmd
	else
		sleep 1
	fi
done
`
