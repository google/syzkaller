// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kvm

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/vm"
)

const (
	hostAddr = "192.168.33.1"
)

func init() {
	vm.Register("kvm", ctor)
}

type instance struct {
	cfg         *vm.Config
	sandbox     string
	sandboxPath string
	lkvm        *exec.Cmd
	readerC     chan error
	waiterC     chan error

	mu      sync.Mutex
	outputB []byte
	outputC chan []byte
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	sandbox := fmt.Sprintf("syz-%v", cfg.Index)
	inst := &instance{
		cfg:         cfg,
		sandbox:     sandbox,
		sandboxPath: filepath.Join(os.Getenv("HOME"), ".lkvm", sandbox),
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	os.RemoveAll(inst.sandboxPath)
	os.Remove(inst.sandboxPath + ".sock")
	out, err := exec.Command(inst.cfg.Bin, "setup", sandbox).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to lkvm setup: %v\n%s", err, out)
	}
	scriptPath := filepath.Join(cfg.Workdir, "script.sh")
	if err := ioutil.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}

	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, wpipe.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}

	inst.lkvm = exec.Command("taskset", "-c", strconv.Itoa(inst.cfg.Index%runtime.NumCPU()),
		inst.cfg.Bin, "sandbox",
		"--disk", inst.sandbox,
		"--kernel", inst.cfg.Kernel,
		"--params", "slub_debug=UZ "+inst.cfg.Cmdline,
		"--mem", strconv.Itoa(inst.cfg.Mem),
		"--cpus", strconv.Itoa(inst.cfg.Cpu),
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
				if inst.cfg.Debug {
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

func validateConfig(cfg *vm.Config) error {
	if cfg.Bin == "" {
		cfg.Bin = "lkvm"
	}
	if cfg.Image != "" {
		return fmt.Errorf("lkvm does not support custom images")
	}
	if cfg.Sshkey != "" {
		return fmt.Errorf("lkvm does not need ssh key")
	}
	if _, err := os.Stat(cfg.Kernel); err != nil {
		return fmt.Errorf("kernel file '%v' does not exist: %v", cfg.Kernel, err)
	}
	if cfg.Cpu <= 0 || cfg.Cpu > 1024 {
		return fmt.Errorf("bad qemu cpu: %v, want [1-1024]", cfg.Cpu)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return fmt.Errorf("bad qemu mem: %v, want [128-1048576]", cfg.Mem)
	}
	return nil
}

func (inst *instance) Close() {
	if inst.lkvm != nil {
		inst.lkvm.Process.Kill()
		err := <-inst.waiterC
		inst.waiterC <- err // repost it for waiting goroutines
		<-inst.readerC
	}
	os.RemoveAll(inst.cfg.Workdir)
	os.RemoveAll(inst.sandboxPath)
	os.Remove(inst.sandboxPath + ".sock")
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", hostAddr, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	dst := filepath.Join(inst.sandboxPath, vmDst)
	if err := fileutil.CopyFile(hostSrc, dst, false); err != nil {
		return "", err
	}
	if err := os.Chmod(dst, 0777); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	outputC := make(chan []byte, 10)
	errorC := make(chan error, 1)
	inst.mu.Lock()
	inst.outputB = nil
	inst.outputC = outputC
	inst.mu.Unlock()

	cmdFile := filepath.Join(inst.sandboxPath, "/syz-cmd")
	tmpFile := cmdFile + "-tmp"
	if err := ioutil.WriteFile(tmpFile, []byte(command), 0700); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(tmpFile, cmdFile); err != nil {
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
				resultErr = vm.TimeoutErr
				break loop
			case <-stop:
				resultErr = vm.TimeoutErr
				break loop
			case <-secondTicker.C:
				if _, err := os.Stat(cmdFile); err != nil {
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
