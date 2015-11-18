// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("local", ctor)
}

type local struct {
	params
	workdir  string
	syscalls string
	id       int
	mgrPort  int
	nocover  bool
}

type params struct {
	Fuzzer   string
	Executor string
}

func ctor(cfg *vm.Config, index int) (vm.Instance, error) {
	p := new(params)
	if err := json.Unmarshal(cfg.Params, p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal local params: %v", err)
	}
	if _, err := os.Stat(p.Fuzzer); err != nil {
		return nil, fmt.Errorf("fuzzer binary '%v' does not exist: %v", p.Fuzzer, err)
	}
	if _, err := os.Stat(p.Executor); err != nil {
		return nil, fmt.Errorf("executor binary '%v' does not exist: %v", p.Executor, err)
	}

	os.MkdirAll(cfg.Workdir, 0770)

	// Disable annoying segfault dmesg messages, fuzzer is going to crash a lot.
	etrace, err := os.Open("/proc/sys/debug/exception-trace")
	if err == nil {
		etrace.Write([]byte{'0'})
		etrace.Close()
	}

	// Don't write executor core files.
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{0, 0})

	loc := &local{
		params:   *p,
		workdir:  cfg.Workdir,
		syscalls: cfg.EnabledSyscalls,
		nocover:  cfg.NoCover,
		id:       index,
		mgrPort:  cfg.ManagerPort,
	}
	return loc, nil
}

func (loc *local) Run() {
	name := fmt.Sprintf("local-%v", loc.id)
	log.Printf("%v: started\n", name)
	for run := 0; ; run++ {
		cmd := exec.Command(loc.Fuzzer, "-name", name, "-saveprog", "-executor", loc.Executor,
			"-manager", fmt.Sprintf("localhost:%v", loc.mgrPort), "-dropprivs=0")
		if loc.syscalls != "" {
			cmd.Args = append(cmd.Args, "-calls="+loc.syscalls)
		}
		if loc.nocover {
			cmd.Args = append(cmd.Args, "-nocover")
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Dir = loc.workdir
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			log.Printf("failed to start fuzzer binary: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		pid := cmd.Process.Pid
		done := make(chan bool)
		go func() {
			select {
			case <-done:
			case <-time.After(time.Hour):
				log.Printf("%v: running for long enough, restarting", name)
				syscall.Kill(-pid, syscall.SIGKILL)
				syscall.Kill(-pid, syscall.SIGKILL)
				syscall.Kill(pid, syscall.SIGKILL)
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}()
		err := cmd.Wait()
		close(done)
		log.Printf("fuzzer binary exited: %v", err)
		time.Sleep(10 * time.Second)
	}
}
