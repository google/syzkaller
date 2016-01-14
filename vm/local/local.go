// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package local

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("local", ctor)
}

type instance struct {
	cfg    *vm.Config
	closed chan bool
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	// Disable annoying segfault dmesg messages, fuzzer is going to crash a lot.
	etrace, err := os.Open("/proc/sys/debug/exception-trace")
	if err == nil {
		etrace.Write([]byte{'0'})
		etrace.Close()
	}

	// Don't write executor core files.
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{0, 0})

	inst := &instance{
		cfg:    cfg,
		closed: make(chan bool),
	}
	return inst, nil
}

func (inst *instance) Close() {
	close(inst.closed)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("127.0.0.1:%v", port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join(inst.cfg.Workdir, filepath.Base(hostSrc))
	if err := fileutil.CopyFile(hostSrc, vmDst, false); err != nil {
		return "", err
	}
	if err := os.Chmod(vmDst, 0777); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, command string) (<-chan []byte, <-chan error, error) {
	for strings.Index(command, "  ") != -1 {
		command = strings.Replace(command, "  ", " ", -1)
	}
	args := strings.Split(command, " ")
	cmd := exec.Command(args[0], args[1:]...)
	if inst.cfg.Debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	outputC := make(chan []byte, 10)
	errorC := make(chan error, 2)
	done := make(chan bool)
	go func() {
		errorC <- cmd.Wait()
		close(done)
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		timeout := time.NewTicker(timeout)
		for {
			select {
			case <-ticker.C:
				select {
				case outputC <- []byte{'.'}:
				default:
				}
			case <-timeout.C:
				errorC <- vm.TimeoutErr
				cmd.Process.Kill()
				ticker.Stop()
				return
			case <-done:
				ticker.Stop()
				timeout.Stop()
				return
			case <-inst.closed:
				errorC <- fmt.Errorf("closed")
				cmd.Process.Kill()
				ticker.Stop()
				timeout.Stop()
				return
			}
		}
	}()
	return outputC, errorC, nil
}
