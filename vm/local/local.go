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

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, wpipe.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}
	for strings.Index(command, "  ") != -1 {
		command = strings.Replace(command, "  ", " ", -1)
	}
	args := strings.Split(command, " ")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()
	outputC := make(chan []byte, 10)
	errorC := make(chan error, 1)
	done := make(chan bool)
	signal := func(err error) {
		time.Sleep(3 * time.Second) // wait for any pending output
		select {
		case errorC <- err:
		default:
		}
	}
	go func() {
		var buf [64 << 10]byte
		var output []byte
		for {
			n, err := rpipe.Read(buf[:])
			if n != 0 {
				if inst.cfg.Debug {
					os.Stdout.Write(buf[:n])
					os.Stdout.Write([]byte{'\n'})
				}
				output = append(output, buf[:n]...)
				select {
				case outputC <- output:
					output = nil
				default:
				}
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				rpipe.Close()
				return
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		signal(err)
		close(done)
	}()
	go func() {
		timeout := time.NewTicker(timeout)
		for {
			select {
			case <-timeout.C:
				signal(vm.TimeoutErr)
				cmd.Process.Kill()
				return
			case <-stop:
				signal(vm.TimeoutErr)
				cmd.Process.Kill()
				timeout.Stop()
				return
			case <-done:
				timeout.Stop()
				return
			case <-inst.closed:
				signal(fmt.Errorf("closed"))
				cmd.Process.Kill()
				timeout.Stop()
				return
			}
		}
	}()
	return outputC, errorC, nil
}
