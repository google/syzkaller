// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("adb", ctor)
}

type instance struct {
	cfg    *vm.Config
	closed chan bool
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	inst := &instance{
		cfg:    cfg,
		closed: make(chan bool),
	}
	if err := inst.adbOK(); err != nil {
		return nil, err
	}
	if err := inst.adbReboot(); err != nil {
		return nil, err
	}
	return inst, nil
}

func validateConfig(cfg *vm.Config) error {
	if cfg.Bin == "" {
		cfg.Bin = "adb"
	}
	if _, err := os.Stat(cfg.ConsoleDev); err != nil {
		return fmt.Errorf("console device '%v' is missing: %v", cfg.ConsoleDev, err)
	}
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	// If 35099 turns out to be busy, try to forward random ports several times.
	devicePort := 35099
	if out, err := inst.adb("reverse", fmt.Sprintf("tcp:%v", devicePort), fmt.Sprintf("tcp:%v", port)); err != nil {
		return "", fmt.Errorf("adb reverse failed: %v\n%s", err, out)
	}
	return fmt.Sprintf("127.0.0.1:%v", devicePort), nil
}

func (inst *instance) adb(args ...string) ([]byte, error) {
	out, err := exec.Command(inst.cfg.Bin, args...).CombinedOutput()
	return out, err
}

// adbOK checks that adb works and there are is devices attached.
func (inst *instance) adbOK() error {
	out, err := inst.adb("shell", "pwd")
	if err != nil {
		return fmt.Errorf("abd does not work or device is not connected: %v\n%s", err, out)
	}
	return nil
}

func (inst *instance) adbReboot() error {
	// adb reboot episodically hangs, so we use a more reliable way.
	if _, err := inst.adb("push", inst.cfg.Executor, "/data/syz-executor"); err != nil {
		return err
	}
	if _, err := inst.adb("shell", "/data/syz-executor", "reboot"); err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	for i := 0; i < 300; i++ {
		time.Sleep(time.Second)
		if inst.adbOK() == nil {
			return nil
		}
	}
	return fmt.Errorf("device did not come up after reboot")
}

func (inst *instance) Close() {
	close(inst.closed)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/data", filepath.Base(hostSrc))
	if _, err := inst.adb("push", hostSrc, vmDst); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, command string) (<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, wpipe.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}

	cat := exec.Command("cat", inst.cfg.ConsoleDev)
	cat.Stdout = wpipe
	cat.Stderr = wpipe
	if err := cat.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, nil, fmt.Errorf("failed to start cat %v: %v", inst.cfg.ConsoleDev, err)

	}
	catDone := make(chan error, 1)
	go func() {
		err := cat.Wait()
		catDone <- fmt.Errorf("cat exited: %v", err)
	}()

	adb := exec.Command(inst.cfg.Bin, "shell", "cd /data; "+command)
	adb.Stdout = wpipe
	adb.Stderr = wpipe
	if err := adb.Start(); err != nil {
		cat.Process.Kill()
		rpipe.Close()
		wpipe.Close()
		return nil, nil, fmt.Errorf("failed to start adb: %v", err)
	}
	adbDone := make(chan error, 1)
	go func() {
		err := adb.Wait()
		adbDone <- fmt.Errorf("adb exited: %v", err)
	}()

	wpipe.Close()
	outc := make(chan []byte, 10)
	errc := make(chan error, 1)
	signal := func(err error) {
		time.Sleep(5 * time.Second) // wait for any pending output
		select {
		case errc <- err:
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
				case outc <- output:
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
		select {
		case <-time.After(timeout):
			signal(vm.TimeoutErr)
			cat.Process.Kill()
			adb.Process.Kill()
		case <-inst.closed:
			signal(fmt.Errorf("instance closed"))
			cat.Process.Kill()
			adb.Process.Kill()
		case err := <-catDone:
			signal(err)
			adb.Process.Kill()
		case err := <-adbDone:
			signal(err)
			cat.Process.Kill()
		}
	}()
	return outc, errc, nil
}
