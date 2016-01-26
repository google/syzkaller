// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

import (
	"fmt"
	"io/ioutil"
	"log"
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
	inst := &instance{
		cfg:    cfg,
		closed: make(chan bool),
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
	if err := inst.repair(); err != nil {
		return nil, err
	}
	// Remove temp files from previous runs.
	inst.adb("shell", "rm -Rf /data/syzkaller*")
	closeInst = nil
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
	if err := inst.adb("reverse", fmt.Sprintf("tcp:%v", devicePort), fmt.Sprintf("tcp:%v", port)); err != nil {
		return "", err
	}
	return fmt.Sprintf("127.0.0.1:%v", devicePort), nil
}

func (inst *instance) adb(args ...string) error {
	if inst.cfg.Debug {
		log.Printf("executing adb %+v", args)
	}
	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wpipe.Close()
	defer rpipe.Close()
	cmd := exec.Command(inst.cfg.Bin, args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		return err
	}
	wpipe.Close()
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Minute):
			if inst.cfg.Debug {
				log.Printf("adb hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.cfg.Debug {
			log.Printf("adb failed: %v\n%s", err, out)
		}
		return fmt.Errorf("adb %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.cfg.Debug {
		log.Printf("adb returned")
	}
	return nil
}

func (inst *instance) repair() error {
	// Give the device up to 5 minutes to come up (it can be rebooting after a previous crash).
	time.Sleep(3 * time.Second)
	for i := 0; i < 300; i++ {
		time.Sleep(time.Second)
		if inst.adb("shell", "pwd") == nil {
			return nil
		}
	}
	// If it does not help, reboot.
	// adb reboot episodically hangs, so we use a more reliable way.
	// Ignore errors because all other adb commands hang as well
	// and the binary can already be on the device.
	inst.adb("push", inst.cfg.Executor, "/data/syz-executor")
	if err := inst.adb("shell", "/data/syz-executor", "reboot"); err != nil {
		return err
	}
	// Now give it another 5 minutes.
	time.Sleep(10 * time.Second)
	var err error
	for i := 0; i < 300; i++ {
		time.Sleep(time.Second)
		if err = inst.adb("shell", "pwd"); err == nil {
			return nil
		}
	}
	return fmt.Errorf("instance is dead and unrepairable: %v", err)
}

func (inst *instance) Close() {
	close(inst.closed)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/data", filepath.Base(hostSrc))
	if err := inst.adb("push", hostSrc, vmDst); err != nil {
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
		if inst.cfg.Debug {
			log.Printf("cat exited: %v", err)
		}
		catDone <- fmt.Errorf("cat exited: %v", err)
	}()

	if inst.cfg.Debug {
		log.Printf("starting: adb shell %v", command)
	}
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
		if inst.cfg.Debug {
			log.Printf("adb exited: %v", err)
		}
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
			if inst.cfg.Debug {
				log.Printf("instance closed")
			}
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
