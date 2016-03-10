// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/syzkaller/vm"
)

const (
	hostAddr = "10.0.2.10"
)

func init() {
	vm.Register("qemu", ctor)
}

type instance struct {
	cfg     *vm.Config
	port    int
	rpipe   *os.File
	wpipe   *os.File
	qemu    *exec.Cmd
	readerC chan error
	waiterC chan error

	mu      sync.Mutex
	outputB []byte
	outputC chan []byte
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	for i := 0; ; i++ {
		inst, err := ctorImpl(cfg)
		if err == nil {
			return inst, nil
		}
		if i < 1000 && strings.Contains(err.Error(), "could not set up host forwarding rule") {
			continue
		}
		return nil, err
	}
}

func ctorImpl(cfg *vm.Config) (vm.Instance, error) {
	inst := &instance{cfg: cfg}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	var err error
	inst.rpipe, inst.wpipe, err = os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, inst.wpipe.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}

	if err := inst.Boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func validateConfig(cfg *vm.Config) error {
	if cfg.Bin == "" {
		cfg.Bin = "qemu-system-x86_64"
	}
	if _, err := os.Stat(cfg.Image); err != nil {
		return fmt.Errorf("image file '%v' does not exist: %v", cfg.Image, err)
	}
	if _, err := os.Stat(cfg.Sshkey); err != nil {
		return fmt.Errorf("ssh key '%v' does not exist: %v", cfg.Sshkey, err)
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
	if inst.qemu != nil {
		inst.qemu.Process.Kill()
		err := <-inst.waiterC
		inst.waiterC <- err // repost it for waiting goroutines
		<-inst.readerC
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Boot() error {
	for {
		// Find an unused TCP port.
		inst.port = rand.Intn(64<<10-1<<10) + 1<<10
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", inst.port))
		if err == nil {
			ln.Close()
			break
		}
	}
	// TODO: ignores inst.cfg.Cpu
	args := []string{
		"-hda", inst.cfg.Image,
		"-snapshot",
		"-m", strconv.Itoa(inst.cfg.Mem),
		"-net", "nic",
		"-net", fmt.Sprintf("user,host=%v,hostfwd=tcp::%v-:22", hostAddr, inst.port),
		"-nographic",
		"-enable-kvm",
		"-numa", "node,nodeid=0,cpus=0-1", "-numa", "node,nodeid=1,cpus=2-3",
		"-smp", "sockets=2,cores=2,threads=1",
		"-usb", "-usbdevice", "mouse", "-usbdevice", "tablet",
		"-soundhw", "all",
	}
	if inst.cfg.Kernel != "" {
		args = append(args,
			"-kernel", inst.cfg.Kernel,
			"-append", "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=UZ "+inst.cfg.Cmdline,
		)
	}
	qemu := exec.Command(inst.cfg.Bin, args...)
	qemu.Stdout = inst.wpipe
	qemu.Stderr = inst.wpipe
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %v", inst.cfg.Bin, args, err)
	}
	inst.qemu = qemu
	// Qemu has started.

	// Start output reading goroutine.
	inst.readerC = make(chan error)
	go func(rpipe *os.File) {
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
	}(inst.rpipe)
	inst.rpipe = nil

	// Wait for the qemu asynchronously.
	inst.waiterC = make(chan error, 1)
	go func() {
		err := qemu.Wait()
		inst.wpipe.Close()
		inst.waiterC <- err
	}()

	// Wait for ssh server to come up.
	time.Sleep(10 * time.Second)
	start := time.Now()
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%v", inst.port), 3*time.Second)
		if err == nil {
			c.SetDeadline(time.Now().Add(3 * time.Second))
			var tmp [1]byte
			n, err := c.Read(tmp[:])
			c.Close()
			if err == nil && n > 0 {
				break // ssh is up and responding
			}
			time.Sleep(3 * time.Second)
		}
		select {
		case err := <-inst.waiterC:
			inst.waiterC <- err     // repost it for Close
			time.Sleep(time.Second) // wait for any pending output
			inst.mu.Lock()
			output := inst.outputB
			inst.mu.Unlock()
			return fmt.Errorf("qemu stopped:\n%v\n", string(output))
		default:
		}
		if time.Since(start) > 10*time.Minute {
			inst.mu.Lock()
			output := inst.outputB
			inst.mu.Unlock()
			return fmt.Errorf("ssh server did not start:\n%v\n", string(output))
		}
	}
	// Drop boot output. It is not interesting if the VM has successfully booted.
	inst.mu.Lock()
	inst.outputB = nil
	inst.mu.Unlock()
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", hostAddr, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	args := append(inst.sshArgs("-P"), hostSrc, "root@localhost:"+vmDst)
	cmd := exec.Command("scp", args...)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Minute):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, command string) (<-chan []byte, <-chan error, error) {
	outputC := make(chan []byte, 10)
	errorC := make(chan error, 1)
	inst.mu.Lock()
	inst.outputB = nil
	inst.outputC = outputC
	inst.mu.Unlock()
	signal := func(err error) {
		time.Sleep(3 * time.Second) // wait for any pending output
		inst.mu.Lock()
		if inst.outputC == outputC {
			inst.outputB = nil
			inst.outputC = nil
		}
		inst.mu.Unlock()
		select {
		case errorC <- err:
		default:
		}
	}
	args := append(inst.sshArgs("-p"), "root@localhost", command)
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = inst.wpipe
	cmd.Stderr = inst.wpipe
	if err := cmd.Start(); err != nil {
		inst.mu.Lock()
		inst.outputC = nil
		inst.mu.Unlock()
		return nil, nil, err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(timeout):
			signal(vm.TimeoutErr)
			cmd.Process.Kill()
		case <-done:
		}
	}()
	go func() {
		err := cmd.Wait()
		close(done)
		signal(err)
	}()
	return outputC, errorC, nil
}

func (inst *instance) sshArgs(portArg string) []string {
	return []string{
		"-i", inst.cfg.Sshkey,
		portArg, strconv.Itoa(inst.port),
		"-o", "ConnectionAttempts=10",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "LogLevel=error",
	}
}
