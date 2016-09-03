// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	rpipe   io.ReadCloser
	wpipe   io.WriteCloser
	qemu    *exec.Cmd
	waiterC chan error
	merger  *vm.OutputMerger
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
		os.RemoveAll(cfg.Workdir)
		return nil, err
	}
}

func ctorImpl(cfg *vm.Config) (vm.Instance, error) {
	inst := &instance{cfg: cfg}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.close(false)
		}
	}()

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	if cfg.Image == "9p" {
		inst.cfg.Sshkey = filepath.Join(inst.cfg.Workdir, "key")
		keygen := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-C", "", "-f", inst.cfg.Sshkey)
		if out, err := keygen.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to execute ssh-keygen: %v\n%s", err, out)
		}
		initFile := filepath.Join(cfg.Workdir, "init.sh")
		if err := ioutil.WriteFile(initFile, []byte(strings.Replace(initScript, "{{KEY}}", inst.cfg.Sshkey, -1)), 0777); err != nil {
			return nil, fmt.Errorf("failed to create init file: %v", err)
		}
	}

	var err error
	inst.rpipe, inst.wpipe, err = vm.LongPipe()
	if err != nil {
		return nil, err
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
	if cfg.Image == "9p" {
		if cfg.Kernel == "" {
			return fmt.Errorf("9p image requires kernel")
		}
	} else {
		if _, err := os.Stat(cfg.Image); err != nil {
			return fmt.Errorf("image file '%v' does not exist: %v", cfg.Image, err)
		}
		if _, err := os.Stat(cfg.Sshkey); err != nil {
			return fmt.Errorf("ssh key '%v' does not exist: %v", cfg.Sshkey, err)
		}
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
	inst.close(true)
}

func (inst *instance) close(removeWorkDir bool) {
	if inst.qemu != nil {
		inst.qemu.Process.Kill()
		err := <-inst.waiterC
		inst.waiterC <- err // repost it for waiting goroutines
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
	os.Remove(filepath.Join(inst.cfg.Workdir, "key"))
	if removeWorkDir {
		os.RemoveAll(inst.cfg.Workdir)
	}
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
		"-m", strconv.Itoa(inst.cfg.Mem),
		"-net", "nic",
		"-net", fmt.Sprintf("user,host=%v,hostfwd=tcp::%v-:22", hostAddr, inst.port),
		"-display", "none",
		"-serial", "stdio",
		"-no-reboot",
		"-enable-kvm",
		"-numa", "node,nodeid=0,cpus=0-1", "-numa", "node,nodeid=1,cpus=2-3",
		"-smp", "sockets=2,cores=2,threads=1",
		"-usb", "-usbdevice", "mouse", "-usbdevice", "tablet",
		"-soundhw", "all",
	}
	if inst.cfg.Image == "9p" {
		args = append(args,
			"-fsdev", "local,id=fsdev0,path=/,security_model=none,readonly",
			"-device", "virtio-9p-pci,fsdev=fsdev0,mount_tag=/dev/root",
		)
	} else {
		args = append(args,
			"-hda", inst.cfg.Image,
			"-snapshot",
		)
	}
	if inst.cfg.Initrd != "" {
		args = append(args,
			"-initrd", inst.cfg.Initrd,
		)
	}
	if inst.cfg.Kernel != "" {
		cmdline := "console=ttyS0 oops=panic panic_on_warn=1 panic=-1 ftrace_dump_on_oops=orig_cpu debug earlyprintk=serial slub_debug=UZ "
		if inst.cfg.Image == "9p" {
			cmdline += "root=/dev/root rootfstype=9p rootflags=trans=virtio,version=9p2000.L,cache=loose "
			cmdline += "init=" + filepath.Join(inst.cfg.Workdir, "init.sh") + " "
		} else {
			cmdline += "root=/dev/sda "
		}
		args = append(args,
			"-kernel", inst.cfg.Kernel,
			"-append", cmdline+inst.cfg.Cmdline,
		)
	}
	qemu := exec.Command(inst.cfg.Bin, args...)
	qemu.Stdout = inst.wpipe
	qemu.Stderr = inst.wpipe
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %v", inst.cfg.Bin, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.qemu = qemu
	// Qemu has started.

	// Start output merger.
	var tee io.Writer
	if inst.cfg.Debug {
		tee = os.Stdout
	}
	inst.merger = vm.NewOutputMerger(tee)
	inst.merger.Add(inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()

	// Wait for the qemu asynchronously.
	inst.waiterC = make(chan error, 1)
	go func() {
		err := qemu.Wait()
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
			bootOutputStop <- true
			<-bootOutputStop
			return fmt.Errorf("qemu stopped:\n%v\n", string(bootOutput))
		default:
		}
		if time.Since(start) > 10*time.Minute {
			bootOutputStop <- true
			<-bootOutputStop
			return fmt.Errorf("ssh server did not start:\n%v\n", string(bootOutput))
		}
	}
	bootOutputStop <- true
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", hostAddr, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	basePath := "/"
	if inst.cfg.Image == "9p" {
		basePath = "/tmp"
	}
	vmDst := filepath.Join(basePath, filepath.Base(hostSrc))
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
	rpipe, wpipe, err := vm.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add(rpipe)

	args := append(inst.sshArgs("-p"), "root@localhost", command)
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
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
	return inst.merger.Output, errc, nil
}

func (inst *instance) sshArgs(portArg string) []string {
	return []string{
		"-i", inst.cfg.Sshkey,
		portArg, strconv.Itoa(inst.port),
		"-F", "/dev/null",
		"-o", "ConnectionAttempts=10",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "LogLevel=error",
	}
}

const initScript = `#! /bin/bash
set -eux
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs nodev /sys/kernel/debug/
mount -t tmpfs none /tmp
mount -t tmpfs none /var
mount -t tmpfs none /etc
mount -t tmpfs none /root
touch /etc/fstab
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/
chmod 0700 /root
chmod 0600 /root/key.pub
mkdir -p /var/run/sshd/
chmod 700 /var/run/sshd
cat > /etc/ssh/sshd_config <<EOF
          Port 22
          Protocol 2
          UsePrivilegeSeparation no
          HostKey {{KEY}}
          PermitRootLogin yes
          AuthenticationMethods publickey
          ChallengeResponseAuthentication no
          AuthorizedKeysFile /root/key.pub
          IgnoreUserKnownHosts yes
          AllowUsers root
          LogLevel INFO
          TCPKeepAlive yes
          RSAAuthentication yes
          PubkeyAuthentication yes
EOF
/sbin/dhclient eth0
/usr/sbin/sshd -e -D
/sbin/halt -f
`
