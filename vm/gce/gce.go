// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gce allows to use Google Compute Engine (GCE) virtual machines as VMs.
// It is assumed that syz-manager also runs on GCE as VMs are created in the current project/zone.
//
// See https://cloud.google.com/compute/docs for details.
// In particular, how to build GCE-compatible images:
// https://cloud.google.com/compute/docs/tutorials/building-images
// Working with serial console:
// https://cloud.google.com/compute/docs/instances/interacting-with-serial-console
package gce

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/gce"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("gce", ctor)
}

type instance struct {
	cfg     *vm.Config
	name    string
	ip      string
	offset  int64
	sshkey  string // per-instance private ssh key
	workdir string
	closed  chan bool
}

var (
	initOnce sync.Once
	GCE      *gce.Context
)

func initGCE() {
	var err error
	GCE, err = gce.NewContext()
	if err != nil {
		Fatalf("failed to init gce: %v", err)
	}
	Logf(0, "gce initialized: running on %v, internal IP, %v project %v, zone %v", GCE.Instance, GCE.InternalIP, GCE.ProjectID, GCE.ZoneID)
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	initOnce.Do(initGCE)
	name := fmt.Sprintf("syzkaller-%v", cfg.Index)
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(cfg.Workdir)
		}
	}()

	// Create SSH key for the instance.
	sshkey := filepath.Join(cfg.Workdir, "key")
	keygen := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-C", "syzkaller", "-f", sshkey)
	if out, err := keygen.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to execute ssh-keygen: %v\n%s", err, out)
	}
	sshkeyPub, err := ioutil.ReadFile(sshkey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	Logf(0, "deleting instance: %v", name)
	if err := GCE.DeleteInstance(name); err != nil {
		return nil, err
	}
	Logf(0, "creating instance: %v", name)
	ip, err := GCE.CreateInstance(name, cfg.MachineType, cfg.Image, string(sshkeyPub))
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			GCE.DeleteInstance(name)
		}
	}()
	Logf(0, "wait instance to boot: %v (%v)", name, ip)
	if err := waitInstanceBoot(ip, cfg.Sshkey); err != nil {
		return nil, err
	}
	ok = true
	inst := &instance{
		cfg:    cfg,
		name:   name,
		ip:     ip,
		sshkey: sshkey,
		closed: make(chan bool),
	}
	return inst, nil
}

func (inst *instance) Close() {
	close(inst.closed)
	GCE.DeleteInstance(inst.name)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", GCE.InternalIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	args := append(sshArgs(inst.cfg.Sshkey, "-P", 22), hostSrc, "root@"+inst.name+":"+vmDst)
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
	conRpipe, conWpipe, err := vm.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	conAddr := fmt.Sprintf("%v.%v.%v.syzkaller.port=1@ssh-serialport.googleapis.com", GCE.ProjectID, GCE.ZoneID, inst.name)
	conArgs := append(sshArgs(inst.sshkey, "-p", 9600), conAddr)
	con := exec.Command("ssh", conArgs...)
	con.Env = []string{}
	con.Stdout = conWpipe
	con.Stderr = conWpipe
	if _, err := con.StdinPipe(); err != nil { // SSH would close connection on stdin EOF
		conRpipe.Close()
		conWpipe.Close()
		return nil, nil, err
	}
	if err := con.Start(); err != nil {
		conRpipe.Close()
		conWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to console server: %v", err)

	}
	conWpipe.Close()
	conDone := make(chan error, 1)
	go func() {
		err := con.Wait()
		conDone <- fmt.Errorf("console connection closed: %v", err)
	}()

	sshRpipe, sshWpipe, err := vm.LongPipe()
	if err != nil {
		con.Process.Kill()
		sshRpipe.Close()
		return nil, nil, err
	}
	args := append(sshArgs(inst.cfg.Sshkey, "-p", 22), "root@"+inst.name, command)
	ssh := exec.Command("ssh", args...)
	ssh.Stdout = sshWpipe
	ssh.Stderr = sshWpipe
	if err := ssh.Start(); err != nil {
		con.Process.Kill()
		conRpipe.Close()
		sshRpipe.Close()
		sshWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to instance: %v", err)
	}
	sshWpipe.Close()
	sshDone := make(chan error, 1)
	go func() {
		err := ssh.Wait()
		sshDone <- fmt.Errorf("ssh exited: %v", err)
	}()

	merger := vm.NewOutputMerger(nil)
	merger.Add(conRpipe)
	merger.Add(sshRpipe)

	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		select {
		case <-time.After(timeout):
			signal(vm.TimeoutErr)
			con.Process.Kill()
			ssh.Process.Kill()
		case <-inst.closed:
			signal(fmt.Errorf("instance closed"))
			con.Process.Kill()
			ssh.Process.Kill()
		case err := <-conDone:
			signal(err)
			ssh.Process.Kill()
		case err := <-sshDone:
			signal(err)
			con.Process.Kill()
		}
		merger.Wait()
	}()
	return merger.Output, errc, nil
}

func waitInstanceBoot(ip, sshkey string) error {
	for i := 0; i < 100; i++ {
		if !vm.SleepInterruptible(5 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		cmd := exec.Command("ssh", append(sshArgs(sshkey, "-p", 22), "root@"+ip, "pwd")...)
		if _, err := cmd.CombinedOutput(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("can't ssh into the instance")
}

func sshArgs(sshKey, portArg string, port int) []string {
	return []string{
		portArg, fmt.Sprint(port),
		"-i", sshKey,
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5",
	}
}
