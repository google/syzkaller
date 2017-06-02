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
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gce"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("gce", ctor)
}

type Config struct {
	Count        int    // number of VMs to use
	Machine_Type string // GCE machine type (e.g. "n1-highcpu-2")
	Sshkey       string // root ssh key for the image
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
	GCE *gce.Context
}

type instance struct {
	cfg     *Config
	GCE     *gce.Context
	name    string
	ip      string
	offset  int64
	gceKey  string // per-instance private ssh key associated with the instance
	sshKey  string // ssh key
	sshUser string
	workdir string
	closed  chan bool
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	if env.Name == "" {
		return nil, fmt.Errorf("config param name is empty (required for GCE)")
	}
	cfg := &Config{
		Count: 1,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if cfg.Count < 1 || cfg.Count > 1000 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 1000]", cfg.Count)
	}
	if env.Debug {
		cfg.Count = 1
	}
	if cfg.Machine_Type == "" {
		return nil, fmt.Errorf("machine_type parameter is empty")
	}
	cfg.Sshkey = osutil.Abs(cfg.Sshkey)

	GCE, err := gce.NewContext()
	if err != nil {
		return nil, fmt.Errorf("failed to init gce: %v", err)
	}
	Logf(0, "gce initialized: running on %v, internal IP %v, project %v, zone %v",
		GCE.Instance, GCE.InternalIP, GCE.ProjectID, GCE.ZoneID)
	pool := &Pool{
		cfg: cfg,
		env: env,
		GCE: GCE,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	name := fmt.Sprintf("%v-%v", pool.env.Name, index)
	// Create SSH key for the instance.
	gceKey := filepath.Join(workdir, "key")
	keygen := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-C", "syzkaller", "-f", gceKey)
	if out, err := keygen.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to execute ssh-keygen: %v\n%s", err, out)
	}
	gceKeyPub, err := ioutil.ReadFile(gceKey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	Logf(0, "deleting instance: %v", name)
	if err := pool.GCE.DeleteInstance(name, true); err != nil {
		return nil, err
	}
	Logf(0, "creating instance: %v", name)
	ip, err := pool.GCE.CreateInstance(name, pool.cfg.Machine_Type, pool.env.Image, string(gceKeyPub))
	if err != nil {
		return nil, err
	}

	ok := false
	defer func() {
		if !ok {
			pool.GCE.DeleteInstance(name, true)
		}
	}()
	sshKey := pool.cfg.Sshkey
	sshUser := "root"
	if sshKey == "" {
		// Assuming image supports GCE ssh fanciness.
		sshKey = gceKey
		sshUser = "syzkaller"
	}
	Logf(0, "wait instance to boot: %v (%v)", name, ip)
	if err := waitInstanceBoot(ip, sshKey, sshUser); err != nil {
		return nil, err
	}
	ok = true
	inst := &instance{
		cfg:     pool.cfg,
		GCE:     pool.GCE,
		name:    name,
		ip:      ip,
		gceKey:  gceKey,
		sshKey:  sshKey,
		sshUser: sshUser,
		closed:  make(chan bool),
	}
	return inst, nil
}

func (inst *instance) Close() {
	close(inst.closed)
	inst.GCE.DeleteInstance(inst.name, false)
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", inst.GCE.InternalIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := "./" + filepath.Base(hostSrc)
	args := append(sshArgs(inst.sshKey, "-P", 22), hostSrc, inst.sshUser+"@"+inst.name+":"+vmDst)
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

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	conRpipe, conWpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	conAddr := fmt.Sprintf("%v.%v.%v.syzkaller.port=1@ssh-serialport.googleapis.com",
		inst.GCE.ProjectID, inst.GCE.ZoneID, inst.name)
	conArgs := append(sshArgs(inst.gceKey, "-p", 9600), conAddr)
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

	sshRpipe, sshWpipe, err := osutil.LongPipe()
	if err != nil {
		con.Process.Kill()
		sshRpipe.Close()
		return nil, nil, err
	}
	if inst.sshUser != "root" {
		command = fmt.Sprintf("sudo bash -c '%v'", command)
	}
	args := append(sshArgs(inst.sshKey, "-p", 22), inst.sshUser+"@"+inst.name, command)
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

	merger := vmimpl.NewOutputMerger(nil)
	merger.Add("console", conRpipe)
	merger.Add("ssh", sshRpipe)

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
			signal(vmimpl.TimeoutErr)
		case <-stop:
			signal(vmimpl.TimeoutErr)
		case <-inst.closed:
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			con.Process.Kill()
			ssh.Process.Kill()
			merger.Wait()
			con.Wait()
			if cmdErr := ssh.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			} else {
				// Check if the instance was terminated due to preemption or host maintenance.
				time.Sleep(5 * time.Second) // just to avoid any GCE races
				if !inst.GCE.IsInstanceRunning(inst.name) {
					Logf(1, "%v: ssh exited but instance is not running", inst.name)
					err = vmimpl.TimeoutErr
				}
			}
			signal(err)
			return
		}
		con.Process.Kill()
		ssh.Process.Kill()
		merger.Wait()
		con.Wait()
		ssh.Wait()
	}()
	return merger.Output, errc, nil
}

func waitInstanceBoot(ip, sshKey, sshUser string) error {
	for i := 0; i < 100; i++ {
		if !vmimpl.SleepInterruptible(5 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		cmd := exec.Command("ssh", append(sshArgs(sshKey, "-p", 22), sshUser+"@"+ip, "pwd")...)
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
