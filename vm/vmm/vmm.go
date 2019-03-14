// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vmm provides VMs based on OpenBSD vmm virtualization.
package vmm

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("vmm", ctor, true)
}

type Config struct {
	Count    int    `json:"count"`    // number of VMs to use
	Mem      int    `json:"mem"`      // amount of VM memory in MBs
	Kernel   string `json:"kernel"`   // kernel to boot
	Template string `json:"template"` // vm template
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg      *Config
	image    string
	debug    bool
	os       string
	sshkey   string
	sshuser  string
	sshhost  string
	sshport  int
	merger   *vmimpl.OutputMerger
	vmName   string
	vmm      *exec.Cmd
	consolew io.WriteCloser
}

var ipRegex = regexp.MustCompile(`bound to (([0-9]+\.){3}3)`)

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count: 1,
		Mem:   512,
	}

	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
	}

	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vmm vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1-128]", cfg.Count)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("invalid config param mem: %v, want [128-1048576]", cfg.Mem)
	}
	if cfg.Kernel == "" {
		return nil, fmt.Errorf("missing config param kernel")
	}
	if !osutil.IsExist(cfg.Kernel) {
		return nil, fmt.Errorf("kernel '%v' does not exist", cfg.Kernel)
	}
	pool := &Pool{
		cfg: cfg,
		env: env,
	}

	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	var tee io.Writer
	if pool.env.Debug {
		tee = os.Stdout
	}
	inst := &instance{
		cfg:     pool.cfg,
		image:   filepath.Join(workdir, "disk.qcow2"),
		debug:   pool.env.Debug,
		os:      pool.env.OS,
		sshkey:  pool.env.SSHKey,
		sshuser: pool.env.SSHUser,
		sshport: 22,
		vmName:  fmt.Sprintf("%v-%v", pool.env.Name, index),
		merger:  vmimpl.NewOutputMerger(tee),
	}

	// Stop the instance from the previous run in case it's still running.
	// This is racy even with -w flag, start periodically fails with:
	// vmctl: start vm command failed: Operation already in progress
	// So also sleep for a bit.
	inst.vmctl("stop", inst.vmName, "-f", "-w")
	time.Sleep(3 * time.Second)

	createArgs := []string{
		"create", inst.image,
		"-b", pool.env.Image,
	}
	if _, err := inst.vmctl(createArgs...); err != nil {
		return nil, err
	}

	if err := inst.Boot(); err != nil {
		// Cleans up if Boot fails.
		inst.Close()
		return nil, err
	}

	return inst, nil
}

func (inst *instance) Boot() error {
	outr, outw, err := osutil.LongPipe()
	if err != nil {
		return err
	}
	inr, inw, err := osutil.LongPipe()
	if err != nil {
		outr.Close()
		outw.Close()
		return err
	}
	startArgs := []string{
		"start", inst.vmName,
		"-b", inst.cfg.Kernel,
		"-d", inst.image,
		"-m", fmt.Sprintf("%vM", inst.cfg.Mem),
		"-L", // add a local network interface
		"-c", // connect to the console
	}
	if inst.cfg.Template != "" {
		startArgs = append(startArgs, "-t", inst.cfg.Template)
	}
	if inst.debug {
		log.Logf(0, "running command: vmctl %#v", startArgs)
	}
	cmd := osutil.Command("vmctl", startArgs...)
	cmd.Stdin = inr
	cmd.Stdout = outw
	cmd.Stderr = outw
	if err := cmd.Start(); err != nil {
		outr.Close()
		outw.Close()
		inr.Close()
		inw.Close()
		return err
	}
	inst.vmm = cmd
	inst.consolew = inw
	outw.Close()
	inr.Close()
	inst.merger.Add("console", outr)

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	ipch := make(chan string, 1)
	go func() {
		gotip := false
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				bootOutputStop <- true
				return
			}
			if gotip {
				continue
			}
			if ip := parseIP(bootOutput); ip != "" {
				ipch <- ip
				gotip = true
			}
		}
	}()

	select {
	case ip := <-ipch:
		inst.sshhost = ip
	case <-inst.merger.Err:
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.BootError{Title: "vmm exited", Output: bootOutput}
	case <-time.After(10 * time.Minute):
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.BootError{Title: "no IP found", Output: bootOutput}
	}

	if err := vmimpl.WaitForSSH(inst.debug, 20*time.Minute, inst.sshhost,
		inst.sshkey, inst.sshuser, inst.os, inst.sshport, nil); err != nil {
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.BootError{Title: err.Error(), Output: bootOutput}
	}
	bootOutputStop <- true
	<-bootOutputStop
	return nil
}

func (inst *instance) Close() {
	inst.vmctl("stop", inst.vmName, "-f")
	if inst.consolew != nil {
		inst.consolew.Close()
	}
	if inst.vmm != nil {
		inst.vmm.Process.Kill()
		inst.vmm.Wait()
	}
	inst.merger.Wait()
}

func (inst *instance) Forward(port int) (string, error) {
	octets := strings.Split(inst.sshhost, ".")
	if len(octets) < 3 {
		return "", fmt.Errorf("too few octets in hostname %v", inst.sshhost)
	}
	addr := fmt.Sprintf("%v.%v.%v.2:%v", octets[0], octets[1], octets[2], port)
	return addr, nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/root", filepath.Base(hostSrc))
	args := append(vmimpl.SCPArgs(inst.debug, inst.sshkey, inst.sshport),
		hostSrc, inst.sshuser+"@"+inst.sshhost+":"+vmDst)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}
	_, err := osutil.RunCmd(10*time.Minute, "", "scp", args...)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)

	args := append(vmimpl.SSHArgs(inst.debug, inst.sshkey, inst.sshport),
		inst.sshuser+"@"+inst.sshhost, command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
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

	go func() {
		select {
		case <-time.After(timeout):
			signal(vmimpl.ErrTimeout)
		case <-stop:
			signal(vmimpl.ErrTimeout)
		case err := <-inst.merger.Err:
			cmd.Process.Kill()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		cmd.Wait()
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Diagnose() ([]byte, bool) {
	return nil, vmimpl.DiagnoseOpenBSD(inst.consolew)
}

// Run the given vmctl(8) command and wait for it to finish.
func (inst *instance) vmctl(args ...string) (string, error) {
	if inst.debug {
		log.Logf(0, "running command: vmctl %#v", args)
	}
	out, err := osutil.RunCmd(time.Minute, "", "vmctl", args...)
	if err != nil {
		if inst.debug {
			log.Logf(0, "vmctl failed: %v", err)
		}
		return "", err
	}
	if inst.debug {
		log.Logf(0, "vmctl output: %v", string(out))
	}
	return string(out), nil
}

func parseIP(output []byte) string {
	matches := ipRegex.FindSubmatch(output)
	if len(matches) < 2 {
		return ""
	}
	return string(matches[1])
}
