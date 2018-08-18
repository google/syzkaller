// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vmm provides VMs based on OpenBSD vmm virtualization.
package vmm

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("vmm", ctor)
}

type Config struct {
	Count    int    `json:"count"`    // number of VMs to use
	CPU      int    `json:"cpu"`      // number of VM CPUs
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
	index    int
	image    string
	debug    bool
	os       string
	workdir  string
	sshkey   string
	sshuser  string
	sshhost  string
	sshport  int
	merger   *vmimpl.OutputMerger
	vmID     int
	stop     chan bool
	diagnose chan string
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count: 1,
		CPU:   1,
		Mem:   512,
	}

	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
	}

	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vmm vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 8 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1-8]", cfg.Count)
	}
	if env.Debug {
		cfg.Count = 1
	}
	if cfg.CPU > 1 {
		return nil, fmt.Errorf("invalid config param cpu: %v, want 1", cfg.CPU)
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
	if cfg.Template == "" {
		return nil, fmt.Errorf("missing config param template")
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
	image := filepath.Join(workdir, "disk.img")
	if err := osutil.CopyFile(pool.env.Image, image); err != nil {
		return nil, err
	}

	inst := &instance{
		cfg:      pool.cfg,
		index:    index,
		image:    image,
		debug:    pool.env.Debug,
		os:       pool.env.OS,
		workdir:  workdir,
		sshkey:   pool.env.SSHKey,
		sshuser:  pool.env.SSHUser,
		sshport:  22,
		stop:     make(chan bool),
		diagnose: make(chan string),
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := inst.Boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) Boot() error {
	name := fmt.Sprintf("syzkaller-%v", inst.index)
	mem := fmt.Sprintf("%vM", inst.cfg.Mem)
	startArgs := []string{
		"start", name,
		"-t", inst.cfg.Template,
		"-b", inst.cfg.Kernel,
		"-d", inst.image,
		"-m", mem,
	}
	startOut, err := inst.vmctl(startArgs...)
	if err != nil {
		return err
	}

	inst.vmID, err = parseID(startOut)
	if err != nil {
		return err
	}
	inst.sshhost = fmt.Sprintf("100.64.%v.3", inst.vmID)

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)

	if err := inst.console(); err != nil {
		return err
	}

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				bootOutputStop <- true
				return
			}
		}
	}()

	if err := vmimpl.WaitForSSH(inst.debug, 2*time.Minute, inst.sshhost,
		inst.sshkey, inst.sshuser, inst.os, inst.sshport); err != nil {
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.BootError{Title: err.Error(), Output: bootOutput}
	}
	bootOutputStop <- true
	return nil
}

func (inst *instance) Close() {
	inst.vmctl("stop", inst.vmIdent(), "-f")
}

func (inst *instance) Forward(port int) (string, error) {
	addr := fmt.Sprintf("100.64.%v.2:%v", inst.vmID, port)
	return addr, nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/root", filepath.Base(hostSrc))
	args := append(vmimpl.SCPArgs(inst.debug, inst.sshkey, inst.sshport),
		hostSrc, inst.sshuser+"@"+inst.sshhost+":"+vmDst)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}
	_, err := osutil.RunCmd(3*time.Minute, "", "scp", args...)
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
			inst.stop <- true
			inst.merger.Wait()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}

			signal(err)
			return
		}
		cmd.Process.Kill()
		inst.stop <- true
		inst.merger.Wait()
		cmd.Wait()
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Diagnose() bool {
	commands := []string{"", "trace", "show registers"}
	for _, c := range commands {
		select {
		case inst.diagnose <- c:
		case <-time.After(2 * time.Second):
		}
	}
	return true
}

func (inst *instance) console() error {
	outr, outw, err := osutil.LongPipe()
	if err != nil {
		return err
	}
	inr, inw, err := osutil.LongPipe()
	if err != nil {
		return err
	}

	cmd := osutil.Command("vmctl", "console", inst.vmIdent())
	cmd.Stdin = inr
	cmd.Stdout = outw
	cmd.Stderr = outw
	if err := cmd.Start(); err != nil {
		return err
	}
	outw.Close()
	inr.Close()
	inst.merger.Add("console", outr)

	go func() {
		stopDiagnose := make(chan bool)
		go func() {
			for {
				select {
				case s := <-inst.diagnose:
					inw.Write([]byte(s + "\n"))
					time.Sleep(1 * time.Second)
				case <-stopDiagnose:
					return
				}
			}
		}()

		stopProcess := make(chan bool)
		go func() {
			select {
			case <-inst.stop:
				cmd.Process.Kill()
			case <-stopProcess:
			}
		}()

		_, err = cmd.Process.Wait()
		inw.Close()
		outr.Close()
		stopDiagnose <- true
		stopProcess <- true
	}()

	return nil
}

// Run the given vmctl(8) command and wait for it to finish.
func (inst *instance) vmctl(args ...string) (string, error) {
	if inst.debug {
		log.Logf(0, "running command: vmctl %#v", args)
	}
	out, err := osutil.RunCmd(10*time.Second, "", "vmctl", args...)
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

func (inst *instance) vmIdent() string {
	return strconv.Itoa(inst.vmID)
}

// Extract VM ID from vmctl start output.
func parseID(str string) (int, error) {
	const prefix = "vmctl: started vm "
	if !strings.HasPrefix(str, prefix) {
		return 0, fmt.Errorf("could not extract ID from: %v", str)
	}
	fields := strings.Fields(str)
	if len(fields) < 4 {
		return 0, fmt.Errorf("could not extract ID from: %v", str)
	}
	i, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, err
	}
	if i <= 0 {
		return 0, fmt.Errorf("invalid ID: %v", i)
	}
	return i, nil
}
