// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vmm provides VMs based on OpenBSD vmm virtualization.
package vmm

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	env   *vmimpl.Env
	cfg   *Config
	count int
	mu    sync.Mutex
}

type instance struct {
	cfg     *Config
	image   string
	imageID int
	debug   bool
	workdir string
	sshkey  string
	sshuser string
	sshhost string
	port    int
	rpipe   io.ReadCloser
	wpipe   io.WriteCloser
	start   *exec.Cmd
	waiterC chan error
	merger  *vmimpl.OutputMerger
	vmID    int
}

type vmStatus struct {
	id     int
	pid    int
	cpu    int
	memMax int
	memCur int
	tty    string
	owner  string
	name   string
}

var idRegexp = regexp.MustCompile("started vm (\\d+)")

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
	imageID := pool.nextID()
	imagePath, err := copyImage(pool.env.Image, imageID)
	if err != nil {
		return nil, err
	}
	if pool.env.Debug {
		log.Logf(0, "using image: %s", imagePath)
	}

	inst := &instance{
		cfg:     pool.cfg,
		image:   imagePath,
		imageID: imageID,
		debug:   pool.env.Debug,
		workdir: workdir,
		sshkey:  pool.env.SSHKey,
		sshuser: pool.env.SSHUser,
		port:    22,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.Boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (pool *Pool) nextID() int {
	pool.mu.Lock()
	pool.count++
	id := pool.count
	pool.mu.Unlock()
	return id
}

func (inst *instance) Boot() error {
	name := fmt.Sprintf("syzkaller-%d", inst.imageID)
	mem := fmt.Sprintf("%dM", inst.cfg.Mem)
	startArgs := []string{
		"start", name,
		"-t", inst.cfg.Template,
		"-b", inst.cfg.Kernel,
		"-d", inst.image,
		"-m", mem,
	}
	startOut, err := inst.vmctl(startArgs...)
	if err != nil {
		return fmt.Errorf("start failed: %v: %s", err, string(startOut))
	}
	if inst.debug {
		log.Logf(0, "start output: %s", string(startOut))
	}

	inst.vmID, err = parseID(string(startOut))
	if err != nil {
		return err
	}
	inst.sshhost = fmt.Sprintf("100.64.%d.3", inst.vmID)

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("vmm", inst.rpipe)
	inst.rpipe = nil

	consoleStop := make(chan bool)
	if err := inst.console(consoleStop); err != nil {
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

	done := func() {
		consoleStop <- true
		<-consoleStop
		close(consoleStop)

		bootOutputStop <- true
		<-bootOutputStop
		close(bootOutputStop)
	}

	// Wait for ssh server to come up.
	time.Sleep(5 * time.Second)
	start := time.Now()
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", inst.sshhost, inst.port), 1*time.Second)
		if err == nil {
			c.SetDeadline(time.Now().Add(1 * time.Second))
			var tmp [1]byte
			n, err := c.Read(tmp[:])
			c.Close()
			if err == nil && n > 0 {
				break // ssh is up and responding
			}
			time.Sleep(3 * time.Second)
		}
		if time.Since(start) > 2*time.Minute {
			done()
			inst.merger.Wait()
			return vmimpl.BootError{Title: "ssh server did not start", Output: bootOutput}
		}
	}
	done()

	return nil
}

func (inst *instance) Close() {
	if out, err := inst.vmctl("stop", inst.vmIdent(), "-f"); err != nil {
		if inst.debug {
			log.Logf(0, "vmctl stop: %v: %s", err, string(out))
		}
	}

	os.Remove(inst.image)
}

func (inst *instance) Forward(port int) (string, error) {
	addr := fmt.Sprintf("100.64.%v.2:%v", inst.vmID, port)
	if inst.debug {
		log.Logf(0, "forward %v", addr)
	}
	return addr, nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/root", filepath.Base(hostSrc))
	args := append(inst.sshArgs("-P"), hostSrc, inst.sshuser+"@"+inst.sshhost+":"+vmDst)
	cmd := osutil.Command("scp", args...)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(3 * time.Minute):
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

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)

	args := append(inst.sshArgs("-p"), inst.sshuser+"@"+inst.sshhost, command)
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

	consoleStop := make(chan bool)
	if err := inst.console(consoleStop); err != nil {
		return nil, nil, err
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

			consoleStop <- true
			<-consoleStop
			close(consoleStop)

			signal(err)
			return
		}
		cmd.Process.Kill()
		cmd.Wait()

		consoleStop <- true
		<-consoleStop
		close(consoleStop)
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Diagnose() bool {
	return false
}

func (inst *instance) console(stop chan bool) error {
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
		return fmt.Errorf("vmctl console: %v", err)
	}
	outw.Close()
	inr.Close()
	inst.merger.Add("console", outr)
	go func() {
		<-stop
		cmd.Process.Kill()
		cmd.Process.Wait()
		inw.Close()
		outr.Close()
		select {
		case <-inst.merger.Err:
			// Error is expected since the process is gone.
		}
		stop <- true
	}()
	return nil
}

func (inst *instance) sshArgs(portArg string) []string {
	args := []string{
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
	if inst.sshkey != "" {
		args = append(args, "-i", inst.sshkey)
	}
	if inst.debug {
		args = append(args, "-v")
	}
	return args
}

// Run the given vmctl(8) command and wait for it to finish.
func (inst *instance) vmctl(args ...string) ([]byte, error) {
	if inst.debug {
		log.Logf(0, "running command: vmctl %#v", args)
	}
	cmd := osutil.Command("vmctl", args...)
	return cmd.CombinedOutput()
}

func (inst *instance) vmIdent() string {
	return strconv.Itoa(inst.vmID)
}

// Copy the disk image since every VM needs its own disk.
// Something similar to the snapshot feature in QEMU is not supported.
func copyImage(src string, id int) (string, error) {
	dirname := filepath.Dir(src)
	basename := filepath.Base(src)
	dst := fmt.Sprintf("%s/%s.%d", dirname, basename, id)
	os.Remove(dst)
	cmd := osutil.Command("cp", src, dst)
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return dst, nil
}

// Extract VM ID from vmctl start output.
func parseID(str string) (int, error) {
	prefix := "vmctl: started vm "
	if !strings.HasPrefix(str, prefix) {
		return 0, fmt.Errorf("could not extract ID from: %s", str)
	}
	fields := strings.Fields(str)
	i, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, err
	}
	if i <= 0 {
		return 0, fmt.Errorf("invalid ID: %d", i)
	}
	return i, nil
}
