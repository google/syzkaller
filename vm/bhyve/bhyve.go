// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bhyve

import (
	"context"
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
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("bhyve", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	Bridge  string `json:"bridge"`  // name of network bridge device, optional
	Count   int    `json:"count"`   // number of VMs to use
	CPU     int    `json:"cpu"`     // number of VM vCPU
	HostIP  string `json:"hostip"`  // VM host IP address
	Mem     string `json:"mem"`     // amount of VM memory
	Dataset string `json:"dataset"` // ZFS dataset containing VM image
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	vmimpl.SSHOptions
	cfg         *Config
	snapshot    string
	tapdev      string
	forwardPort int
	image       string
	debug       bool
	os          string
	merger      *vmimpl.OutputMerger
	vmName      string
	bhyve       *exec.Cmd
	consolew    io.WriteCloser
}

var ipRegex = regexp.MustCompile(`bound to (([0-9]+\.){3}[0-9]+) `)
var tapRegex = regexp.MustCompile(`^tap[0-9]+`)

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count: 1,
		CPU:   1,
		Mem:   "512M",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse bhyve vm config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1-128]", cfg.Count)
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

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		cfg:   pool.cfg,
		debug: pool.env.Debug,
		os:    pool.env.OS,
		SSHOptions: vmimpl.SSHOptions{
			Key:  pool.env.SSHKey,
			User: pool.env.SSHUser,
		},
		vmName: fmt.Sprintf("syzkaller-%v-%v", pool.env.Name, index),
	}

	dataset := inst.cfg.Dataset
	mountpoint, err := osutil.RunCmd(time.Minute, "", "zfs", "get", "-H", "-o", "value", "mountpoint", dataset)
	if err != nil {
		return nil, err
	}

	snapshot := fmt.Sprintf("%v@bhyve-%v", dataset, inst.vmName)
	clone := fmt.Sprintf("%v/bhyve-%v", dataset, inst.vmName)

	prefix := strings.TrimSuffix(string(mountpoint), "\n") + "/"
	image := strings.TrimPrefix(pool.env.Image, prefix)
	if image == pool.env.Image {
		return nil, fmt.Errorf("image file %v not contained in dataset %v", image, prefix)
	}
	inst.image = prefix + fmt.Sprintf("bhyve-%v", inst.vmName) + "/" + image

	// Stop the instance from a previous run in case it's still running.
	osutil.RunCmd(time.Minute, "", "bhyvectl", "--destroy", fmt.Sprintf("--vm=%v", inst.vmName))
	// Destroy a lingering snapshot and clone.
	osutil.RunCmd(time.Minute, "", "zfs", "destroy", "-R", snapshot)

	// Create a snapshot of the data set containing the VM image.
	// bhyve will use a clone of the snapshot, which gets recreated every time the VM
	// is restarted. This is all to work around bhyve's current lack of an
	// image snapshot facility.
	if _, err := osutil.RunCmd(time.Minute, "", "zfs", "snapshot", snapshot); err != nil {
		inst.Close()
		return nil, err
	}
	inst.snapshot = snapshot
	if _, err := osutil.RunCmd(time.Minute, "", "zfs", "clone", snapshot, clone); err != nil {
		inst.Close()
		return nil, err
	}

	if inst.cfg.Bridge != "" {
		tapdev, err := osutil.RunCmd(time.Minute, "", "ifconfig", "tap", "create")
		if err != nil {
			inst.Close()
			return nil, err
		}
		inst.tapdev = tapRegex.FindString(string(tapdev))
		if _, err := osutil.RunCmd(time.Minute, "", "ifconfig", inst.cfg.Bridge, "addm", inst.tapdev); err != nil {
			inst.Close()
			return nil, err
		}
	}

	if err := inst.Boot(); err != nil {
		inst.Close()
		return nil, err
	}

	return inst, nil
}

func (inst *instance) Boot() error {
	loaderArgs := []string{
		"-c", "stdio",
		"-m", inst.cfg.Mem,
		"-d", inst.image,
		"-e", "autoboot_delay=0",
		inst.vmName,
	}

	// Stop the instance from the previous run in case it's still running.
	osutil.RunCmd(time.Minute, "", "bhyvectl", "--destroy", fmt.Sprintf("--vm=%v", inst.vmName))

	_, err := osutil.RunCmd(time.Minute, "", "bhyveload", loaderArgs...)
	if err != nil {
		return err
	}

	netdev := ""
	if inst.tapdev != "" {
		inst.Port = 22
		netdev = inst.tapdev
	} else {
		inst.Port = vmimpl.UnusedTCPPort()
		netdev = fmt.Sprintf("slirp,hostfwd=tcp:127.0.0.1:%v-:22", inst.Port)
	}

	bhyveArgs := []string{
		"-H", "-A", "-P",
		"-c", fmt.Sprintf("%d", inst.cfg.CPU),
		"-m", inst.cfg.Mem,
		"-s", "0:0,hostbridge",
		"-s", "1:0,lpc",
		"-s", fmt.Sprintf("2:0,virtio-net,%v", netdev),
		"-s", fmt.Sprintf("3:0,virtio-blk,%v", inst.image),
		"-l", "com1,stdio",
		inst.vmName,
	}

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

	bhyve := osutil.Command("bhyve", bhyveArgs...)
	bhyve.Stdin = inr
	bhyve.Stdout = outw
	bhyve.Stderr = outw
	if err := bhyve.Start(); err != nil {
		outr.Close()
		outw.Close()
		inr.Close()
		inw.Close()
		return err
	}
	outw.Close()
	outw = nil
	inst.consolew = inw
	inr.Close()
	inst.bhyve = bhyve

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("console", vmimpl.OutputConsole, outr)
	outr = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	ipch := make(chan string, 1)
	go func() {
		gotip := false
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out.Data...)
			case <-bootOutputStop:
				close(bootOutputStop)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	select {
	case ip := <-ipch:
		if inst.tapdev != "" {
			inst.Addr = ip
		} else {
			inst.Addr = "localhost"
		}
	case <-inst.merger.Errors(ctx):
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.BootError{Title: "bhyve exited", Output: bootOutput}
	case <-time.After(10 * time.Minute):
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.BootError{Title: "no IP found", Output: bootOutput}
	}

	err = vmimpl.WaitForSSH(10*time.Minute, inst.SSHOptions, inst.os, nil, false, inst.debug)
	if err != nil {
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.MakeBootError(err, bootOutput)
	}
	bootOutputStop <- true
	return nil
}

func (inst *instance) Close() error {
	if inst.consolew != nil {
		inst.consolew.Close()
	}
	if inst.bhyve != nil {
		inst.bhyve.Process.Kill()
		inst.bhyve.Wait()
		osutil.RunCmd(time.Minute, "", "bhyvectl", fmt.Sprintf("--vm=%v", inst.vmName), "--destroy")
		inst.bhyve = nil
	}
	if inst.snapshot != "" {
		osutil.RunCmd(time.Minute, "", "zfs", "destroy", "-R", inst.snapshot)
		inst.snapshot = ""
	}
	if inst.tapdev != "" {
		osutil.RunCmd(time.Minute, "", "ifconfig", inst.tapdev, "destroy")
		inst.tapdev = ""
	}
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.tapdev != "" {
		return fmt.Sprintf("%v:%v", inst.cfg.HostIP, port), nil
	} else {
		if port == 0 {
			return "", fmt.Errorf("vm/bhyve: forward port is zero")
		}
		if inst.forwardPort != 0 {
			return "", fmt.Errorf("vm/bhyve: forward port is already set")
		}
		inst.forwardPort = port
		return fmt.Sprintf("localhost:%v", port), nil
	}
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/root", filepath.Base(hostSrc))
	args := append(vmimpl.SCPArgs(inst.debug, inst.Key, inst.Port, false),
		hostSrc, inst.User+"@"+inst.Addr+":"+vmDst)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}
	_, err := osutil.RunCmd(10*time.Minute, "", "scp", args...)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	rpipeErr, wpipeErr, err := osutil.LongPipe()
	if err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	inst.merger.Add("ssh", vmimpl.OutputStdout, rpipe)
	inst.merger.Add("ssh-err", vmimpl.OutputStderr, rpipeErr)

	var sshargs []string
	if inst.forwardPort != 0 {
		sshargs = vmimpl.SSHArgsForward(inst.debug, inst.Key, inst.Port, inst.forwardPort, false)
	} else {
		sshargs = vmimpl.SSHArgs(inst.debug, inst.Key, inst.Port, false)
	}
	args := append(sshargs, inst.User+"@"+inst.Addr, command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipeErr
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		wpipeErr.Close()
		return nil, nil, err
	}
	wpipe.Close()
	wpipeErr.Close()
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		errCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		select {
		case <-ctx.Done():
			signal(vmimpl.ErrTimeout)
		case err := <-inst.merger.Errors(errCtx):
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

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return vmimpl.DiagnoseFreeBSD(inst.consolew)
}

func parseIP(output []byte) string {
	matches := ipRegex.FindSubmatch(output)
	if len(matches) < 2 {
		return ""
	}
	return string(matches[1])
}
