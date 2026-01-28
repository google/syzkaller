// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmware

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("vmware", vmimpl.Type{
		Ctor: ctor,
	})
}

type Config struct {
	BaseVMX string `json:"base_vmx"` // location of the base vmx
	Count   int    `json:"count"`    // number of VMs to run in parallel
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg         *Config
	baseVMX     string
	vmx         string
	ipAddr      string
	closed      chan bool
	debug       bool
	sshuser     string
	sshkey      string
	forwardPort int
	timeouts    targets.Timeouts
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if cfg.BaseVMX == "" {
		return nil, fmt.Errorf("config param base_vmx is empty")
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if _, err := exec.LookPath("vmrun"); err != nil {
		return nil, fmt.Errorf("cannot find vmrun")
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
	createTime := strconv.FormatInt(time.Now().UnixNano(), 10)
	vmx := filepath.Join(workdir, createTime, "syzkaller.vmx")
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser
	inst := &instance{
		cfg:      pool.cfg,
		debug:    pool.env.Debug,
		baseVMX:  pool.cfg.BaseVMX,
		vmx:      vmx,
		sshkey:   sshkey,
		sshuser:  sshuser,
		closed:   make(chan bool),
		timeouts: pool.env.Timeouts,
	}
	if err := inst.clone(); err != nil {
		return nil, err
	}
	if err := inst.boot(); err != nil {
		return nil, err
	}
	return inst, nil
}

func (inst *instance) clone() error {
	if inst.debug {
		log.Logf(0, "cloning %v to %v", inst.baseVMX, inst.vmx)
	}
	if _, err := osutil.RunCmd(2*time.Minute, "", "vmrun", "clone", inst.baseVMX, inst.vmx, "full"); err != nil {
		return err
	}
	return nil
}

func (inst *instance) boot() error {
	if inst.debug {
		log.Logf(0, "starting %v", inst.vmx)
	}
	if _, err := osutil.RunCmd(5*time.Minute, "", "vmrun", "start", inst.vmx, "nogui"); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, "getting IP of %v", inst.vmx)
	}
	ip, err := osutil.RunCmd(5*time.Minute, "", "vmrun", "getGuestIPAddress", inst.vmx, "-wait")
	if err != nil {
		return err
	}
	inst.ipAddr = strings.TrimSuffix(string(ip), "\n")
	if inst.debug {
		log.Logf(0, "VM %v has IP: %v", inst.vmx, inst.ipAddr)
	}
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("isolated: Forward port already set")
	}
	if port == 0 {
		return "", fmt.Errorf("isolated: Forward port is zero")
	}
	inst.forwardPort = port
	return fmt.Sprintf("127.0.0.1:%v", port), nil
}

func (inst *instance) Close() error {
	if inst.debug {
		log.Logf(0, "stopping %v", inst.vmx)
	}
	osutil.RunCmd(2*time.Minute, "", "vmrun", "stop", inst.vmx, "hard")
	if inst.debug {
		log.Logf(0, "deleting %v", inst.vmx)
	}
	osutil.RunCmd(2*time.Minute, "", "vmrun", "deleteVM", inst.vmx)
	close(inst.closed)
	return nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join("/", base)

	args := append(vmimpl.SCPArgs(inst.debug, inst.sshkey, 22, false),
		hostSrc, fmt.Sprintf("%v@%v:%v", inst.sshuser, inst.ipAddr, vmDst))

	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}

	_, err := osutil.RunCmd(3*time.Minute, "", "scp", args...)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	vmxDir := filepath.Dir(inst.vmx)
	serial := filepath.Join(vmxDir, "serial")
	dmesg, err := net.Dial("unix", serial)
	if err != nil {
		return nil, nil, err
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		dmesg.Close()
		return nil, nil, err
	}

	args := vmimpl.SSHArgs(inst.debug, inst.sshkey, 22, false)
	// Forward target port as part of the ssh connection (reverse proxy)
	if inst.forwardPort != 0 {
		proxy := fmt.Sprintf("%v:127.0.0.1:%v", inst.forwardPort, inst.forwardPort)
		args = append(args, "-R", proxy)
	}
	args = append(args, inst.sshuser+"@"+inst.ipAddr, "cd / && exec "+command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		dmesg.Close()
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("dmesg", vmimpl.OutputConsole, dmesg)
	merger.Add("ssh", vmimpl.OutputCommand, rpipe)

	return vmimpl.Multiplex(ctx, cmd, merger, vmimpl.MultiplexConfig{
		Console: dmesg,
		Close:   inst.closed,
		Debug:   inst.debug,
		Scale:   inst.timeouts.Scale,
	})
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
