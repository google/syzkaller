// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"strings"
	"regexp"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("vbox", ctor, false)
}

type Config struct {
	BaseVM  string `json:"base_vm"`  // name of the base vm
	Serial  string `json:"serial"`   // name of the base serial location (linux: /tmp or windows: \\.\pipe\)
	Count   int    `json:"count"`    // number of VMs to run in parallel
	Options string `json:"options"`  // any additional options (like --options=Link for faster cloning)
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg         *Config
	baseVM      string
	vmname      string
	ipAddr      string
	serialname  string
	closed      chan bool
	debug       bool
	sshuser     string
	sshkey      string
	forwardPort int
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if cfg.BaseVM == "" {
		return nil, fmt.Errorf("config param base_vm is empty")
	}
	if cfg.Serial == "" {
		return nil, fmt.Errorf("config param Serial is empty")
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if _, err := exec.LookPath("VBoxManage"); err != nil {
		return nil, fmt.Errorf("cannot find VBoxManage")
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
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
	createTime := strconv.FormatInt(time.Now().UnixNano(), 10)
	vmname := "syzk-" + createTime
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser
	inst := &instance{
		cfg:     pool.cfg,
		debug:   pool.env.Debug,
		baseVM:  pool.cfg.BaseVM,
		vmname:  vmname,
		serialname: vmname,
		sshkey:  sshkey,
		sshuser: sshuser,
		closed:  make(chan bool),
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
		log.Logf(0, "cloning %v to %v", inst.baseVM, inst.vmname)
	}
	if _, err := osutil.RunCmd(5*time.Minute, "", "VBoxManage", "clonevm", inst.baseVM, "--name="+inst.vmname, "--register","--mode=all",inst.cfg.Options); err != nil {
		return err
	}
	serialPrefix := filepath.Dir(inst.cfg.Serial)
	serial := filepath.Join(serialPrefix, inst.serialname)
	if inst.debug {
		log.Logf(0, "setting serial %v to %v", inst.vmname, inst.serialname)
	}
	if _, err := osutil.RunCmd(5*time.Minute, "", "VBoxManage", "modifyvm", inst.vmname, "--uartmode1", "server", serial ); err != nil {
		return err
	}
	return nil
}

func (inst *instance) boot() error {
	if inst.debug {
		log.Logf(0, "starting %v", inst.vmname)
	}
	if _, err := osutil.RunCmd(5*time.Minute, "", "VBoxManage", "startvm", inst.vmname, "--type=headless"); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, "getting IP of %v", inst.vmname)
	}
	ip, err := osutil.RunCmd(5*time.Minute, "", "VBoxManage", "guestproperty", "wait", inst.vmname, "VirtualBox/GuestInfo/Net/0/V4/IP","--timeout 300000") // in msec = 1000 * 5 * 60
	if err != nil {
		return err
	}
	if strings.Contains(string(ip), "VBoxManage: error") {
		log.Logf(0, "Error waiting for VM %v to output IP", inst.vmname)
		return fmt.Errorf("Error waiting for VM to output IP")
	}
	re := regexp.MustCompile(`((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}`)
	match := re.FindStringSubmatch(string(ip))
	inst.ipAddr = match[1]
	if inst.debug {
		log.Logf(0, "VM %v has IP: %v", inst.vmname, inst.ipAddr)
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

func (inst *instance) Close() {
	if inst.debug {
		log.Logf(0, "stopping %v", inst.vmname)
	}
	osutil.RunCmd(5*time.Minute, "", "VBoxManage", "controlvm", inst.vmname, "poweroff")
	if inst.debug {
		log.Logf(0, "deleting %v", inst.vmname)
	}
	osutil.RunCmd(5*time.Minute, "", "VBoxManage", "unregistervm", inst.vmname, "--delete")
	close(inst.closed)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join("/", base)

	args := append(vmimpl.SCPArgs(inst.debug, inst.sshkey, 22),
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

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	serialPrefix := filepath.Dir(inst.cfg.Serial)
	serial := filepath.Join(serialPrefix, inst.serialname)
	dmesg, err := net.Dial("unix", serial)
	if err != nil {
		return nil, nil, err
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		dmesg.Close()
		return nil, nil, err
	}

	args := vmimpl.SSHArgs(inst.debug, inst.sshkey, 22)
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
	merger.Add("dmesg", dmesg)
	merger.Add("ssh", rpipe)

	return vmimpl.Multiplex(cmd, merger, dmesg, timeout, stop, inst.closed, inst.debug)
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
