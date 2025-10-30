// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package virtualbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("virtualbox", vmimpl.Type{Ctor: ctor})
}

type Config struct {
	BaseVM string `json:"vm_name"` // name of the base VM
	Count  int    `json:"count"`   // number of VMs to run in parallel
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg        *Config
	debug      bool
	baseVM     string
	vmName     string
	sshPort    int
	rpcPort    int
	sshuser    string
	sshkey     string
	timeouts   targets.Timeouts
	serialPath string
	scriptPath string
	closed     chan bool
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if cfg.BaseVM == "" {
		return nil, fmt.Errorf("config param base_vm is empty")
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1,128]", cfg.Count)
	}
	if _, err := exec.LookPath("VBoxManage"); err != nil {
		return nil, fmt.Errorf("cannot find VBoxManage")
	}
	return &Pool{cfg: cfg, env: env}, nil
}

func (pool *Pool) Count() int { return pool.cfg.Count }

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	baseDir := filepath.Dir(filepath.Dir(workdir))
	scriptPath := filepath.Join(baseDir, "tools", "virtualbox-helper.sh")
	serialPath := filepath.Join(workdir, timestamp, "serial")
	vmName := fmt.Sprintf("syzkaller_%s", timestamp)
	inst := &instance{
		cfg:        pool.cfg,
		debug:      pool.env.Debug,
		baseVM:     pool.cfg.BaseVM,
		vmName:     vmName,
		sshuser:    pool.env.SSHUser,
		sshkey:     pool.env.SSHKey,
		timeouts:   pool.env.Timeouts,
		serialPath: serialPath,
		scriptPath: scriptPath,
		closed:     make(chan bool),
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
		log.Logf(0, "cloning VM %q to %q", inst.baseVM, inst.vmName)
	}
	if _, err := osutil.RunCmd(2*time.Minute, "", "VBoxManage", "clonevm", inst.baseVM,
		"--name", inst.vmName, "--register"); err != nil {
		if inst.debug {
			log.Logf(0, "clone failed for VM %q -> %q: %v", inst.baseVM, inst.vmName, err)
		}
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if inst.debug {
			log.Logf(0, "failed to listen on 127.0.0.1:0: %v", err)
		}
		return err
	}
	inst.sshPort = ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	rule := fmt.Sprintf("syzkaller_pf_%d", inst.sshPort)
	natArg := fmt.Sprintf("%s,tcp,,%d,,22", rule, inst.sshPort)
	if inst.debug {
		log.Logf(0, "setting NAT rule %q", natArg)
	}
	if _, err := osutil.RunCmd(2*time.Minute, "", "VBoxManage",
		"modifyvm", inst.vmName, "--natpf1", natArg); err != nil {
		if inst.debug {
			log.Logf(0, "VBoxManage modifyvm --natpf1 failed: %v", err)
		}
		return err
	}
	if inst.debug {
		log.Logf(0, "SSH NAT forwarding: host 127.0.0.1:%d -> guest:22", inst.sshPort)
	}

	serialDir := filepath.Dir(inst.serialPath)
	if inst.debug {
		log.Logf(0, "ensuring serial parent directory exists: %s", serialDir)
	}
	if err := os.MkdirAll(serialDir, 0755); err != nil {
		return fmt.Errorf("failed to create serial directory %s: %w", serialDir, err)
	}
	if inst.debug {
		log.Logf(0, "enabling UART on VM %q (0x3F8/IRQ4) and piping to %s", inst.vmName, inst.serialPath)
	}
	if _, err := osutil.RunCmd(2*time.Minute, "", "VBoxManage",
		"modifyvm", inst.vmName, "--uart1", "0x3F8", "4"); err != nil {
		if inst.debug {
			log.Logf(0, "VBoxManage modifyvm --uart1 failed: %v", err)
		}
		return err
	}
	if _, err := osutil.RunCmd(2*time.Minute, "", "VBoxManage",
		"modifyvm", inst.vmName, "--uart-mode1", "server", inst.serialPath); err != nil {
		if inst.debug {
			log.Logf(0, "VBoxManage modifyvm --uart-mode1 failed: %v", err)
		}
		return err
	}

	return nil
}

func (inst *instance) boot() error {
	if inst.debug {
		log.Logf(0, "booting VM %q (headless)", inst.vmName)
	}
	if _, err := osutil.RunCmd(2*time.Minute, "", "VBoxManage",
		"startvm", inst.vmName, "--type", "headless"); err != nil {
		if inst.debug {
			log.Logf(0, "VBoxManage startvm failed: %v", err)
		}
		return err
	}

	time.Sleep(10 * time.Second)

	_, err := osutil.RunCmd(2*time.Minute, "", "bash", inst.scriptPath, inst.serialPath)
	if err != nil {
		log.Logf(0, "vbox_connect_serial script failed")
		return err
	}
	if inst.debug {
		log.Logf(0, "vbox_connect_serial script succeeded")
	}

	time.Sleep(10 * time.Second)
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.rpcPort != 0 {
		return "", fmt.Errorf("isolated: Forward port already set")
	}
	if port == 0 {
		return "", fmt.Errorf("isolated: Forward port is zero")
	}
	inst.rpcPort = port
	return fmt.Sprintf("127.0.0.1:%d", port), nil
}

func (inst *instance) Close() error {
	if inst.debug {
		log.Logf(0, "stopping %v", inst.vmName)
	}
	osutil.RunCmd(2*time.Minute, "", "VBoxManage", "controlvm", inst.vmName, "poweroff")
	if inst.debug {
		log.Logf(0, "deleting %v", inst.vmName)
	}
	osutil.RunCmd(2*time.Minute, "", "VBoxManage", "unregistervm", inst.vmName, "--delete")
	close(inst.closed)
	return nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDest := "/" + base

	args := vmimpl.SCPArgs(inst.debug, inst.sshkey, inst.sshPort, false)
	args = append(args, hostSrc, fmt.Sprintf("%v@127.0.0.1:%v", inst.sshuser, vmDest))

	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}

	if _, err := osutil.RunCmd(3*time.Minute, "", "scp", args...); err != nil {
		return "", err
	}
	return vmDest, nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan []byte, <-chan error, error) {
	dmesg, err := net.Dial("unix", inst.serialPath)
	if err != nil {
		if inst.debug {
			log.Logf(0, "serial console not available: %v; continuing without it", err)
		}
		dmesg = nil
	}
	args := vmimpl.SSHArgs(inst.debug, inst.sshkey, inst.sshPort, false)
	if inst.rpcPort != 0 {
		proxy := fmt.Sprintf("%d:127.0.0.1:%d", inst.rpcPort, inst.rpcPort)
		args = append(args, "-R", proxy)
	}

	args = append(args, fmt.Sprintf("%v@127.0.0.1", inst.sshuser), fmt.Sprintf("cd / && exec %v", command))
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		if inst.debug {
			log.Logf(0, "LongPipe failed: %v", err)
		}
		if dmesg != nil {
			dmesg.Close()
		}
		return nil, nil, err
	}
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		if dmesg != nil {
			dmesg.Close()
		}
		return nil, nil, err
	}
	wpipe.Close()
	merger := vmimpl.NewOutputMerger(nil)
	merger.Add("dmesg", dmesg)
	merger.Add("ssh", rpipe)

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
