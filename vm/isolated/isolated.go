// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package isolated

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/config"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("isolated", ctor)
}

type Config struct {
	Targets       []string // target machines
	Target_Dir    string   // directory to copy/run on target
	Target_Reboot bool     // reboot target on repair
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg    *Config
	target string
	closed chan bool
	debug  bool
	sshkey string
	port   int
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("config param targets is empty")
	}
	if cfg.Target_Dir == "" {
		return nil, fmt.Errorf("config param target_dir is empty")
	}
	// sshkey is optional
	if env.SshKey != "" && !osutil.IsExist(env.SshKey) {
		return nil, fmt.Errorf("ssh key '%v' does not exist", env.SshKey)
	}
	if env.Debug {
		cfg.Targets = cfg.Targets[:1]
	}
	pool := &Pool{
		cfg: cfg,
		env: env,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return len(pool.cfg.Targets)
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		cfg:    pool.cfg,
		target: pool.env.SshUser + "@" + pool.cfg.Targets[index],
		closed: make(chan bool),
		debug:  pool.env.Debug,
		sshkey: pool.env.SshKey,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := inst.repair(); err != nil {
		return nil, err
	}

	// Create working dir if doesn't exist.
	inst.ssh("mkdir -p '" + inst.cfg.Target_Dir + "'")

	// Remove temp files from previous runs.
	inst.ssh("rm -rf '" + filepath.Join(inst.cfg.Target_Dir, "*") + "'")

	closeInst = nil
	return inst, nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.port != 0 {
		return "", fmt.Errorf("isolated: Forward port already set")
	}
	if port == 0 {
		return "", fmt.Errorf("isolated: Forward port is zero")
	}
	inst.port = port
	return fmt.Sprintf("127.0.0.1:%v", port), nil
}

func (inst *instance) ssh(command string) ([]byte, error) {
	if inst.debug {
		Logf(0, "executing ssh %+v", command)
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	args := append(inst.sshArgs("-p"), inst.target, command)
	if inst.debug {
		Logf(0, "running command: ssh %#v", args)
	}
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, err
	}
	wpipe.Close()

	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Second * 30):
			if inst.debug {
				Logf(0, "ssh hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.debug {
			Logf(0, "ssh failed: %v\n%s", err, out)
		}
		return nil, fmt.Errorf("ssh %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.debug {
		Logf(0, "ssh returned")
	}
	out, _ := ioutil.ReadAll(rpipe)
	return out, nil
}

func (inst *instance) repair() error {
	Logf(2, "isolated: trying to ssh")
	if err := inst.waitForSsh(30 * 60); err == nil {
		if inst.cfg.Target_Reboot == true {
			Logf(2, "isolated: trying to reboot")
			inst.ssh("reboot") // reboot will return an error, ignore it
			if err := inst.waitForReboot(5 * 60); err != nil {
				Logf(2, "isolated: machine did not reboot")
				return err
			}
			Logf(2, "isolated: rebooted wait for comeback")
			if err := inst.waitForSsh(30 * 60); err != nil {
				Logf(2, "isolated: machine did not comeback")
				return err
			}
			Logf(2, "isolated: reboot succeeded")
		} else {
			Logf(2, "isolated: ssh succeeded")
		}
	} else {
		Logf(2, "isolated: ssh failed")
		return fmt.Errorf("SSH failed")
	}

	return nil
}

func (inst *instance) waitForSsh(timeout int) error {
	var err error
	start := time.Now()
	for {
		if !vmimpl.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if _, err = inst.ssh("pwd"); err == nil {
			return nil
		}
		if time.Since(start).Seconds() > float64(timeout) {
			break
		}
	}
	return fmt.Errorf("isolated: instance is dead and unrepairable: %v", err)
}

func (inst *instance) waitForReboot(timeout int) error {
	var err error
	start := time.Now()
	for {
		if !vmimpl.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		// If it fails, then the reboot started
		if _, err = inst.ssh("pwd"); err != nil {
			return nil
		}
		if time.Since(start).Seconds() > float64(timeout) {
			break
		}
	}
	return fmt.Errorf("isolated: the machine did not reboot on repair")
}

func (inst *instance) Close() {
	close(inst.closed)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	baseName := filepath.Base(hostSrc)
	vmDst := filepath.Join(inst.cfg.Target_Dir, baseName)
	inst.ssh("pkill -9 '" + baseName + "'; rm -f '" + vmDst + "'")
	args := append(inst.sshArgs("-P"), hostSrc, inst.target+":"+vmDst)
	cmd := exec.Command("scp", args...)
	if inst.debug {
		Logf(0, "running command: scp %#v", args)
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

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	args := append(inst.sshArgs("-p"), inst.target)
	dmesg, err := vmimpl.OpenRemoteConsole("ssh", args...)
	if err != nil {
		return nil, nil, err
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		dmesg.Close()
		return nil, nil, err
	}

	args = inst.sshArgs("-p")
	// Forward target port as part of the ssh connection (reverse proxy)
	if inst.port != 0 {
		proxy := fmt.Sprintf("%v:127.0.0.1:%v", inst.port, inst.port)
		args = append(args, "-R", proxy)
	}
	args = append(args, inst.target, "cd "+inst.cfg.Target_Dir+" && exec "+command)
	Logf(0, "running command: ssh %#v", args)
	if inst.debug {
		Logf(0, "running command: ssh %#v", args)
	}
	cmd := exec.Command("ssh", args...)
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
			if inst.debug {
				Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			cmd.Process.Kill()
			dmesg.Close()
			merger.Wait()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		dmesg.Close()
		merger.Wait()
		cmd.Wait()
	}()
	return merger.Output, errc, nil
}

func (inst *instance) sshArgs(portArg string) []string {
	args := []string{
		portArg, "22",
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
