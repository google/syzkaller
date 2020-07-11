// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package isolated

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
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

const pstoreConsoleFile = "/sys/fs/pstore/console-ramoops-0"

func init() {
	vmimpl.Register("isolated", ctor, false)
}

type Config struct {
	Host          string   `json:"host"`           // host ip addr
	Targets       []string `json:"targets"`        // target machines: (hostname|ip)(:port)?
	TargetDir     string   `json:"target_dir"`     // directory to copy/run on target
	TargetReboot  bool     `json:"target_reboot"`  // reboot target on repair
	USBDevNums    []string `json:"usb_device_num"` // /sys/bus/usb/devices/
	StartupScript string   `json:"startup_script"` // script to execute after each startup
	Pstore        bool     `json:"pstore"`         // use crashlogs from pstore
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg         *Config
	os          string
	targetAddr  string
	targetPort  int
	index       int
	closed      chan bool
	debug       bool
	sshUser     string
	sshKey      string
	forwardPort int
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("config param targets is empty")
	}
	if cfg.TargetDir == "" {
		return nil, fmt.Errorf("config param target_dir is empty")
	}
	for _, target := range cfg.Targets {
		if _, _, err := splitTargetPort(target); err != nil {
			return nil, fmt.Errorf("bad target %q: %v", target, err)
		}
	}
	if len(cfg.USBDevNums) > 0 {
		if len(cfg.USBDevNums) != len(cfg.Targets) {
			return nil, fmt.Errorf("the number of Targets and the number of USBDevNums should be same")
		}
	}
	if env.Debug && len(cfg.Targets) > 1 {
		log.Logf(0, "limiting number of targets from %v to 1 in debug mode", len(cfg.Targets))
		cfg.Targets = cfg.Targets[:1]
		if len(cfg.USBDevNums) > 1 {
			cfg.USBDevNums = cfg.USBDevNums[:1]
		}
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
	targetAddr, targetPort, _ := splitTargetPort(pool.cfg.Targets[index])
	inst := &instance{
		cfg:        pool.cfg,
		os:         pool.env.OS,
		targetAddr: targetAddr,
		targetPort: targetPort,
		index:      index,
		closed:     make(chan bool),
		debug:      pool.env.Debug,
		sshUser:    pool.env.SSHUser,
		sshKey:     pool.env.SSHKey,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := inst.repair(); err != nil {
		return nil, fmt.Errorf("repair failed: %v", err)
	}

	// Remount to writable.
	inst.ssh("mount -o remount,rw /")

	// Create working dir if doesn't exist.
	inst.ssh("mkdir -p '" + inst.cfg.TargetDir + "'")

	// Remove temp files from previous runs.
	inst.ssh("rm -rf '" + filepath.Join(inst.cfg.TargetDir, "*") + "'")

	// Remove pstore files from previous runs.
	if inst.cfg.Pstore {
		inst.ssh(fmt.Sprintf("rm %v", pstoreConsoleFile))
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("isolated: Forward port already set")
	}
	if port == 0 {
		return "", fmt.Errorf("isolated: Forward port is zero")
	}
	inst.forwardPort = port
	return fmt.Sprintf(inst.cfg.Host+":%v", port), nil
}

func (inst *instance) ssh(command string) error {
	if inst.debug {
		log.Logf(0, "executing ssh %+v", command)
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return err
	}
	// TODO(dvyukov): who is closing rpipe?

	args := append(vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort),
		inst.sshUser+"@"+inst.targetAddr, command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return err
	}
	wpipe.Close()

	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Second * 30):
			if inst.debug {
				log.Logf(0, "ssh hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.debug {
			log.Logf(0, "ssh failed: %v\n%s", err, out)
		}
		return fmt.Errorf("ssh %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.debug {
		log.Logf(0, "ssh returned")
	}
	return nil
}

func (inst *instance) waitRebootAndSSH(rebootTimeout int, sshTimeout time.Duration) error {
	if err := inst.waitForReboot(rebootTimeout); err != nil {
		log.Logf(2, "isolated: machine did not reboot")
		return err
	}
	log.Logf(2, "isolated: rebooted wait for comeback")
	if err := inst.waitForSSH(sshTimeout); err != nil {
		log.Logf(2, "isolated: machine did not comeback")
		return err
	}
	log.Logf(2, "isolated: reboot succeeded")
	return nil
}

// Escapes double quotes(and nested double quote escapes). Ignores any other escapes.
// Reference: https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html
func escapeDoubleQuotes(inp string) string {
	var ret strings.Builder
	for pos := 0; pos < len(inp); pos++ {
		// If inp[pos] is not a double quote or a backslash, just use
		// as is.
		if inp[pos] != '"' && inp[pos] != '\\' {
			ret.WriteByte(inp[pos])
			continue
		}
		// If it is a double quote, escape.
		if inp[pos] == '"' {
			ret.WriteString("\\\"")
			continue
		}
		// If we detect a backslash, reescape only if what it's already escaping
		// is a double-quotes.
		temp := ""
		j := pos
		for ; j < len(inp); j++ {
			if inp[j] == '\\' {
				temp += string(inp[j])
				continue
			}
			// If the escape corresponds to a double quotes, re-escape.
			// Else, just use as is.
			if inp[j] == '"' {
				temp = temp + temp + "\\\""
			} else {
				temp += string(inp[j])
			}
			break
		}
		ret.WriteString(temp)
		pos = j
	}
	return ret.String()
}

func (inst *instance) repair() error {
	log.Logf(2, "isolated: trying to ssh")
	if err := inst.waitForSSH(30 * time.Minute); err != nil {
		log.Logf(2, "isolated: ssh failed")
		return fmt.Errorf("SSH failed")
	}
	if inst.cfg.TargetReboot {
		if len(inst.cfg.USBDevNums) > 0 {
			log.Logf(2, "isolated: trying to reboot by USB authorization")
			usbAuth := fmt.Sprintf("%s%s%s", "/sys/bus/usb/devices/", inst.cfg.USBDevNums[inst.index], "/authorized")
			if err := ioutil.WriteFile(usbAuth, []byte("0"), 0); err != nil {
				log.Logf(2, "isolated: failed to turn off the device")
				return err
			}
			if err := ioutil.WriteFile(usbAuth, []byte("1"), 0); err != nil {
				log.Logf(2, "isolated: failed to turn on the device")
				return err
			}
		} else {
			log.Logf(2, "isolated: ssh succeeded, trying to reboot by ssh")
			inst.ssh("reboot") // reboot will return an error, ignore it
			if err := inst.waitRebootAndSSH(5*60, 30*time.Minute); err != nil {
				return fmt.Errorf("waitRebootAndSSH failed: %v", err)
			}
		}
	}
	if inst.cfg.StartupScript != "" {
		log.Logf(2, "isolated: executing startup_script")
		// Execute the contents of the StartupScript on the DUT.
		contents, err := ioutil.ReadFile(inst.cfg.StartupScript)
		if err != nil {
			return fmt.Errorf("unable to read startup_script: %v", err)
		}
		c := string(contents)
		if err := inst.ssh(fmt.Sprintf("bash -c \"%v\"", escapeDoubleQuotes(c))); err != nil {
			return fmt.Errorf("failed to execute startup_script: %v", err)
		}
		log.Logf(2, "isolated: done executing startup_script")
	}
	return nil
}

func (inst *instance) waitForSSH(timeout time.Duration) error {
	return vmimpl.WaitForSSH(inst.debug, timeout, inst.targetAddr, inst.sshKey, inst.sshUser,
		inst.os, inst.targetPort, nil)
}

func (inst *instance) waitForReboot(timeout int) error {
	var err error
	start := time.Now()
	for {
		if !vmimpl.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		// If it fails, then the reboot started.
		if err = inst.ssh("pwd"); err != nil {
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
	vmDst := filepath.Join(inst.cfg.TargetDir, baseName)
	inst.ssh("pkill -9 '" + baseName + "'; rm -f '" + vmDst + "'")
	args := append(vmimpl.SCPArgs(inst.debug, inst.sshKey, inst.targetPort),
		hostSrc, inst.sshUser+"@"+inst.targetAddr+":"+vmDst)
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
	args := append(vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort), inst.sshUser+"@"+inst.targetAddr)
	dmesg, err := vmimpl.OpenRemoteConsole("ssh", args...)
	if err != nil {
		return nil, nil, err
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		dmesg.Close()
		return nil, nil, err
	}

	args = vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort)
	// Forward target port as part of the ssh connection (reverse proxy)
	if inst.forwardPort != 0 {
		proxy := fmt.Sprintf("%v:127.0.0.1:%v", inst.forwardPort, inst.forwardPort)
		args = append(args, "-R", proxy)
	}
	if inst.cfg.Pstore {
		args = append(args, "-o", "ServerAliveInterval=6")
		args = append(args, "-o", "ServerAliveCountMax=5")
	}
	args = append(args, inst.sshUser+"@"+inst.targetAddr, "cd "+inst.cfg.TargetDir+" && exec "+command)
	log.Logf(0, "running command: ssh %#v", args)
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

func (inst *instance) readPstoreContents() ([]byte, error) {
	log.Logf(0, "reading pstore contents")
	args := append(vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort),
		inst.sshUser+"@"+inst.targetAddr, "cat "+pstoreConsoleFile+" && rm "+pstoreConsoleFile)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	var stdout, stderr bytes.Buffer
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("unable to read pstore file: %v: %v", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (inst *instance) Diagnose() ([]byte, bool) {
	if !inst.cfg.Pstore {
		return nil, false
	}
	log.Logf(2, "waiting for crashed DUT to come back up")
	if err := inst.waitRebootAndSSH(5*60, 30*time.Minute); err != nil {
		return []byte(fmt.Sprintf("unable to SSH into DUT after reboot: %v", err)), false
	}
	log.Logf(2, "reading contents of pstore")
	contents, err := inst.readPstoreContents()
	if err != nil {
		return []byte(fmt.Sprintf("Diagnose failed: %v\n", err)), false
	}
	return contents, false
}

func splitTargetPort(addr string) (string, int, error) {
	target := addr
	port := 22
	if colonPos := strings.Index(addr, ":"); colonPos != -1 {
		p, err := strconv.ParseUint(addr[colonPos+1:], 10, 16)
		if err != nil {
			return "", 0, err
		}
		target = addr[:colonPos]
		port = int(p)
	}
	if target == "" {
		return "", 0, fmt.Errorf("target is empty")
	}
	return target, port, nil
}
