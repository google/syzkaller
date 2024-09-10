// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package starnix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	var _ vmimpl.Infoer = (*instance)(nil)
	vmimpl.Register(targets.Starnix, vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
}

type Pool struct {
	count int
	env   *vmimpl.Env
	cfg   *Config
}

type instance struct {
	fuchsiaDirectory string
	ffxBinary        string
	name             string
	index            int
	cfg              *Config
	version          string
	debug            bool
	workdir          string
	port             int
	forwardPort      int
	rpipe            io.ReadCloser
	wpipe            io.WriteCloser
	fuchsiaLogs      *exec.Cmd
	sshPubKey        string
	sshPrivKey       string
	merger           *vmimpl.OutputMerger
	diagnose         chan bool
}

const targetDir = "/tmp"

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse starnix vm config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}

	pool := &Pool{
		count: cfg.Count,
		env:   env,
		cfg:   cfg,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		fuchsiaDirectory: pool.env.KernelSrc,
		name:             fmt.Sprintf("VM-%v", index),
		index:            index,
		cfg:              pool.cfg,
		debug:            pool.env.Debug,
		workdir:          workdir,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	var err error
	inst.ffxBinary, err = getToolPath(inst.fuchsiaDirectory, "ffx")
	if err != nil {
		return nil, err
	}

	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.setFuchsiaVersion(); err != nil {
		return nil, fmt.Errorf(
			"there is an error running ffx commands in the Fuchsia checkout (%q): %w",
			inst.fuchsiaDirectory,
			err)
	}
	pubkey, err := osutil.RunCmd(30*time.Second, inst.fuchsiaDirectory, inst.ffxBinary, "config", "get", "ssh.pub")
	if err != nil {
		return nil, err
	}
	inst.sshPubKey = string(bytes.Trim(pubkey, "\"\n"))
	privkey, err := osutil.RunCmd(30*time.Second, inst.fuchsiaDirectory, inst.ffxBinary, "config", "get", "ssh.priv")
	if err != nil {
		return nil, err
	}
	inst.sshPrivKey = string(bytes.Trim(privkey, "\"\n"))

	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) boot() error {
	inst.port = vmimpl.UnusedTCPPort()
	// Start output merger.
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)

	inst.ffx("doctor", "--restart-daemon")

	inst.ffx("emu", "stop", inst.name)

	if err := inst.startFuchsiaVM(); err != nil {
		return fmt.Errorf("instance %s: could not start Fuchsia VM: %w", inst.name, err)
	}
	if err := inst.startSshdAndConnect(); err != nil {
		return fmt.Errorf("instance %s: could not start sshd: %w", inst.name, err)
	}
	if inst.debug {
		log.Logf(0, "instance %s: setting up...", inst.name)
	}
	if err := inst.startFuchsiaLogs(); err != nil {
		return fmt.Errorf("instance %s: could not start fuchsia logs: %w", inst.name, err)
	}
	if inst.debug {
		log.Logf(0, "instance %s: booted successfully", inst.name)
	}
	return nil
}

func (inst *instance) Close() error {
	inst.ffx("emu", "stop", inst.name)
	if inst.fuchsiaLogs != nil {
		inst.fuchsiaLogs.Process.Kill()
		inst.fuchsiaLogs.Wait()
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
	return nil
}

func (inst *instance) startFuchsiaVM() error {
	err := inst.ffx("emu", "start", "--headless", "--name", inst.name, "--net", "user")
	if err != nil {
		return err
	}
	return nil
}

func (inst *instance) startFuchsiaLogs() error {
	// `ffx log` outputs some buffered logs by default, and logs from early boot
	// trigger a false positive from the unexpected reboot check. To avoid this,
	// only request logs from now on.
	cmd := osutil.Command(inst.ffxBinary, "--target", inst.name, "log", "--since", "now",
		"--show-metadata", "--show-full-moniker", "--no-color")
	cmd.Dir = inst.fuchsiaDirectory
	cmd.Stdout = inst.wpipe
	cmd.Stderr = inst.wpipe
	inst.merger.Add("fuchsia", inst.rpipe)
	if err := cmd.Start(); err != nil {
		return err
	}
	inst.fuchsiaLogs = cmd
	inst.wpipe.Close()
	inst.wpipe = nil
	return nil
}

func (inst *instance) startSshdAndConnect() error {
	cmd := osutil.Command(
		inst.ffxBinary,
		"--target",
		inst.name,
		"component",
		"run",
		"/core/starnix_runner/playground:alpine",
		"fuchsia-pkg://fuchsia.com/syzkaller_starnix#meta/alpine_container.cm",
	)
	cmd.Dir = inst.fuchsiaDirectory
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(1, "instance %s: started alpine container", inst.name)
	}
	cmd = osutil.Command(inst.ffxBinary,
		"--target",
		inst.name,
		"component",
		"run",
		"/core/starnix_runner/playground:alpine/daemons:start_sshd",
		"fuchsia-pkg://fuchsia.com/syzkaller_starnix#meta/start_sshd.cm",
	)
	cmd.Dir = inst.fuchsiaDirectory
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(1, "instance %s: started sshd on alpine container", inst.name)
	}
	cmd = osutil.Command(
		inst.ffxBinary,
		"--target",
		inst.name,
		"component",
		"copy",
		inst.sshPubKey,
		"/core/starnix_runner/playground:alpine::out::fs_root/tmp/authorized_keys",
	)
	cmd.Dir = inst.fuchsiaDirectory
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, "instance %s: copied ssh key", inst.name)
	}
	return inst.connect()
}

func (inst *instance) connect() error {
	if inst.debug {
		log.Logf(1, "instance %s: attempting to connect to starnix container over ssh", inst.name)
	}
	address, err := osutil.RunCmd(
		30*time.Second,
		inst.fuchsiaDirectory,
		inst.ffxBinary,
		"--target",
		inst.name,
		"target",
		"get-ssh-address")
	if err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, "instance %s: the fuchsia instance's address is %s", inst.name, address)
	}
	cmd := osutil.Command(
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-i", inst.sshPrivKey,
		"-NT",
		"-L", fmt.Sprintf("localhost:%d:localhost:7000", inst.port), fmt.Sprintf("ssh://%s", bytes.Trim(address, "\n")),
	)
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	time.Sleep(5 * time.Second)
	if inst.debug {
		log.Logf(0, "instance %s: forwarded port from starnix container", inst.name)
	}
	return nil
}

func (inst *instance) ffx(args ...string) error {
	return inst.runCommand(inst.ffxBinary, args...)
}

// Runs a command inside the fuchsia directory.
func (inst *instance) runCommand(cmd string, args ...string) error {
	if inst.debug {
		log.Logf(1, "instance %s: running command: %s %q", inst.name, cmd, args)
	}
	output, err := osutil.RunCmd(5*time.Minute, inst.fuchsiaDirectory, cmd, args...)
	if inst.debug {
		log.Logf(1, "instance %s: %s", inst.name, output)
	}
	return err
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/starnix: forward port is zero")
	}
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("vm/starnix: forward port already set")
	}
	inst.forwardPort = port
	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join(targetDir, base)
	if inst.debug {
		log.Logf(1, "instance %s: attempting to push binary %s to instance over scp", inst.name, base)
	}
	err := inst.runCommand(
		"scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-i", inst.sshPrivKey,
		"-P", strconv.Itoa(inst.port),
		hostSrc,
		fmt.Sprintf("root@localhost:%s", vmDst),
	)
	if err == nil {
		return vmDst, err
	}
	return vmDst, fmt.Errorf("instance %s: can't push binary %s to instance over scp", inst.name, base)
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)

	// Run `command` on the instance over ssh.
	const useSystemSSHCfg = false
	sshArgs := vmimpl.SSHArgsForward(inst.debug, inst.sshPrivKey, inst.port, inst.forwardPort, useSystemSSHCfg)
	sshCmd := []string{"ssh"}
	sshCmd = append(sshCmd, sshArgs...)
	sshCmd = append(sshCmd, "root@localhost", "cd "+targetDir+" && ", command)
	if inst.debug {
		log.Logf(1, "instance %s: running command: %#v", inst.name, sshCmd)
	}

	cmd := osutil.Command(sshCmd[0], sshCmd[1:]...)
	cmd.Dir = inst.workdir
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
	retry:
		select {
		case <-time.After(timeout):
			signal(vmimpl.ErrTimeout)
		case <-stop:
			signal(vmimpl.ErrTimeout)
		case <-inst.diagnose:
			cmd.Process.Kill()
			goto retry
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

func (inst *instance) Info() ([]byte, error) {
	info := fmt.Sprintf("%v\n%v", inst.version, "ffx")
	return []byte(info), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *instance) setFuchsiaVersion() error {
	version, err := osutil.RunCmd(1*time.Minute, inst.fuchsiaDirectory, inst.ffxBinary, "version")
	if err != nil {
		return err
	}
	inst.version = string(version)
	return nil
}

// Get the currently-selected build dir in a Fuchsia checkout.
func getFuchsiaBuildDir(fuchsiaDir string) (string, error) {
	fxBuildDir := filepath.Join(fuchsiaDir, ".fx-build-dir")
	contents, err := os.ReadFile(fxBuildDir)
	if err != nil {
		return "", fmt.Errorf("failed to read %q: %w", fxBuildDir, err)
	}

	buildDir := strings.TrimSpace(string(contents))
	if !filepath.IsAbs(buildDir) {
		buildDir = filepath.Join(fuchsiaDir, buildDir)
	}

	return buildDir, nil
}

// Subset of data format used in tool_paths.json.
type toolMetadata struct {
	Name string
	Path string
}

// Resolve a tool by name using tool_paths.json in the build dir.
func getToolPath(fuchsiaDir, toolName string) (string, error) {
	buildDir, err := getFuchsiaBuildDir(fuchsiaDir)
	if err != nil {
		return "", err
	}

	jsonPath := filepath.Join(buildDir, "tool_paths.json")
	jsonBlob, err := os.ReadFile(jsonPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %q: %w", jsonPath, err)
	}
	var metadataList []toolMetadata
	if err := json.Unmarshal(jsonBlob, &metadataList); err != nil {
		return "", fmt.Errorf("failed to parse %q: %w", jsonPath, err)
	}

	for _, metadata := range metadataList {
		if metadata.Name == toolName {
			return filepath.Join(buildDir, metadata.Path), nil
		}
	}

	return "", fmt.Errorf("no path found for tool %q in %q", toolName, jsonPath)
}
