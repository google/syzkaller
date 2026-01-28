// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package starnix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	count  int
	env    *vmimpl.Env
	cfg    *Config
	ffxDir string
}

type instance struct {
	fuchsiaDir   string
	ffxBinary    string
	ffxLogBinary string
	ffxDir       string
	name         string
	index        int
	cfg          *Config
	version      string
	debug        bool
	workdir      string
	port         int
	forwardPort  int
	rpipe        io.ReadCloser
	wpipe        io.WriteCloser
	fuchsiaLogs  *exec.Cmd
	sshBridge    *exec.Cmd
	sshPubKey    string
	sshPrivKey   string
	merger       *vmimpl.OutputMerger
	timeouts     targets.Timeouts
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

	ffxDir, err := os.MkdirTemp("", "syz-ffx")
	if err != nil {
		return nil, fmt.Errorf("failed to make ffx isolation dir: %w", err)
	}
	if env.Debug {
		log.Logf(0, "initialized vm pool with ffx dir: %v", ffxDir)
	}

	pool := &Pool{
		count:  cfg.Count,
		env:    env,
		cfg:    cfg,
		ffxDir: ffxDir,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.count
}

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		fuchsiaDir: pool.env.KernelSrc,
		ffxDir:     pool.ffxDir,
		name:       fmt.Sprintf("VM-%v", index),
		index:      index,
		cfg:        pool.cfg,
		debug:      pool.env.Debug,
		workdir:    workdir,
		timeouts:   pool.env.Timeouts,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	var err error
	inst.ffxBinary, err = GetToolPath(inst.fuchsiaDir, "ffx")
	if err != nil {
		return nil, err
	}
	inst.ffxLogBinary, err = GetToolPath(inst.fuchsiaDir, "ffx-log")
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
			inst.fuchsiaDir,
			err)
	}
	pubkey, err := inst.getFfxConfigValue("ssh.pub")
	if err != nil {
		return nil, err
	}
	inst.sshPubKey = pubkey

	privkey, err := inst.getFfxConfigValue("ssh.priv")
	if err != nil {
		return nil, err
	}
	inst.sshPrivKey = privkey

	// Copy auto-detected paths from in-tree ffx to isolated ffx.
	err = inst.copyFfxConfigValuesToIsolate(
		"product.path",
		"sdk.overrides.aemu_internal",
		"sdk.overrides.uefi_internal_x64")
	if err != nil {
		return nil, err
	}

	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (pool *Pool) Close() error {
	if pool.env.Debug {
		log.Logf(0, "shutting down vm pool with tempdir %v...", pool.ffxDir)
	}

	// The ffx daemon will exit automatically when it sees its isolation dir removed.
	return os.RemoveAll(pool.ffxDir)
}

func (inst *instance) boot() error {
	inst.port = vmimpl.UnusedTCPPort()
	// Start output merger.
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)

	inst.runFfx(5*time.Minute, true, "emu", "stop", inst.name)

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
	inst.runFfx(5*time.Minute, true, "emu", "stop", inst.name)
	if inst.fuchsiaLogs != nil {
		inst.fuchsiaLogs.Process.Kill()
		inst.fuchsiaLogs.Wait()
	}
	if inst.sshBridge != nil {
		inst.sshBridge.Process.Kill()
		inst.sshBridge.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	return nil
}

func (inst *instance) startFuchsiaVM() error {
	if _, err := inst.runFfx(
		5*time.Minute,
		true,
		"emu", "start", "--headless",
		"--name", inst.name, "--net", "user"); err != nil {
		return err
	}
	return nil
}

func (inst *instance) startFuchsiaLogs() error {
	// `ffx log` outputs some buffered logs by default, and logs from early boot
	// trigger a false positive from the unexpected reboot check. To avoid this,
	// only request logs from now on.
	cmd := inst.ffxCommand(
		true,
		inst.ffxLogBinary,
		"--target", inst.name, "log", "--since", "now",
		"--show-metadata", "--show-full-moniker", "--no-color",
		"--exclude-tags", "netlink")
	cmd.Stdout = inst.wpipe
	cmd.Stderr = inst.wpipe
	inst.merger.Add("fuchsia", vmimpl.OutputConsole, inst.rpipe)
	if inst.debug {
		log.Logf(1, "instance %s: starting ffx log", inst.name)
	}
	if err := cmd.Start(); err != nil {
		if inst.debug {
			log.Logf(0, "instance %s: failed to start ffx log", inst.name)
		}
		return err
	}
	inst.fuchsiaLogs = cmd
	inst.wpipe.Close()
	inst.wpipe = nil
	return nil
}

func (inst *instance) startSshdAndConnect() error {
	if _, err := inst.runFfx(
		5*time.Minute,
		true,
		"--target",
		inst.name,
		"component",
		"run",
		"/core/starnix_runner/playground:alpine",
		"fuchsia-pkg://fuchsia.com/syzkaller_starnix#meta/alpine_container.cm",
	); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(1, "instance %s: started alpine container", inst.name)
	}
	if _, err := inst.runFfx(
		5*time.Minute,
		true,
		"--target",
		inst.name,
		"component",
		"run",
		"/core/starnix_runner/playground:alpine/daemons:start_sshd",
		"fuchsia-pkg://fuchsia.com/syzkaller_starnix#meta/start_sshd.cm",
	); err != nil {
		return err
	}
	if inst.debug {
		log.Logf(1, "instance %s: started sshd on alpine container", inst.name)
	}
	if _, err := inst.runFfx(
		5*time.Minute,
		true,
		"--target",
		inst.name,
		"component",
		"copy",
		inst.sshPubKey,
		"/core/starnix_runner/playground:alpine::out::fs_root/tmp/authorized_keys",
	); err != nil {
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
	// Even though the formatting option is called `addresses`, it is guaranteed
	// to return at most 1 address per target.
	address, err := inst.runFfx(
		30*time.Second,
		true,
		"target",
		"list",
		inst.name,
		"--format",
		"addresses",
	)
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
		"-L", fmt.Sprintf("localhost:%d:localhost:7000", inst.port),
		fmt.Sprintf("ssh://%s", bytes.Trim(address, "\n")),
	)
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}

	inst.sshBridge = cmd

	time.Sleep(5 * time.Second)
	if inst.debug {
		log.Logf(0, "instance %s: forwarded port from starnix container", inst.name)
	}
	return nil
}

func (inst *instance) ffxCommand(isolated bool, binary string, args ...string) *exec.Cmd {
	config := []string{"-c", "log.enabled=false,ffx.analytics.disabled=true"}
	if !isolated {
		config = append(config, "-c", "daemon.autostart=false")
	}
	args = slices.Concat(config, args)
	cmd := osutil.Command(binary, args...)
	cmd.Dir = inst.fuchsiaDir
	cmd.Env = append(cmd.Environ(), "FUCHSIA_ANALYTICS_DISABLED=1")
	if isolated {
		cmd.Env = append(cmd.Env, "FFX_ISOLATE_DIR="+inst.ffxDir)
	}
	return cmd
}

func (inst *instance) runFfx(timeout time.Duration, isolated bool, args ...string) ([]byte, error) {
	if inst.debug {
		isolation := "without"
		if isolated {
			isolation = "with"
		}
		log.Logf(1, "instance %s: running ffx %s isolation: %q", inst.name, isolation, args)
	}

	cmd := inst.ffxCommand(isolated, inst.ffxBinary, args...)
	cmd.Stderr = os.Stderr
	output, err := osutil.Run(timeout, cmd)
	if inst.debug {
		log.Logf(1, "instance %s: %s", inst.name, output)
	}
	return output, err
}

// Gets a value from ffx's default configuration.
func (inst *instance) getFfxConfigValue(key string) (string, error) {
	rawValue, err := inst.runFfx(
		30*time.Second,
		false,
		"config", "get", key)
	if err != nil {
		return "", err
	}
	return string(bytes.Trim(rawValue, "\"\n")), nil
}

// Copies values from ffx's default configuration into the ffx isolate's configuration.
func (inst *instance) copyFfxConfigValuesToIsolate(keys ...string) error {
	for _, key := range keys {
		value, err := inst.getFfxConfigValue(key)
		if err != nil {
			return err
		}
		_, err = inst.runFfx(
			30*time.Second,
			true,
			"config", "set", key, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Runs a command inside the fuchsia directory.
func (inst *instance) runCommand(cmd string, args ...string) error {
	if inst.debug {
		log.Logf(1, "instance %s: running command: %s %q", inst.name, cmd, args)
	}
	output, err := osutil.RunCmd(5*time.Minute, inst.fuchsiaDir, cmd, args...)
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

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", vmimpl.OutputCommand, rpipe)

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
	return vmimpl.Multiplex(ctx, cmd, inst.merger, vmimpl.MultiplexConfig{
		Debug: inst.debug,
		Scale: inst.timeouts.Scale,
	})
}

func (inst *instance) Info() ([]byte, error) {
	info := fmt.Sprintf("%v\n%v", inst.version, "ffx")
	return []byte(info), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *instance) setFuchsiaVersion() error {
	version, err := osutil.RunCmd(1*time.Minute, inst.fuchsiaDir, inst.ffxBinary, "version")
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
func GetToolPath(fuchsiaDir, toolName string) (string, error) {
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
