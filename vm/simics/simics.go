// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package simics implements test machines on top of the Intel Simics full-system simulator.
//
// Every instance runs its own simulator process in a Simics project, started as
//
//	<project>/simics <simics_args> <target> <param>=<value>... -e "run-script <setup.py>" -e run
//
// The target is any Simics target or script, by default the QSP x86 "user-provided-linux"
// target, which boots the kernel given in the config with the image as the virtio root disk.
// Before the simulation starts, the per-instance setup script moves the serial console onto
// a private telnet port (the kernel console is read from there) and forwards a free host
// port to guest port 22 through the service node of the simulated Ethernet link
// (Simics prints it as "Host TCP port NNNN -> a.b.c.d:22"), and commands run over ssh.
//
// Simics uses VMP (hardware-assisted x86 simulation) on its own if the host supports it
// and the vmxmon module is loaded, otherwise it falls back to pure software simulation.
// Simics keeps guest disk writes in memory, so all instances can share one image.
package simics

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
	vmimpl.Register("simics", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	// Number of simulator instances to run in parallel (1 by default).
	Count int `json:"count"`
	// Simics project directory, as created by Simics' project-setup (default: $SIMICS_PROJECT).
	// The simulator runs there, so relative script paths in target are resolved against it.
	Project string `json:"project"`
	// Simulator launcher (default: <project>/simics).
	Simics string `json:"simics"`
	// Launcher options given before the target (default: "--no-win --batch-mode").
	SimicsArgs string `json:"simics_args"`
	// Target or script to load (default: "qsp-x86/user-provided-linux"), e.g.
	// "targets/qsp-x86/qsp-hdd-boot.simics" to boot the kernel installed in a disk image.
	Target string `json:"target"`
	// Target parameters (name -> value), passed as <name>=<value> on the command line.
	// "{{KERNEL}}", "{{IMAGE}}", "{{CMDLINE}}", "{{WORKDIR}}" and "{{INDEX}}" in the values
	// are replaced with kernel, the manager image, cmdline, the instance working directory
	// and the instance index. For the default target, the parameters that boot kernel with
	// the image as virtio root disk are preset, and params are applied on top of them.
	Params map[string]string `json:"params"`
	// Kernel image (bzImage) to boot, used for "{{KERNEL}}".
	Kernel string `json:"kernel"`
	// Kernel command line, used for "{{CMDLINE}}" (default: see defaultCmdline).
	Cmdline string `json:"cmdline"`
	// Text console object that carries the kernel console (console= on the kernel command line
	// has to point at its serial port). By default the first textcon object, sorted by name,
	// e.g. "qsp.serconsole.con" for the default target or "board.serconsole.con" for qsp-hdd-boot.
	Console string `json:"console"`
	// Ethernet link (switch) that the guest NIC is connected to. By default the only one.
	EthernetLink string `json:"ethernet_link"`
	// IP address that the guest gets on that link; the ssh port forward goes there
	// (default: 10.10.0.100, the first address of the service node DHCP pool of the QSP targets).
	GuestIP string `json:"guest_ip"`
	// Additional Simics CLI commands to run after the setup, right before the simulation starts.
	Commands []string `json:"commands"`
	// Time limit in seconds for the simulator to come up and the guest to become reachable
	// over ssh (default: 1800).
	BootTimeout int `json:"boot_timeout"`
	// Directory in the guest where binaries are copied to (default: "/").
	TargetDir string `json:"target_dir"`
	// Save the simulator and serial console output of VM N to <workdir>/simics/vm-N.log
	// (true by default). The file is rewritten on every boot of that VM.
	ConsoleLog bool `json:"console_log"`
}

type Pool struct {
	env    *vmimpl.Env
	cfg    *Config
	params map[string]string
}

type instance struct {
	cfg      *Config
	index    int
	workdir  string
	args     []string
	debug    bool
	os       string
	timeouts targets.Timeouts
	vmimpl.SSHOptions
	consolePort int
	forwardPort int

	simics  *exec.Cmd
	stdin   io.WriteCloser
	console net.Conn
	merger  *vmimpl.OutputMerger
	logPath string
	log     *os.File

	// The host port forwarded to guest ssh, parsed out of the simulator output.
	sshPortc chan int
}

const (
	defaultArgs        = "--no-win --batch-mode"
	defaultTarget      = "qsp-x86/user-provided-linux"
	defaultGuestIP     = "10.10.0.100"
	defaultBootTimeout = 1800
	// The default target attaches the image as a virtio block device; there is no initramfs,
	// so the kernel needs the virtio block, ext4, and e1000e (the QSP NIC) drivers built in.
	defaultCmdline = "root=/dev/vda1 rw console=ttyS0,115200 earlyprintk=serial,ttyS0,115200" +
		" nokaslr oops=panic panic_on_warn=1 panic=86400"
)

// defaultParams boot cfg.Kernel with the manager image as virtio root disk on the default target.
var defaultParams = map[string]string{
	"machine:software:linux:kernel":            "{{KERNEL}}",
	"machine:software:linux:virtio_rootfs":     "{{IMAGE}}",
	"machine:software:linux:cmdline":           "{{CMDLINE}}",
	"machine:hardware:consoles:con0:show":      "FALSE",
	"machine:hardware:consoles:gfx_con:create": "FALSE",
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:       1,
		SimicsArgs:  defaultArgs,
		Target:      defaultTarget,
		Cmdline:     defaultCmdline,
		GuestIP:     defaultGuestIP,
		BootTimeout: defaultBootTimeout,
		TargetDir:   "/",
		ConsoleLog:  true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse simics vm config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if cfg.BootTimeout <= 0 {
		return nil, fmt.Errorf("invalid config param boot_timeout: %v", cfg.BootTimeout)
	}
	if net.ParseIP(cfg.GuestIP) == nil {
		return nil, fmt.Errorf("invalid config param guest_ip: %q", cfg.GuestIP)
	}
	if cfg.Project == "" {
		cfg.Project = os.Getenv("SIMICS_PROJECT")
	}
	if cfg.Project == "" {
		return nil, fmt.Errorf("config param project is not set (the Simics project directory)")
	}
	cfg.Project = osutil.Abs(cfg.Project)
	if !osutil.IsExist(cfg.Project) {
		return nil, fmt.Errorf("simics project %v does not exist", cfg.Project)
	}
	if cfg.Simics == "" {
		cfg.Simics = filepath.Join(cfg.Project, "simics")
	}
	if _, err := exec.LookPath(cfg.Simics); err != nil {
		return nil, fmt.Errorf("simics launcher: %w", err)
	}
	if cfg.Kernel != "" {
		cfg.Kernel = osutil.Abs(cfg.Kernel)
		if !osutil.IsExist(cfg.Kernel) {
			return nil, fmt.Errorf("kernel %v does not exist", cfg.Kernel)
		}
	}
	params := make(map[string]string)
	if cfg.Target == defaultTarget {
		maps.Copy(params, defaultParams)
	}
	maps.Copy(params, cfg.Params)
	for name, val := range params {
		if strings.Contains(val, "{{KERNEL}}") && cfg.Kernel == "" {
			return nil, fmt.Errorf("simics param %v needs the kernel config param", name)
		}
		if strings.Contains(val, "{{IMAGE}}") && env.Image == "" {
			return nil, fmt.Errorf("simics param %v needs the manager image", name)
		}
	}
	return &Pool{
		env:    env,
		cfg:    cfg,
		params: params,
	}, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inst := &instance{
		cfg:         pool.cfg,
		index:       index,
		workdir:     workdir,
		debug:       pool.env.Debug,
		os:          pool.env.OS,
		timeouts:    pool.env.Timeouts,
		consolePort: vmimpl.UnusedTCPPort(),
		sshPortc:    make(chan int, 1),
		SSHOptions: vmimpl.SSHOptions{
			Addr: "localhost",
			Key:  pool.env.SSHKey,
			User: pool.env.SSHUser,
		},
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if pool.cfg.ConsoleLog {
		inst.logPath = filepath.Join(pool.env.Workdir, "simics", fmt.Sprintf("vm-%v.log", index))
	}
	setup := filepath.Join(workdir, "syz-setup.py")
	if err := osutil.WriteFile(setup, pool.setupScript(inst)); err != nil {
		return nil, err
	}
	inst.args = pool.simicsArgs(inst, setup)
	if err := inst.boot(); err != nil {
		return nil, err
	}
	closeInst = nil
	return inst, nil
}

func (pool *Pool) simicsArgs(inst *instance, setup string) []string {
	cfg := pool.cfg
	args := strings.Fields(cfg.SimicsArgs)
	args = append(args, cfg.Target)
	repl := strings.NewReplacer(
		"{{KERNEL}}", cfg.Kernel,
		"{{IMAGE}}", pool.env.Image,
		"{{CMDLINE}}", cfg.Cmdline,
		"{{WORKDIR}}", inst.workdir,
		"{{INDEX}}", strconv.Itoa(inst.index),
	)
	// Map iteration order is random; keep the command line stable.
	for _, name := range slices.Sorted(maps.Keys(pool.params)) {
		args = append(args, name+"="+repl.Replace(pool.params[name]))
	}
	args = append(args, "-e", "run-script "+strconv.Quote(setup))
	for _, cmd := range cfg.Commands {
		args = append(args, "-e", repl.Replace(cmd))
	}
	return append(args, "-e", "run")
}

// setupScript returns the Python script that runs in the simulator once the target is loaded.
func (pool *Pool) setupScript(inst *instance) []byte {
	params, err := json.Marshal(map[string]any{
		"console":       pool.cfg.Console,
		"console_port":  inst.consolePort,
		"ethernet_link": pool.cfg.EthernetLink,
		"guest_ip":      pool.cfg.GuestIP,
		"ssh_port":      vmimpl.UnusedTCPPort(),
	})
	if err != nil {
		panic(err)
	}
	// Base64 keeps arbitrary config strings from breaking out of the Python string literal.
	return fmt.Appendf(nil, setupScript, base64.StdEncoding.EncodeToString(params))
}

const setupScript = `# Generated by syzkaller (vm/simics).
import base64
import json
import cli
import simics
import real_ethernet_network as ren

cfg = json.loads(base64.b64decode('%s').decode('utf-8'))

# The kernel console: only to the telnet client, buffered until it connects.
name = cfg["console"]
if not name:
    cons = sorted(o.name for o in simics.SIM_object_iterator_for_class("textcon"))
    if not cons:
        raise cli.CliError("syz-simics: the target has no text console")
    name = cons[0]
con = simics.SIM_get_object(name)
con.cmd_line_output = False
try:
    con.buffer_until_telnet_connection = True
except Exception:
    pass
con.tcp.port = cfg["console_port"]
print("syz-simics: console %%s on port %%d" %% (con.name, con.tcp.port))

# ssh: the given host port is a hint, the command prints the one actually used.
link = cfg["ethernet_link"]
if not link:
    links = ren.ethlinks_find_all_instantiated()
    if len(links) != 1:
        raise cli.CliError("syz-simics: %%d ethernet links, set ethernet_link" %% len(links))
    link = links[0].name
cli.run_command("connect-real-network-port-in target-port = 22 ethernet-link = %%s"
                " host-port = %%d target-ip = %%s -tcp" %% (link, cfg["ssh_port"], cfg["guest_ip"]))
`

func (inst *instance) boot() error {
	if inst.debug {
		log.Logf(0, "running command: %v %#v", inst.cfg.Simics, inst.args)
	}
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return err
	}
	// The simulator command line would exit on stdin EOF, so keep an open pipe there.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		rpipe.Close()
		wpipe.Close()
		return err
	}
	// osutil.Command starts the simulator in its own process group (and sets Pdeathsig),
	// which Close kills as a whole.
	cmd := osutil.Command(inst.cfg.Simics, inst.args...)
	cmd.Dir = inst.cfg.Project
	cmd.Stdin = stdinR
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	err = cmd.Start()
	wpipe.Close()
	stdinR.Close()
	if err != nil {
		rpipe.Close()
		stdinW.Close()
		return fmt.Errorf("failed to start %v %+v: %w", inst.cfg.Simics, inst.args, err)
	}
	inst.simics = cmd
	inst.stdin = stdinW
	if inst.logPath != "" {
		if err := osutil.MkdirAll(filepath.Dir(inst.logPath)); err == nil {
			inst.log, _ = os.Create(inst.logPath)
		}
		if inst.log != nil {
			fmt.Fprintf(inst.log, "%v: %v %q\n", time.Now().Format(time.DateTime), inst.cfg.Simics, inst.args)
		}
	}

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("simics", vmimpl.OutputConsole,
		inst.teeLog(&lineWatcher{r: rpipe, onLine: inst.parseSimicsLine}))

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	outputc := inst.merger.Output
	go func() {
		for {
			select {
			case out, ok := <-outputc:
				if !ok {
					// Do not spin on a closed channel, wait for bootOutputStop.
					outputc = nil
					continue
				}
				bootOutput = append(bootOutput, out.Data...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()
	stopBootOutput := func() []byte {
		bootOutputStop <- true
		<-bootOutputStop
		return bootOutput
	}

	deadline := time.Now().Add(time.Duration(inst.cfg.BootTimeout) * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. The serial console: it carries the kernel log, so connect before anything else.
	conn, err := inst.connectConsole(deadline, inst.merger.Errors(ctx))
	if err != nil {
		out := stopBootOutput()
		return vmimpl.InfraError{Title: fmt.Sprintf("simics console: %v", err), Output: out}
	}
	inst.console = conn
	inst.merger.Add("console", vmimpl.OutputConsole, inst.teeLog(newTelnetReader(conn)))
	// Errors() only watches the decoders that exist at call time, so re-arm it.
	cancel()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	errc := inst.merger.Errors(ctx)

	// 2. The host port that is forwarded to guest ssh.
	select {
	case inst.Port = <-inst.sshPortc:
	case err := <-errc:
		out := stopBootOutput()
		return vmimpl.MakeBootError(fmt.Errorf("simics exited before forwarding ssh: %w", err), out)
	case <-time.After(time.Until(deadline)):
		out := stopBootOutput()
		return vmimpl.InfraError{Title: "simics did not report the host port forwarded to guest port 22",
			Output: out}
	case <-vmimpl.Shutdown:
		stopBootOutput()
		return fmt.Errorf("shutdown in progress")
	}
	if inst.debug {
		log.Logf(0, "VM-%v: console on port %v, ssh on port %v", inst.index, inst.consolePort, inst.Port)
	}

	// 3. The guest itself.
	if err := vmimpl.WaitForSSH(max(time.Until(deadline), time.Minute), inst.SSHOptions,
		inst.os, errc, false, inst.debug); err != nil {
		return vmimpl.MakeBootError(err, stopBootOutput())
	}
	stopBootOutput()
	return nil
}

// Simics: "Host TCP port 4022 -> 10.10.0.100:22".
var sshPortRe = regexp.MustCompile(`Host TCP port (\d+)\b.*:22\b`)

func (inst *instance) parseSimicsLine(line []byte) {
	m := sshPortRe.FindSubmatch(line)
	if m == nil {
		return
	}
	if port, err := strconv.Atoi(string(m[1])); err == nil && port > 0 && port < 1<<16 {
		select {
		case inst.sshPortc <- port:
		default:
		}
	}
}

// connectConsole waits until the serial console accepts telnet connections.
func (inst *instance) connectConsole(deadline time.Time, stop <-chan error) (net.Conn, error) {
	addr := net.JoinHostPort("localhost", strconv.Itoa(inst.consolePort))
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	// Abort a pending dial as soon as the simulator exits or syzkaller shuts down.
	var stopErr error
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case err := <-stop:
			stopErr = fmt.Errorf("simics exited: %w", err)
			cancel()
		case <-vmimpl.Shutdown:
			stopErr = fmt.Errorf("shutdown in progress")
			cancel()
		case <-ctx.Done():
		}
	}()
	var dialer net.Dialer
	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		select {
		case <-time.After(time.Second):
			continue
		case <-ctx.Done():
		}
		cancel()
		<-stopped
		if stopErr != nil {
			return nil, stopErr
		}
		return nil, fmt.Errorf("can't connect to the serial console on port %v: %w", inst.consolePort, err)
	}
}

func (inst *instance) Close() error {
	if inst.console != nil {
		inst.console.Close()
	}
	if inst.simics != nil {
		// Kill the whole process group: the launcher script and the simulator it starts.
		syscall.Kill(-inst.simics.Process.Pid, syscall.SIGKILL)
		inst.simics.Process.Kill()
		inst.simics.Wait()
	}
	if inst.stdin != nil {
		inst.stdin.Close()
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.log != nil {
		inst.log.Close()
	}
	return nil
}

// teeLog copies everything read from r into the VM log file, if there is one.
func (inst *instance) teeLog(r io.ReadCloser) io.ReadCloser {
	if inst.log == nil {
		return r
	}
	return &teeReader{r: r, w: inst.log}
}

type teeReader struct {
	r io.ReadCloser
	w io.Writer
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.w.Write(p[:n])
	}
	return n, err
}

func (t *teeReader) Close() error {
	return t.r.Close()
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/simics: forward port is zero")
	}
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("vm/simics: forward port already set")
	}
	inst.forwardPort = port
	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join(inst.cfg.TargetDir, filepath.Base(hostSrc))
	err := vmimpl.SCP(hostSrc, vmDst, vmimpl.SCPOptions{
		Debug:         inst.debug,
		Key:           inst.Key,
		Port:          inst.Port,
		User:          inst.User,
		Addr:          inst.Addr,
		Timeout:       10 * time.Minute * inst.timeouts.Scale,
		VerboseOutput: true,
	})
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

	args := vmimpl.SSHArgsForward(inst.debug, inst.Key, inst.Port, inst.forwardPort, false)
	args = append(args, inst.User+"@"+inst.Addr, "cd "+inst.cfg.TargetDir+" && "+command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Dir = inst.workdir
	cmd.Stdout = wpipe
	cmd.Stderr = wpipeErr
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		wpipeErr.Close()
		return nil, nil, err
	}
	wpipe.Close()
	wpipeErr.Close()
	return vmimpl.Multiplex(ctx, cmd, inst.merger, vmimpl.MultiplexConfig{
		Debug: inst.debug,
		Scale: inst.timeouts.Scale,
	})
}

func (inst *instance) Info() ([]byte, error) {
	return fmt.Appendf(nil, "%v %q\n", inst.cfg.Simics, inst.args), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	if inst.os == targets.Linux {
		if output, wait, handled := vmimpl.DiagnoseLinux(rep, inst.ssh); handled {
			return output, wait
		}
	}
	return nil, false
}

func (inst *instance) ssh(args ...string) ([]byte, error) {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.Key, inst.Port, false), inst.User+"@"+inst.Addr)
	return osutil.RunCmd(time.Minute*inst.timeouts.Scale, "", "ssh", append(sshArgs, args...)...)
}

// lineWatcher passes data through and calls onLine for every complete line.
type lineWatcher struct {
	r      io.ReadCloser
	buf    []byte
	onLine func(line []byte)
}

func (w *lineWatcher) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	w.buf = append(w.buf, p[:n]...)
	for {
		pos := bytes.IndexByte(w.buf, '\n')
		if pos == -1 {
			break
		}
		w.onLine(bytes.TrimRight(w.buf[:pos], "\r"))
		w.buf = w.buf[pos+1:]
	}
	const maxLine = 4 << 10
	if len(w.buf) > maxLine {
		w.buf = w.buf[len(w.buf)-maxLine:]
	}
	w.buf = append([]byte(nil), w.buf...)
	return n, err
}

func (w *lineWatcher) Close() error {
	return w.r.Close()
}

// telnetReader strips telnet protocol commands from the serial console stream.
// Option negotiation is not answered, the stream is only read.
type telnetReader struct {
	conn  net.Conn
	state int
	buf   []byte
}

const (
	telnetSE   = 240
	telnetSB   = 250
	telnetWILL = 251
	telnetDONT = 254
	telnetIAC  = 255
)

const (
	stData = iota
	stIAC
	stOption
	stSub
	stSubIAC
)

func newTelnetReader(conn net.Conn) *telnetReader {
	return &telnetReader{conn: conn}
}

func (t *telnetReader) Read(p []byte) (int, error) {
	if cap(t.buf) < len(p) {
		t.buf = make([]byte, len(p))
	}
	for {
		n, err := t.conn.Read(t.buf[:len(p)])
		out := t.filter(p[:0], t.buf[:n])
		if len(out) != 0 || err != nil {
			return len(out), err
		}
	}
}

func (t *telnetReader) filter(out, in []byte) []byte {
	for _, c := range in {
		switch t.state {
		case stData:
			switch c {
			case telnetIAC:
				t.state = stIAC
			case 0:
				// NUL after CR, or padding.
			default:
				out = append(out, c)
			}
		case stIAC:
			switch {
			case c == telnetIAC:
				out = append(out, c)
				t.state = stData
			case c == telnetSB:
				t.state = stSub
			case c >= telnetWILL && c <= telnetDONT:
				t.state = stOption
			default:
				t.state = stData
			}
		case stOption:
			t.state = stData
		case stSub:
			if c == telnetIAC {
				t.state = stSubIAC
			}
		case stSubIAC:
			if c == telnetSE {
				t.state = stData
			} else {
				t.state = stSub
			}
		}
	}
	return out
}

func (t *telnetReader) Close() error {
	return t.conn.Close()
}
