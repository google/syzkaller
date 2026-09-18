// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package crosvm implements VMs based on crosvm, the ChromeOS Virtual Machine Monitor
// (https://crosvm.dev). See docs/linux/setup_linux-host_crosvm-vm_x86-64-kernel.md.
package crosvm

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	vmimpl.Register("crosvm", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
	// crosvm binary name ("crosvm" by default).
	Crosvm string `json:"crosvm"`
	// Location of the kernel to boot, e.g. arch/x86/boot/bzImage.
	// crosvm always boots the kernel directly, so this is mandatory.
	Kernel string `json:"kernel"`
	// Additional kernel command line arguments.
	// The root device, console and the static network configuration are added automatically.
	Cmdline string `json:"cmdline"`
	// Initial ramdisk (optional).
	Initrd string `json:"initrd"`
	// Root device as seen by the guest ("/dev/vda1" by default).
	// crosvm exposes disks as virtio-blk, so the image is /dev/vda and its first partition
	// is /dev/vda1. Images without a partition table need "/dev/vda".
	RootDevice string `json:"root_device"`
	// Name of the guest network interface to configure from the kernel command line
	// ("eth0" by default, which requires net.ifnames=0 in the kernel command line).
	// An empty value configures all interfaces.
	NetDevice string `json:"network_device"`
	// Number of VM CPUs (1 by default).
	CPU int `json:"cpu"`
	// Amount of VM memory in MiB (1024 by default).
	Mem int `json:"mem"`
	// Run every VM on a copy-on-write overlay of the image instead of the image itself
	// (true by default). This is the equivalent of QEMU's -snapshot.
	Overlay bool `json:"overlay"`
	// Run all devices in a single non-sandboxed process (true by default).
	// crosvm's minijail sandbox needs additional privileges and a seccomp policy directory,
	// which is not worth it for a fuzzing VM that is untrusted anyway.
	DisableSandbox bool `json:"disable_sandbox"`
	// Name of a pre-created persistent tap device to use for networking (optional).
	// If empty, crosvm creates a tap device itself, which requires CAP_NET_ADMIN.
	// "{{INDEX}}" is replaced with the 0-based index of the VM.
	TapName string `json:"tap_name"`
	// Second octet of the per-VM /24 network (168 by default), i.e. VM with index N uses
	// 192.<net_base>.<100+N>.0/24 with the host at .1 and the guest at .2.
	// Only used when tap_name is not set.
	NetBase int `json:"net_base"`
	// Host and guest IP addresses (optional).
	// These must be set when tap_name is used, and override the computed addresses otherwise.
	HostIP  string `json:"host_ip"`
	GuestIP string `json:"guest_ip"`
	Netmask string `json:"netmask"`
	// Additional command line arguments for the crosvm binary.
	// "{{INDEX}}" is replaced with the 0-based index of the VM.
	CrosvmArgs string `json:"crosvm_args"`
}

type Pool struct {
	env     *vmimpl.Env
	cfg     *Config
	target  *targets.Target
	version string
}

type instance struct {
	index   int
	cfg     *Config
	target  *targets.Target
	version string
	args    []string
	image   string
	debug   bool
	os      string
	workdir string
	vmimpl.SSHOptions
	timeouts targets.Timeouts
	hostIP   string
	sock     string
	rpipe    io.ReadCloser
	wpipe    io.WriteCloser
	crosvm   *exec.Cmd
	merger   *vmimpl.OutputMerger
	*snapshot
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:          1,
		Crosvm:         "crosvm",
		CPU:            1,
		Mem:            1024,
		RootDevice:     "/dev/vda1",
		NetDevice:      "eth0",
		Overlay:        true,
		DisableSandbox: true,
		NetBase:        168,
		Netmask:        "255.255.255.0",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse crosvm vm config: %w", err)
	}
	if env.OS != targets.Linux {
		return nil, fmt.Errorf("crosvm supports only linux targets")
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if cfg.CPU < 1 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("bad crosvm cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("bad crosvm mem: %v, want [128-1048576]", cfg.Mem)
	}
	if cfg.NetBase < 0 || cfg.NetBase > 255 {
		return nil, fmt.Errorf("bad crosvm net_base: %v, want [0-255]", cfg.NetBase)
	}
	if cfg.TapName != "" && (cfg.HostIP == "" || cfg.GuestIP == "") {
		return nil, fmt.Errorf("crosvm tap_name requires host_ip and guest_ip")
	}
	if cfg.TapName == "" && cfg.Count > maxComputedNets {
		return nil, fmt.Errorf("crosvm count %v needs more than the %v automatically assigned "+
			"networks, use tap_name instead", cfg.Count, maxComputedNets)
	}
	if _, err := exec.LookPath(cfg.Crosvm); err != nil {
		return nil, err
	}
	// crosvm has no BIOS/bootloader by default: it always loads the kernel itself,
	// so unlike QEMU we cannot boot a kernel installed inside the image.
	if cfg.Kernel == "" {
		return nil, fmt.Errorf("crosvm requires the kernel config param")
	}
	if !osutil.IsExist(cfg.Kernel) {
		return nil, fmt.Errorf("kernel file '%v' does not exist", cfg.Kernel)
	}
	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
	}
	// Note: crosvm's qcow2 implementation rejects compressed clusters ("compressed blocks
	// not supported"), which most distributed cloud images use. Such an image has to be
	// converted first, e.g. with "qemu-img convert -O qcow2 in.qcow2 out.qcow2".
	cfg.Kernel = osutil.Abs(cfg.Kernel)
	if cfg.Initrd != "" {
		// Catch this here: a missing initrd otherwise surfaces as a guest that
		// boots and then cannot find its root filesystem, which is a much
		// harder failure to read.
		if !osutil.IsExist(cfg.Initrd) {
			return nil, fmt.Errorf("initrd file '%v' does not exist", cfg.Initrd)
		}
		cfg.Initrd = osutil.Abs(cfg.Initrd)
	}

	// "crosvm --version" does not exist, the version is printed by the "version" subcommand.
	output, err := osutil.RunCmd(time.Minute, "", cfg.Crosvm, "version")
	if err != nil {
		return nil, err
	}
	pool := &Pool{
		env:     env,
		cfg:     cfg,
		target:  targets.Get(env.OS, env.Arch),
		version: strings.TrimSpace(string(output)),
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inst := &instance{
		index:    index,
		cfg:      pool.cfg,
		target:   pool.target,
		version:  pool.version,
		image:    pool.env.Image,
		debug:    pool.env.Debug,
		os:       pool.env.OS,
		timeouts: pool.env.Timeouts,
		workdir:  workdir,
		sock:     filepath.Join(workdir, "crosvm.sock"),
		SSHOptions: vmimpl.SSHOptions{
			// crosvm has no user mode networking on Linux (its slirp backend is
			// Windows only), so we always talk to the guest over the tap network.
			Port: 22,
			Key:  pool.env.SSHKey,
			User: pool.env.SSHUser,
		},
	}
	if pool.env.Snapshot {
		inst.snapshot = new(snapshot)
	}
	inst.hostIP, inst.Addr = pool.cfg.addresses(index)

	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := inst.setupImage(); err != nil {
		return nil, err
	}
	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}
	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

// maxComputedNets is the number of distinct /24 networks we can hand out automatically
// (192.<net_base>.100.0/24 .. 192.<net_base>.227.0/24).
const maxComputedNets = 128

// addresses returns the host and guest IP addresses of the VM with the given index.
// The configured addresses may contain "{{INDEX}}", which is how a pool of VMs on
// pre-created tap devices gets one address per VM.
func (cfg *Config) addresses(index int) (hostIP, guestIP string) {
	hostIP, guestIP = expandIndex(cfg.HostIP, index), expandIndex(cfg.GuestIP, index)
	if hostIP == "" {
		hostIP = fmt.Sprintf("192.%v.%v.1", cfg.NetBase, 100+index)
	}
	if guestIP == "" {
		guestIP = fmt.Sprintf("192.%v.%v.2", cfg.NetBase, 100+index)
	}
	return
}

func expandIndex(str string, index int) string {
	return strings.ReplaceAll(str, "{{INDEX}}", fmt.Sprint(index))
}

// mac returns a locally administered unicast MAC address unique to the VM index.
func mac(index int) string {
	return fmt.Sprintf("02:00:00:00:%02x:%02x", index/256, index%256)
}

// setupImage prepares the disk image the VM boots from. By default every VM gets its own
// qcow2 overlay over the base image, so that VMs neither corrupt the image nor each other.
func (inst *instance) setupImage() error {
	if !inst.cfg.Overlay {
		return nil
	}
	overlay := filepath.Join(inst.workdir, "image.qcow2")
	// crosvm refuses to create the overlay if the file already exists.
	os.Remove(overlay)
	if _, err := osutil.RunCmd(time.Minute*inst.timeouts.Scale, "", inst.cfg.Crosvm,
		"create_qcow2", "--backing-file", osutil.Abs(inst.image), overlay); err != nil {
		return fmt.Errorf("failed to create image overlay: %w", err)
	}
	inst.image = overlay
	return nil
}

func (inst *instance) boot() error {
	args, err := inst.buildCrosvmArgs()
	if err != nil {
		return err
	}
	if inst.debug {
		log.Logf(0, "running command: %v %#v", inst.cfg.Crosvm, args)
	}
	inst.args = args
	crosvm := osutil.Command(inst.cfg.Crosvm, args...)
	crosvm.Stdout = inst.wpipe
	crosvm.Stderr = inst.wpipe
	if err := crosvm.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %w", inst.cfg.Crosvm, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.crosvm = crosvm

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("crosvm", vmimpl.OutputConsole, inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out.Data...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := vmimpl.WaitForSSH(10*time.Minute*inst.timeouts.Scale, inst.SSHOptions,
		inst.os, inst.merger.Errors(ctx), false, inst.debug); err != nil {
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.MakeBootError(err, bootOutput)
	}
	bootOutputStop <- true
	return nil
}

func (inst *instance) buildCrosvmArgs() ([]string, error) {
	args := []string{
		"run",
		"--socket", inst.sock,
		"--cpus", fmt.Sprintf("num-cores=%v", inst.cfg.CPU),
		"--mem", fmt.Sprintf("size=%v", inst.cfg.Mem),
		// crosvm exits instead of rebooting, which is what we want: a rebooting VM
		// is a lost VM as far as syzkaller is concerned.
		"--serial", "type=stdout,hardware=serial,console=true,earlycon=true,stdin=false",
		"--no-usb",
	}
	if inst.cfg.DisableSandbox {
		args = append(args, "--disable-sandbox")
	}
	args = append(args, "--net", inst.netArg())
	args = append(args, "--block", fmt.Sprintf("path=%v", osutil.Abs(inst.image)))
	if inst.cfg.Initrd != "" {
		args = append(args, "--initrd", inst.cfg.Initrd)
	}
	if inst.snapshot != nil {
		snapshotArgs, err := inst.snapshotEnable()
		if err != nil {
			return nil, err
		}
		args = append(args, snapshotArgs...)
	}
	args = append(args, splitArgs(inst.cfg.CrosvmArgs, inst.index)...)
	args = append(args, "--params", inst.cmdline())
	// The kernel is a positional argument and must come last.
	args = append(args, inst.cfg.Kernel)
	return args, nil
}

func (inst *instance) netArg() string {
	if inst.cfg.TapName != "" {
		return fmt.Sprintf("tap-name=%v,mac=%v", expandIndex(inst.cfg.TapName, inst.index), mac(inst.index))
	}
	// In this mode crosvm creates and configures a vmtap device itself, which needs
	// CAP_NET_ADMIN. See docs/linux/setup_linux-host_crosvm-vm_x86-64-kernel.md.
	return fmt.Sprintf("host-ip=%v,netmask=%v,mac=%v", inst.hostIP, inst.cfg.Netmask, mac(inst.index))
}

func (inst *instance) cmdline() string {
	cmdline := []string{
		"root=" + inst.cfg.RootDevice,
		"console=ttyS0",
		// crosvm does not run a DHCP server for the tap device, so the guest address is
		// configured by the kernel itself (needs CONFIG_IP_PNP=y). The trailing fields are
		// gateway, netmask, hostname, device and autoconf.
		fmt.Sprintf("ip=%v::%v:%v::%v:off", inst.Addr, inst.hostIP, inst.cfg.Netmask, inst.cfg.NetDevice),
	}
	if inst.cfg.Cmdline != "" {
		cmdline = append(cmdline, inst.cfg.Cmdline)
	}
	return strings.Join(cmdline, " ")
}

func splitArgs(str string, index int) (args []string) {
	for _, arg := range strings.Fields(str) {
		args = append(args, expandIndex(arg, index))
	}
	return
}

func (inst *instance) Close() error {
	if inst.crosvm != nil {
		// Ask crosvm to shut down cleanly first so that it releases the tap device
		// and unlinks the control socket, then make sure it is gone. A hung VM must not
		// hold up the shutdown, so this gets a much shorter timeout than other commands.
		inst.control(10*time.Second, "stop")
		inst.crosvm.Process.Kill()
		inst.crosvm.Wait()
		inst.crosvm = nil
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
	if inst.snapshot != nil {
		inst.snapshotClose()
	}
	return nil
}

// control runs a crosvm control subcommand against this instance's control socket.
func (inst *instance) control(timeout time.Duration, args ...string) ([]byte, error) {
	if inst.debug {
		log.Logf(0, "crosvm: running control command: %v", args)
	}
	args = append(args, inst.sock)
	output, err := osutil.RunCmd(timeout, "", inst.cfg.Crosvm, args...)
	if inst.debug {
		log.Logf(0, "crosvm: reply: %v\n%s", err, output)
	}
	if err != nil {
		return nil, fmt.Errorf("crosvm control command %q: %w", args, err)
	}
	return output, nil
}

// controlRetry is control() for commands issued right after crosvm was started, when the
// control socket may not exist or may not be listening yet.
func (inst *instance) controlRetry(timeout time.Duration, args ...string) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		output, err := inst.control(timeout, args...)
		if err == nil {
			return output, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		if inst.crosvm != nil && inst.crosvm.ProcessState != nil {
			return nil, fmt.Errorf("crosvm exited before accepting %q: %w", args, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/crosvm: forward port is zero")
	}
	// The guest reaches the host over the tap device.
	return fmt.Sprintf("%v:%v", inst.hostIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	err := vmimpl.SCP(hostSrc, vmDst, vmimpl.SCPOptions{
		Debug:         inst.debug,
		Key:           inst.Key,
		Port:          inst.Port,
		SystemSSHCfg:  false,
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

	args := []string{"ssh"}
	args = append(args, vmimpl.SSHArgs(inst.debug, inst.Key, inst.Port, false)...)
	args = append(args, inst.User+"@"+inst.Addr, "cd / && "+command)
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}
	cmd := osutil.Command(args[0], args[1:]...)
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
	info := fmt.Sprintf("%v\n%v %q\n", inst.version, inst.cfg.Crosvm, inst.args)
	return []byte(info), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	if output, wait, handled := vmimpl.DiagnoseLinux(rep, inst.ssh); handled {
		return output, wait
	}
	return nil, false
}

func (inst *instance) ssh(args ...string) ([]byte, error) {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.Key, inst.Port, false), inst.User+"@"+inst.Addr)
	return osutil.RunCmd(time.Minute*inst.timeouts.Scale, "", "ssh", append(sshArgs, args...)...)
}
