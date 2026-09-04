// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package firecracker implements VMs based on Firecracker, the AWS microVM
// monitor (https://firecracker-microvm.github.io). See
// docs/linux/setup_linux-host_firecracker-vm_x86-64-kernel.md.
package firecracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	vmimpl.Register("firecracker", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
	// firecracker binary name ("firecracker" by default).
	Firecracker string `json:"firecracker"`
	// Location of the kernel to boot, e.g. arch/x86/boot/bzImage.
	// Firecracker always boots the kernel directly (no BIOS/bootloader), so this is mandatory.
	Kernel string `json:"kernel"`
	// Additional kernel command line arguments.
	// The root device, console and the static network configuration are added automatically.
	Cmdline string `json:"cmdline"`
	// Initial ramdisk (optional).
	Initrd string `json:"initrd"`
	// Root device as seen by the guest ("/dev/vda1" by default).
	// Firecracker exposes the first drive as virtio-blk, so the image is /dev/vda and its
	// first partition is /dev/vda1. Images without a partition table need "/dev/vda".
	RootDevice string `json:"root_device"`
	// Name of the guest network interface to configure from the kernel command line
	// ("eth0" by default, which requires net.ifnames=0 in the kernel command line).
	// An empty value configures all interfaces.
	NetDevice string `json:"network_device"`
	// Number of VM CPUs (1 by default).
	CPU int `json:"cpu"`
	// Amount of VM memory in MiB (1024 by default).
	Mem int `json:"mem"`
	// Name of a pre-created persistent tap device to use for networking (optional).
	// If empty, the backend creates and configures a tap device itself, which requires
	// CAP_NET_ADMIN. "{{INDEX}}" is replaced with the 0-based index of the VM.
	TapName string `json:"tap_name"`
	// Second octet of the per-VM /24 network (168 by default), i.e. VM with index N uses
	// 192.<net_base>.<100+N>.0/24 with the host at .1 and the guest at .2.
	NetBase int `json:"net_base"`
	// Host and guest IP addresses (optional).
	// These must be set when tap_name is used, and override the computed addresses otherwise.
	HostIP  string `json:"host_ip"`
	GuestIP string `json:"guest_ip"`
	Netmask string `json:"netmask"`
	// Attach virtio devices over a PCI transport instead of firecracker's default MMIO
	// transport (true by default). Firecracker's MMIO transport needs CONFIG_VIRTIO_MMIO=y
	// and CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y built into the guest; distro kernels
	// usually ship VIRTIO_MMIO as a module (unusable with no initrd) but VIRTIO_PCI=y,
	// so PCI is the portable default and matches what qemu/crosvm give the guest.
	EnablePCI bool `json:"enable_pci"`
	// Additional command line arguments for the firecracker binary.
	// "{{INDEX}}" is replaced with the 0-based index of the VM.
	FirecrackerArgs string `json:"firecracker_args"`
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
	timeouts    targets.Timeouts
	hostIP      string
	sock        string
	tapName     string
	tapCreated  bool
	rpipe       io.ReadCloser
	wpipe       io.WriteCloser
	firecracker *exec.Cmd
	merger      *vmimpl.OutputMerger
	*snapshot
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:       1,
		Firecracker: "firecracker",
		CPU:         1,
		Mem:         1024,
		RootDevice:  "/dev/vda1",
		NetDevice:   "eth0",
		NetBase:     168,
		Netmask:     "255.255.255.0",
		EnablePCI:   true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse firecracker vm config: %w", err)
	}
	if env.OS != targets.Linux {
		return nil, fmt.Errorf("firecracker supports only linux targets")
	}
	// Snapshot mode is not implemented for firecracker (see snapshot_unimpl.go), so
	// reject it here rather than letting SetupSnapshot fail mid-run.
	if env.Snapshot {
		return nil, fmt.Errorf("firecracker does not support snapshot mode")
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if cfg.CPU < 1 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("bad firecracker cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("bad firecracker mem: %v, want [128-1048576]", cfg.Mem)
	}
	if cfg.NetBase < 0 || cfg.NetBase > 255 {
		return nil, fmt.Errorf("bad firecracker net_base: %v, want [0-255]", cfg.NetBase)
	}
	if cfg.TapName != "" && (cfg.HostIP == "" || cfg.GuestIP == "") {
		return nil, fmt.Errorf("firecracker tap_name requires host_ip and guest_ip")
	}
	if cfg.TapName == "" && cfg.Count > maxComputedNets {
		return nil, fmt.Errorf("firecracker count %v needs more than the %v automatically assigned "+
			"networks, use tap_name instead", cfg.Count, maxComputedNets)
	}
	if _, err := exec.LookPath(cfg.Firecracker); err != nil {
		return nil, err
	}
	// setupImage always converts the base image to raw with qemu-img (firecracker
	// cannot read qcow2), so require it up front rather than failing per-VM at boot.
	if _, err := exec.LookPath("qemu-img"); err != nil {
		return nil, fmt.Errorf("firecracker needs qemu-img to convert the image to raw: %w", err)
	}
	// Firecracker has no BIOS/bootloader: it always loads the kernel itself, so unlike QEMU
	// we cannot boot a kernel installed inside the image.
	if cfg.Kernel == "" {
		return nil, fmt.Errorf("firecracker requires the kernel config param")
	}
	if !osutil.IsExist(cfg.Kernel) {
		return nil, fmt.Errorf("kernel file '%v' does not exist", cfg.Kernel)
	}
	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
	}
	cfg.Kernel = osutil.Abs(cfg.Kernel)
	if cfg.Initrd != "" {
		// Catch this here: a missing initrd otherwise surfaces as a guest that boots and
		// then cannot find its root filesystem, which is a much harder failure to read.
		if !osutil.IsExist(cfg.Initrd) {
			return nil, fmt.Errorf("initrd file '%v' does not exist", cfg.Initrd)
		}
		cfg.Initrd = osutil.Abs(cfg.Initrd)
	}

	output, err := osutil.RunCmd(time.Minute, "", cfg.Firecracker, "--version")
	if err != nil {
		return nil, err
	}
	pool := &Pool{
		env:     env,
		cfg:     cfg,
		target:  targets.Get(env.OS, env.Arch),
		version: strings.TrimSpace(strings.Split(string(output), "\n")[0]),
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
		sock:     filepath.Join(workdir, "firecracker.sock"),
		SSHOptions: vmimpl.SSHOptions{
			// Firecracker has no user mode networking, so we always talk to the guest
			// over the tap network.
			Port: 22,
			Key:  pool.env.SSHKey,
			User: pool.env.SSHUser,
		},
	}
	if pool.env.Snapshot {
		inst.snapshot = new(snapshot)
	}
	inst.hostIP, inst.Addr = pool.cfg.addresses(index)
	inst.tapName = expandIndex(pool.cfg.TapName, index)
	if inst.tapName == "" {
		inst.tapName = fmt.Sprintf("syz%v", index)
	}

	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := inst.setupImage(); err != nil {
		return nil, err
	}
	if err := inst.setupNetwork(); err != nil {
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

// setupImage prepares the disk image the VM boots from. Firecracker exposes drives as raw
// virtio-blk devices and cannot read qcow2, nor does it have a copy-on-write overlay like
// crosvm. So every VM gets its own raw copy of the base image (converted with qemu-img if
// the base is qcow2), so that VMs neither corrupt the base image nor each other.
func (inst *instance) setupImage() error {
	raw := filepath.Join(inst.workdir, "image.raw")
	os.Remove(raw)
	// qemu-img convert handles both qcow2 and raw inputs and always writes a raw output.
	if _, err := osutil.RunCmd(10*time.Minute*inst.timeouts.Scale, "", "qemu-img", "convert",
		"-O", "raw", osutil.Abs(inst.image), raw); err != nil {
		return fmt.Errorf("failed to convert image to raw for firecracker: %w", err)
	}
	inst.image = raw
	return nil
}

// setupNetwork creates and configures the host tap device firecracker attaches to, unless
// a pre-created device was named in the config. Firecracker, unlike crosvm, never creates
// the tap device itself, so we bring it up here. This needs CAP_NET_ADMIN; see
// docs/linux/setup_linux-host_firecracker-vm_x86-64-kernel.md.
func (inst *instance) setupNetwork() error {
	if inst.cfg.TapName != "" {
		// A pre-created persistent tap device is managed by the operator, not by us.
		return nil
	}
	// Remove a stale device from a previous crashed run, then recreate it.
	inst.runIP("link", "del", inst.tapName)
	if err := inst.runIPChecked("tuntap", "add", "dev", inst.tapName, "mode", "tap"); err != nil {
		return fmt.Errorf("failed to create tap device %v: %w", inst.tapName, err)
	}
	inst.tapCreated = true
	if err := inst.runIPChecked("addr", "add",
		fmt.Sprintf("%v/%v", inst.hostIP, maskBits(inst.cfg.Netmask)), "dev", inst.tapName); err != nil {
		return fmt.Errorf("failed to assign host ip to %v: %w", inst.tapName, err)
	}
	if err := inst.runIPChecked("link", "set", "dev", inst.tapName, "up"); err != nil {
		return fmt.Errorf("failed to bring up %v: %w", inst.tapName, err)
	}
	return nil
}

func (inst *instance) runIP(args ...string) error {
	_, err := osutil.RunCmd(time.Minute*inst.timeouts.Scale, "", "ip", args...)
	return err
}

func (inst *instance) runIPChecked(args ...string) error {
	if inst.debug {
		log.Logf(0, "firecracker: ip %v", strings.Join(args, " "))
	}
	return inst.runIP(args...)
}

// maskBits converts a dotted-decimal netmask (e.g. 255.255.255.0) to a prefix length,
// falling back to /24 if the value cannot be parsed as an IPv4 mask.
func maskBits(netmask string) int {
	const fallback = 24
	ip := net.ParseIP(netmask)
	if ip == nil {
		return fallback
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fallback
	}
	ones, _ := net.IPMask(ipv4).Size()
	if ones == 0 {
		return fallback
	}
	return ones
}

// fcConfig mirrors the subset of the firecracker JSON configuration we set. Field names
// match src/firecracker/swagger/firecracker.yaml, so this is equivalent to the sequence
// of PUT requests the API socket accepts before InstanceStart.
type fcConfig struct {
	BootSource    fcBootSource    `json:"boot-source"`
	Drives        []fcDrive       `json:"drives"`
	MachineConfig fcMachineConfig `json:"machine-config"`
	NetworkIfaces []fcNetIface    `json:"network-interfaces"`
}

type fcBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
	InitrdPath      string `json:"initrd_path,omitempty"`
}

type fcDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type fcMachineConfig struct {
	VcpuCount  int  `json:"vcpu_count"`
	MemSizeMib int  `json:"mem_size_mib"`
	Smt        bool `json:"smt"`
}

type fcNetIface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

// writeConfig writes the firecracker JSON config file that fully describes the microVM.
// Passing it via --config-file both configures and boots the VM, which avoids the extra
// round of PUT requests over the API socket that the manual flow uses.
func (inst *instance) writeConfig() (string, error) {
	cfg := fcConfig{
		BootSource: fcBootSource{
			KernelImagePath: inst.cfg.Kernel,
			BootArgs:        inst.cmdline(),
			InitrdPath:      inst.cfg.Initrd,
		},
		Drives: []fcDrive{{
			DriveID:    "rootfs",
			PathOnHost: osutil.Abs(inst.image),
			// Deliberately not the "root device" as far as firecracker is concerned:
			// marking it root makes firecracker append "root=/dev/vda rw" to the kernel
			// command line, which both duplicates and overrides our own "root=/dev/vda1"
			// (the last root= wins) and points at the whole disk instead of its first
			// partition. We add the correct root= in cmdline() ourselves.
			IsRootDevice: false,
			IsReadOnly:   false,
		}},
		MachineConfig: fcMachineConfig{
			VcpuCount:  inst.cfg.CPU,
			MemSizeMib: inst.cfg.Mem,
			Smt:        false,
		},
		NetworkIfaces: []fcNetIface{{
			IfaceID:     "eth0",
			GuestMAC:    mac(inst.index),
			HostDevName: inst.tapName,
		}},
	}
	data, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(inst.workdir, "firecracker.json")
	if err := osutil.WriteFile(path, data); err != nil {
		return "", err
	}
	return path, nil
}

func (inst *instance) cmdline() string {
	cmdline := []string{
		"root=" + inst.cfg.RootDevice,
		"console=ttyS0",
		// Firecracker runs no DHCP server, so the guest address is configured by the
		// kernel itself (needs CONFIG_IP_PNP=y). The trailing fields are gateway,
		// netmask, hostname, device and autoconf.
		fmt.Sprintf("ip=%v::%v:%v::%v:off", inst.Addr, inst.hostIP, inst.cfg.Netmask, inst.cfg.NetDevice),
		// A rebooting VM is a lost VM as far as syzkaller is concerned; make a panic/reboot
		// terminate firecracker instead.
		"reboot=k panic=-1",
	}
	if inst.cfg.Cmdline != "" {
		cmdline = append(cmdline, inst.cfg.Cmdline)
	}
	return strings.Join(cmdline, " ")
}

func (inst *instance) boot() error {
	cfgPath, err := inst.writeConfig()
	if err != nil {
		return err
	}
	// Firecracker refuses to start if the API socket already exists.
	os.Remove(inst.sock)
	args := []string{"--api-sock", inst.sock, "--config-file", cfgPath}
	if inst.cfg.EnablePCI {
		// Expose virtio devices over PCI so a guest with CONFIG_VIRTIO_PCI=y (but
		// VIRTIO_MMIO only modular) sees the root disk and NIC; see EnablePCI.
		args = append(args, "--enable-pci")
	}
	args = append(args, splitArgs(inst.cfg.FirecrackerArgs, inst.index)...)
	if inst.debug {
		log.Logf(0, "running command: %v %#v", inst.cfg.Firecracker, args)
	}
	inst.args = args
	firecracker := osutil.Command(inst.cfg.Firecracker, args...)
	firecracker.Stdout = inst.wpipe
	firecracker.Stderr = inst.wpipe
	if err := firecracker.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %w", inst.cfg.Firecracker, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.firecracker = firecracker

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("firecracker", vmimpl.OutputConsole, inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	// Copy the channel into a local so we can nil it out if it is ever closed
	// (e.g. the merger tears down before we send bootOutputStop). Receiving from
	// a closed channel returns immediately, so leaving the case enabled would
	// spin the goroutine at 100% CPU; a nil channel blocks forever and disables
	// the case instead.
	outChan := inst.merger.Output
	go func() {
		for {
			select {
			case out, ok := <-outChan:
				if !ok {
					outChan = nil
					continue
				}
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

func splitArgs(str string, index int) (args []string) {
	for _, arg := range strings.Fields(str) {
		args = append(args, expandIndex(arg, index))
	}
	return
}

func (inst *instance) Close() error {
	if inst.firecracker != nil {
		inst.firecracker.Process.Kill()
		inst.firecracker.Wait()
		inst.firecracker = nil
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
	os.Remove(inst.sock)
	// Only tear down a tap device we created ourselves; a pre-created persistent one
	// belongs to the operator.
	if inst.tapCreated {
		inst.runIP("link", "del", inst.tapName)
		inst.tapCreated = false
	}
	if inst.snapshot != nil {
		inst.snapshotClose()
	}
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/firecracker: forward port is zero")
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
	info := fmt.Sprintf("%v\n%v %q\n", inst.version, inst.cfg.Firecracker, inst.args)
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
