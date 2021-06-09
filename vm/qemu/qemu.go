// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"bytes"
	"encoding/json"
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
	var _ vmimpl.Infoer = (*instance)(nil)
	vmimpl.Register("qemu", ctor, true)
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
	// QEMU binary name (optional).
	// If not specified, qemu-system-arch is used by default.
	Qemu string `json:"qemu"`
	// Additional command line arguments for the QEMU binary.
	// If not specified, the default value specifies machine type, cpu and usually contains -enable-kvm.
	// If you provide this parameter, it needs to contain the desired machine, cpu
	// and include -enable-kvm if necessary.
	// "{{INDEX}}" is replaced with 0-based index of the VM (from 0 to Count-1).
	// "{{TEMPLATE}}" is replaced with the path to a copy of workdir/template dir.
	// "{{TCP_PORT}}" is replaced with a random free TCP port
	QemuArgs string `json:"qemu_args"`
	// Location of the kernel for injected boot (e.g. arch/x86/boot/bzImage, optional).
	// This is passed to QEMU as the -kernel option.
	Kernel string `json:"kernel"`
	// Additional command line options for the booting kernel, for example `root=/dev/sda1`.
	// Can only be specified with kernel.
	Cmdline string `json:"cmdline"`
	// Initial ramdisk, passed via -initrd QEMU flag (optional).
	Initrd string `json:"initrd"`
	// QEMU image device.
	// The default value "hda" is transformed to "-hda image" for QEMU.
	// The modern way of describing QEMU hard disks is supported, so the value
	// "drive index=0,media=disk,file=" is transformed to "-drive index=0,media=disk,file=image" for QEMU.
	ImageDevice string `json:"image_device"`
	// QEMU network device type to use.
	// If not specified, some default per-arch value will be used.
	// See the full list with qemu-system-x86_64 -device help.
	NetDev string `json:"network_device"`
	// Number of VM CPUs (1 by default).
	CPU int `json:"cpu"`
	// Amount of VM memory in MiB (1024 by default).
	Mem int `json:"mem"`
	// For building kernels without -snapshot for pkg/build (true by default).
	Snapshot bool `json:"snapshot"`
}

type Pool struct {
	env        *vmimpl.Env
	cfg        *Config
	target     *targets.Target
	archConfig *archConfig
	version    string
}

type instance struct {
	index       int
	cfg         *Config
	target      *targets.Target
	archConfig  *archConfig
	version     string
	args        []string
	image       string
	debug       bool
	os          string
	workdir     string
	sshkey      string
	sshuser     string
	timeouts    targets.Timeouts
	port        int
	monport     int
	forwardPort int
	mon         net.Conn
	monEnc      *json.Encoder
	monDec      *json.Decoder
	rpipe       io.ReadCloser
	wpipe       io.WriteCloser
	qemu        *exec.Cmd
	merger      *vmimpl.OutputMerger
	files       map[string]string
	diagnose    chan bool
}

type archConfig struct {
	Qemu      string
	QemuArgs  string
	TargetDir string // "/" by default
	NetDev    string // default network device type (see the full list with qemu-system-x86_64 -device help)
	RngDev    string // default rng device (optional)
	// UseNewQemuImageOptions specifies whether the arch uses "new" QEMU image device options.
	UseNewQemuImageOptions bool
	CmdLine                []string
}

var archConfigs = map[string]*archConfig{
	"linux/amd64": {
		Qemu:     "qemu-system-x86_64",
		QemuArgs: "-enable-kvm -cpu host,migratable=off",
		// e1000e fails on recent Debian distros with:
		// Initialization of device e1000e failed: failed to find romfile "efi-e1000e.rom
		// But other arches don't use e1000e, e.g. arm64 uses virtio by default.
		NetDev: "e1000",
		RngDev: "virtio-rng-pci",
		CmdLine: []string{
			"root=/dev/sda",
			"console=ttyS0",
		},
	},
	"linux/386": {
		Qemu:   "qemu-system-i386",
		NetDev: "e1000",
		RngDev: "virtio-rng-pci",
		CmdLine: []string{
			"root=/dev/sda",
			"console=ttyS0",
		},
	},
	"linux/arm64": {
		Qemu:     "qemu-system-aarch64",
		QemuArgs: "-machine virt,virtualization=on -cpu cortex-a57",
		NetDev:   "virtio-net-pci",
		RngDev:   "virtio-rng-pci",
		CmdLine: []string{
			"root=/dev/vda",
			"console=ttyAMA0",
		},
	},
	"linux/arm": {
		Qemu:                   "qemu-system-arm",
		QemuArgs:               "-machine vexpress-a15 -cpu max",
		NetDev:                 "virtio-net-device",
		RngDev:                 "virtio-rng-device",
		UseNewQemuImageOptions: true,
		CmdLine: []string{
			"root=/dev/vda",
			"console=ttyAMA0",
		},
	},
	"linux/mips64le": {
		Qemu:     "qemu-system-mips64el",
		QemuArgs: "-M malta -cpu MIPS64R2-generic -nodefaults",
		NetDev:   "e1000",
		RngDev:   "virtio-rng-pci",
		CmdLine: []string{
			"root=/dev/sda",
			"console=ttyS0",
		},
	},
	"linux/ppc64le": {
		Qemu:     "qemu-system-ppc64",
		QemuArgs: "-enable-kvm -vga none",
		NetDev:   "virtio-net-pci",
		RngDev:   "virtio-rng-pci",
	},
	"linux/riscv64": {
		Qemu:                   "qemu-system-riscv64",
		QemuArgs:               "-machine virt",
		NetDev:                 "virtio-net-pci",
		RngDev:                 "virtio-rng-pci",
		UseNewQemuImageOptions: true,
		CmdLine: []string{
			"root=/dev/vda",
			"console=ttyS0",
		},
	},
	"linux/s390x": {
		Qemu:     "qemu-system-s390x",
		QemuArgs: "-M s390-ccw-virtio -cpu max,zpci=on",
		NetDev:   "virtio-net-pci",
		RngDev:   "virtio-rng-ccw",
		CmdLine: []string{
			"root=/dev/vda",
		},
	},
	"freebsd/amd64": {
		Qemu:     "qemu-system-x86_64",
		QemuArgs: "-enable-kvm",
		NetDev:   "e1000",
		RngDev:   "virtio-rng-pci",
	},
	"darwin/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -machine q35 -cpu host,migratable=off",
		TargetDir: "/tmp",
		NetDev:    "e1000-82545em",
		RngDev:    "virtio-rng-pci",
	},
	"netbsd/amd64": {
		Qemu:     "qemu-system-x86_64",
		QemuArgs: "-enable-kvm",
		NetDev:   "e1000",
		RngDev:   "virtio-rng-pci",
	},
	"fuchsia/amd64": {
		Qemu:      "qemu-system-x86_64",
		QemuArgs:  "-enable-kvm -machine q35 -cpu host,migratable=off",
		TargetDir: "/tmp",
		NetDev:    "e1000",
		RngDev:    "virtio-rng-pci",
		CmdLine: []string{
			"kernel.serial=legacy",
			"kernel.halt-on-panic=true",
		},
	},
	"akaros/amd64": {
		Qemu:     "qemu-system-x86_64",
		QemuArgs: "-enable-kvm -cpu host,migratable=off",
		NetDev:   "e1000",
		RngDev:   "virtio-rng-pci",
	},
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	archConfig := archConfigs[env.OS+"/"+env.Arch]
	cfg := &Config{
		Count:       1,
		CPU:         1,
		Mem:         1024,
		ImageDevice: "hda",
		Qemu:        archConfig.Qemu,
		QemuArgs:    archConfig.QemuArgs,
		NetDev:      archConfig.NetDev,
		Snapshot:    true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse qemu vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}
	if _, err := exec.LookPath(cfg.Qemu); err != nil {
		return nil, err
	}
	if env.Image == "9p" {
		if env.OS != targets.Linux {
			return nil, fmt.Errorf("9p image is supported for linux only")
		}
		if cfg.Kernel == "" {
			return nil, fmt.Errorf("9p image requires kernel")
		}
	} else {
		if !osutil.IsExist(env.Image) {
			return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
		}
	}
	if cfg.CPU <= 0 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("bad qemu cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("bad qemu mem: %v, want [128-1048576]", cfg.Mem)
	}
	cfg.Kernel = osutil.Abs(cfg.Kernel)
	cfg.Initrd = osutil.Abs(cfg.Initrd)

	output, err := osutil.RunCmd(time.Minute, "", cfg.Qemu, "--version")
	if err != nil {
		return nil, err
	}
	version := string(bytes.Split(output, []byte{'\n'})[0])

	pool := &Pool{
		env:        env,
		cfg:        cfg,
		version:    version,
		target:     targets.Get(env.OS, env.Arch),
		archConfig: archConfig,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser
	if pool.env.Image == "9p" {
		sshkey = filepath.Join(workdir, "key")
		sshuser = "root"
		if _, err := osutil.RunCmd(10*time.Minute, "", "ssh-keygen", "-t", "rsa", "-b", "2048",
			"-N", "", "-C", "", "-f", sshkey); err != nil {
			return nil, err
		}
		initFile := filepath.Join(workdir, "init.sh")
		if err := osutil.WriteExecFile(initFile, []byte(strings.Replace(initScript, "{{KEY}}", sshkey, -1))); err != nil {
			return nil, fmt.Errorf("failed to create init file: %v", err)
		}
	}

	for i := 0; ; i++ {
		inst, err := pool.ctor(workdir, sshkey, sshuser, index)
		if err == nil {
			return inst, nil
		}
		// Older qemu prints "could", newer -- "Could".
		if i < 1000 && strings.Contains(err.Error(), "ould not set up host forwarding rule") {
			continue
		}
		return nil, err
	}
}

func (pool *Pool) ctor(workdir, sshkey, sshuser string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		index:      index,
		cfg:        pool.cfg,
		target:     pool.target,
		archConfig: pool.archConfig,
		version:    pool.version,
		image:      pool.env.Image,
		debug:      pool.env.Debug,
		os:         pool.env.OS,
		timeouts:   pool.env.Timeouts,
		workdir:    workdir,
		sshkey:     sshkey,
		sshuser:    sshuser,
		diagnose:   make(chan bool, 1),
	}
	if st, err := os.Stat(inst.image); err != nil && st.Size() == 0 {
		// Some kernels may not need an image, however caller may still
		// want to pass us a fake empty image because the rest of syzkaller
		// assumes that an image is mandatory. So if the image is empty, we ignore it.
		inst.image = ""
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

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

func (inst *instance) Close() {
	if inst.qemu != nil {
		inst.qemu.Process.Kill()
		inst.qemu.Wait()
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
	if inst.mon != nil {
		inst.mon.Close()
	}
}

func (inst *instance) boot() error {
	inst.port = vmimpl.UnusedTCPPort()
	inst.monport = vmimpl.UnusedTCPPort()
	args := []string{
		"-m", strconv.Itoa(inst.cfg.Mem),
		"-smp", strconv.Itoa(inst.cfg.CPU),
		"-chardev", fmt.Sprintf("socket,id=SOCKSYZ,server=on,nowait,host=localhost,port=%v", inst.monport),
		"-mon", "chardev=SOCKSYZ,mode=control",
		"-display", "none",
		"-serial", "stdio",
		"-no-reboot",
		"-name", fmt.Sprintf("VM-%v", inst.index),
	}
	if inst.archConfig.RngDev != "" {
		args = append(args, "-device", inst.archConfig.RngDev)
	}
	templateDir := filepath.Join(inst.workdir, "template")
	args = append(args, splitArgs(inst.cfg.QemuArgs, templateDir, inst.index)...)
	args = append(args,
		"-device", inst.cfg.NetDev+",netdev=net0",
		"-netdev", fmt.Sprintf("user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:%v-:22", inst.port))
	if inst.image == "9p" {
		args = append(args,
			"-fsdev", "local,id=fsdev0,path=/,security_model=none,readonly",
			"-device", "virtio-9p-pci,fsdev=fsdev0,mount_tag=/dev/root",
		)
	} else if inst.image != "" {
		if inst.archConfig.UseNewQemuImageOptions {
			args = append(args,
				"-device", "virtio-blk-device,drive=hd0",
				"-drive", fmt.Sprintf("file=%v,if=none,format=raw,id=hd0", inst.image),
			)
		} else {
			// inst.cfg.ImageDevice can contain spaces
			imgline := strings.Split(inst.cfg.ImageDevice, " ")
			imgline[0] = "-" + imgline[0]
			if strings.HasSuffix(imgline[len(imgline)-1], "file=") {
				imgline[len(imgline)-1] = imgline[len(imgline)-1] + inst.image
			} else {
				imgline = append(imgline, inst.image)
			}
			args = append(args, imgline...)
		}
		if inst.cfg.Snapshot {
			args = append(args, "-snapshot")
		}
	}
	if inst.cfg.Initrd != "" {
		args = append(args,
			"-initrd", inst.cfg.Initrd,
		)
	}
	if inst.cfg.Kernel != "" {
		cmdline := append([]string{}, inst.archConfig.CmdLine...)
		if inst.image == "9p" {
			cmdline = append(cmdline,
				"root=/dev/root",
				"rootfstype=9p",
				"rootflags=trans=virtio,version=9p2000.L,cache=loose",
				"init="+filepath.Join(inst.workdir, "init.sh"),
			)
		}
		cmdline = append(cmdline, inst.cfg.Cmdline)
		args = append(args,
			"-kernel", inst.cfg.Kernel,
			"-append", strings.Join(cmdline, " "),
		)
	}
	if inst.debug {
		log.Logf(0, "running command: %v %#v", inst.cfg.Qemu, args)
	}
	inst.args = args
	qemu := osutil.Command(inst.cfg.Qemu, args...)
	qemu.Stdout = inst.wpipe
	qemu.Stderr = inst.wpipe
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %v", inst.cfg.Qemu, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.qemu = qemu
	// Qemu has started.

	// Start output merger.
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("qemu", inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()
	if err := vmimpl.WaitForSSH(inst.debug, 10*time.Minute*inst.timeouts.Scale, "localhost",
		inst.sshkey, inst.sshuser, inst.os, inst.port, inst.merger.Err); err != nil {
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.MakeBootError(err, bootOutput)
	}
	bootOutputStop <- true
	return nil
}

func splitArgs(str, templateDir string, index int) (args []string) {
	for _, arg := range strings.Split(str, " ") {
		if arg == "" {
			continue
		}
		arg = strings.ReplaceAll(arg, "{{INDEX}}", fmt.Sprint(index))
		arg = strings.ReplaceAll(arg, "{{TEMPLATE}}", templateDir)
		const tcpPort = "{{TCP_PORT}}"
		if strings.Contains(arg, tcpPort) {
			arg = strings.ReplaceAll(arg, tcpPort, fmt.Sprint(vmimpl.UnusedTCPPort()))
		}
		args = append(args, arg)
	}
	return
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/qemu: forward port is zero")
	}
	if !inst.target.HostFuzzer {
		if inst.forwardPort != 0 {
			return "", fmt.Errorf("vm/qemu: forward port already set")
		}
		inst.forwardPort = port
	}
	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *instance) targetDir() string {
	if inst.image == "9p" {
		return "/tmp"
	}
	if inst.archConfig.TargetDir == "" {
		return "/"
	}
	return inst.archConfig.TargetDir
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join(inst.targetDir(), base)
	if inst.target.HostFuzzer {
		if base == "syz-fuzzer" || base == "syz-execprog" {
			return hostSrc, nil // we will run these on host
		}
		if inst.files == nil {
			inst.files = make(map[string]string)
		}
		inst.files[vmDst] = hostSrc
	}

	args := append(vmimpl.SCPArgs(inst.debug, inst.sshkey, inst.port),
		hostSrc, inst.sshuser+"@localhost:"+vmDst)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}
	_, err := osutil.RunCmd(10*time.Minute*inst.timeouts.Scale, "", "scp", args...)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	inst.merger.Add("ssh", rpipe)

	sshArgs := vmimpl.SSHArgsForward(inst.debug, inst.sshkey, inst.port, inst.forwardPort)
	args := strings.Split(command, " ")
	if bin := filepath.Base(args[0]); inst.target.HostFuzzer &&
		(bin == "syz-fuzzer" || bin == "syz-execprog") {
		// Weird mode for fuchsia and akaros.
		// Fuzzer and execprog are on host (we did not copy them), so we will run them as is,
		// but we will also wrap executor with ssh invocation.
		for i, arg := range args {
			if strings.HasPrefix(arg, "-executor=") {
				args[i] = "-executor=" + "/usr/bin/ssh " + strings.Join(sshArgs, " ") +
					" " + inst.sshuser + "@localhost " + arg[len("-executor="):]
			}
			if host := inst.files[arg]; host != "" {
				args[i] = host
			}
		}
	} else {
		args = []string{"ssh"}
		args = append(args, sshArgs...)
		args = append(args, inst.sshuser+"@localhost", "cd "+inst.targetDir()+" && "+command)
	}
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}
	cmd := osutil.Command(args[0], args[1:]...)
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
	info := fmt.Sprintf("%v\n%v %q\n", inst.version, inst.cfg.Qemu, inst.args)
	return []byte(info), nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	if inst.target.OS == targets.Linux {
		if output, wait, handled := vmimpl.DiagnoseLinux(rep, inst.ssh); handled {
			return output, wait
		}
	}
	// TODO: we don't need registers on all reports. Probably only relevant for "crashes"
	// (NULL derefs, paging faults, etc), but is not useful for WARNING/BUG/HANG (?).
	ret := []byte(fmt.Sprintf("%s Registers:\n", time.Now().Format("15:04:05 ")))
	for cpu := 0; cpu < inst.cfg.CPU; cpu++ {
		regs, err := inst.hmp("info registers", cpu)
		if err == nil {
			ret = append(ret, []byte(fmt.Sprintf("info registers vcpu %v\n", cpu))...)
			ret = append(ret, []byte(regs)...)
		} else {
			log.Logf(0, "VM-%v failed reading regs: %v", inst.index, err)
			ret = append(ret, []byte(fmt.Sprintf("Failed reading regs: %v\n", err))...)
		}
	}
	return ret, false
}

func (inst *instance) ssh(args ...string) ([]byte, error) {
	return osutil.RunCmd(time.Minute*inst.timeouts.Scale, "", "ssh", inst.sshArgs(args...)...)
}

func (inst *instance) sshArgs(args ...string) []string {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.sshkey, inst.port), inst.sshuser+"@localhost")
	return append(sshArgs, args...)
}

// nolint: lll
const initScript = `#! /bin/bash
set -eux
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs nodev /sys/kernel/debug/
mount -t tmpfs none /tmp
mount -t tmpfs none /var
mount -t tmpfs none /run
mount -t tmpfs none /etc
mount -t tmpfs none /root
touch /etc/fstab
mkdir /etc/network
mkdir /run/network
printf 'auto lo\niface lo inet loopback\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet static\naddress 10.0.2.15\nnetmask 255.255.255.0\nnetwork 10.0.2.0\ngateway 10.0.2.1\nbroadcast 10.0.2.255\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet6 static\naddress fe80::5054:ff:fe12:3456/64\ngateway 2000:da8:203:612:0:3:0:1\n\n' >> /etc/network/interfaces
mkdir -p /etc/network/if-pre-up.d
mkdir -p /etc/network/if-up.d
ifup lo
ifup eth0 || true
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/
chmod 0700 /root
chmod 0600 /root/key.pub
mkdir -p /var/run/sshd/
chmod 700 /var/run/sshd
groupadd -g 33 sshd
useradd -u 33 -g 33 -c sshd -d / sshd
cat > /etc/ssh/sshd_config <<EOF
          Port 22
          Protocol 2
          UsePrivilegeSeparation no
          HostKey {{KEY}}
          PermitRootLogin yes
          AuthenticationMethods publickey
          ChallengeResponseAuthentication no
          AuthorizedKeysFile /root/key.pub
          IgnoreUserKnownHosts yes
          AllowUsers root
          LogLevel INFO
          TCPKeepAlive yes
          RSAAuthentication yes
          PubkeyAuthentication yes
EOF
/usr/sbin/sshd -e -D
/sbin/halt -f
`
