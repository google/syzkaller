// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gvisor provides support for gVisor, user-space kernel, testing.
// See https://github.com/google/gvisor
package gvisor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	vmimpl.Register(targets.GVisor, vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	Count            int    `json:"count"` // number of VMs to use
	RunscArgs        string `json:"runsc_args"`
	MemoryTotalBytes uint64 `json:"memory_total_bytes"`
	CPUs             uint64 `json:"cpus"`
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg      *Config
	image    string
	debug    bool
	rootDir  string
	imageDir string
	name     string
	port     int
	cmd      *exec.Cmd
	merger   *vmimpl.OutputMerger
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count: 1,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vm config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 128 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 128]", cfg.Count)
	}
	hostTotalMemory := osutil.SystemMemorySize()
	minMemory := uint64(cfg.Count) * 10_000_000
	if cfg.MemoryTotalBytes != 0 && (cfg.MemoryTotalBytes < minMemory || cfg.MemoryTotalBytes > hostTotalMemory) {
		return nil, fmt.Errorf("invalid config param memory_total_bytes: %v, want [%d,%d]",
			minMemory, cfg.MemoryTotalBytes, hostTotalMemory)
	}
	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file %q does not exist", env.Image)
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

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	rootDir := filepath.Clean(filepath.Join(workdir, "..", "gvisor_root"))
	imageDir := filepath.Join(workdir, "image")
	bundleDir := filepath.Join(workdir, "bundle")
	osutil.MkdirAll(rootDir)
	osutil.MkdirAll(bundleDir)
	osutil.MkdirAll(imageDir)

	caps := ""
	for _, c := range sandboxCaps {
		if caps != "" {
			caps += ", "
		}
		caps += "\"" + c + "\""
	}
	name := fmt.Sprintf("%v-%v", pool.env.Name, index)
	memoryLimit := int64(pool.cfg.MemoryTotalBytes / uint64(pool.Count()))
	if pool.cfg.MemoryTotalBytes == 0 {
		memoryLimit = -1
	}
	cpuPeriod := uint64(100000)
	cpus := pool.cfg.CPUs
	if cpus == 0 {
		cpus = uint64(runtime.NumCPU())
	}
	cpuLimit := cpuPeriod * cpus
	vmConfig := fmt.Sprintf(configTempl, imageDir, caps, name, memoryLimit, cpuLimit, cpuPeriod)
	if err := osutil.WriteFile(filepath.Join(bundleDir, "config.json"), []byte(vmConfig)); err != nil {
		return nil, err
	}
	bin, err := exec.LookPath(os.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %v: %w", os.Args[0], err)
	}
	if err := osutil.CopyFile(bin, filepath.Join(imageDir, "init")); err != nil {
		return nil, err
	}

	panicLog := filepath.Join(bundleDir, "panic.fifo")
	if err := syscall.Mkfifo(panicLog, 0666); err != nil {
		return nil, err
	}
	defer syscall.Unlink(panicLog)

	// Open the fifo for read-write to be able to open for read-only
	// without blocking.
	panicLogWriteFD, err := os.OpenFile(panicLog, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer panicLogWriteFD.Close()

	panicLogReadFD, err := os.Open(panicLog)
	if err != nil {
		return nil, err
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		panicLogReadFD.Close()
		return nil, err
	}
	var tee io.Writer
	if pool.env.Debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("runsc", vmimpl.OutputConsole, rpipe)
	merger.Add("runsc-goruntime", vmimpl.OutputConsole, panicLogReadFD)

	inst := &instance{
		cfg:      pool.cfg,
		image:    pool.env.Image,
		debug:    pool.env.Debug,
		rootDir:  rootDir,
		imageDir: imageDir,
		name:     name,
		merger:   merger,
	}

	// Kill the previous instance in case it's still running.
	osutil.Run(time.Minute, inst.runscCmd("delete", "-force", inst.name))
	time.Sleep(3 * time.Second)

	cmd := inst.runscCmd("--panic-log", panicLog, "--cpu-num-from-quota", "run", "-bundle", bundleDir, inst.name)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		panicLogWriteFD.Close()
		merger.Wait()
		return nil, err
	}
	inst.cmd = cmd
	wpipe.Close()

	if err := inst.waitBoot(); err != nil {
		panicLogWriteFD.Close()
		inst.Close()
		return nil, err
	}
	return inst, nil
}

func (inst *instance) waitBoot() error {
	errorMsg := []byte("FATAL ERROR:")
	bootedMsg := []byte(initStartMsg)
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	var output []byte
	for {
		select {
		case out := <-inst.merger.Output:
			output = append(output, out.Data...)
			if pos := bytes.Index(output, errorMsg); pos != -1 {
				end := bytes.IndexByte(output[pos:], '\n')
				if end == -1 {
					end = len(output)
				} else {
					end += pos
				}
				return vmimpl.BootError{
					Title:  string(output[pos:end]),
					Output: output,
				}
			}
			if bytes.Contains(output, bootedMsg) {
				return nil
			}
		case err := <-inst.merger.Err:
			return vmimpl.BootError{
				Title:  fmt.Sprintf("runsc failed: %v", err),
				Output: output,
			}
		case <-timeout.C:
			return vmimpl.BootError{
				Title:  "init process did not start",
				Output: output,
			}
		}
	}
}

func (inst *instance) args() []string {
	args := []string{
		"-root", inst.rootDir,
		"-watchdog-action=panic",
		"-network=none",
		"-debug",
		// Send debug logs to stderr, so that they will be picked up by
		// syzkaller. Without this, debug logs are sent to /dev/null.
		"-debug-log=/dev/stderr",
	}
	if inst.cfg.RunscArgs != "" {
		args = append(args, strings.Split(inst.cfg.RunscArgs, " ")...)
	}
	return args
}

func (inst *instance) Info() ([]byte, error) {
	info := fmt.Sprintf("%v %v\n", inst.image, strings.Join(inst.args(), " "))
	return []byte(info), nil
}

func (inst *instance) runscCmd(add ...string) *exec.Cmd {
	cmd := osutil.Command(inst.image, append(inst.args(), add...)...)
	cmd.Env = []string{
		"GOTRACEBACK=all",
		"GORACE=halt_on_error=1",
		// New glibc-s enable rseq by default but ptrace and systrap
		// platforms don't work in this case. runsc is linked with libc
		// only when the race detector is enabled.
		"GLIBC_TUNABLES=glibc.pthread.rseq=0",
	}
	return cmd
}

func (inst *instance) Close() error {
	time.Sleep(3 * time.Second)
	osutil.Run(time.Minute, inst.runscCmd("delete", "-force", inst.name))
	inst.cmd.Process.Kill()
	inst.merger.Wait()
	inst.cmd.Wait()
	osutil.Run(time.Minute, inst.runscCmd("delete", "-force", inst.name))
	time.Sleep(3 * time.Second)
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.port != 0 {
		return "", fmt.Errorf("forward port is already setup")
	}
	inst.port = port
	return "stdin:0", nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	fname := filepath.Base(hostSrc)
	if err := osutil.CopyFile(hostSrc, filepath.Join(inst.imageDir, fname)); err != nil {
		return "", err
	}
	if err := os.Chmod(inst.imageDir, 0777); err != nil {
		return "", err
	}
	return filepath.Join("/", fname), nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	args := []string{"exec", "-user=0:0"}
	for _, c := range sandboxCaps {
		args = append(args, "-cap", c)
	}
	args = append(args, inst.name)
	args = append(args, strings.Split(command, " ")...)
	cmd := inst.runscCmd(args...)

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	defer wpipe.Close()
	inst.merger.Add("cmd", vmimpl.OutputCommand, rpipe)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe

	guestSock, err := inst.guestProxy()
	if err != nil {
		return nil, nil, err
	}
	if guestSock != nil {
		defer guestSock.Close()
		cmd.Stdin = guestSock
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		select {
		case <-ctx.Done():
			signal(vmimpl.ErrTimeout)
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
		log.Logf(1, "stopping %s", inst.name)
		w := make(chan bool)
		go func() {
			select {
			case <-w:
				return
			case <-time.After(time.Minute):
				cmd.Process.Kill()
			}
		}()
		osutil.Run(time.Minute, inst.runscCmd("kill", inst.name, "9"))
		err := cmd.Wait()
		close(w)
		log.Logf(1, "%s exited with %s", inst.name, err)
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) guestProxy() (*os.File, error) {
	if inst.port == 0 {
		return nil, nil
	}
	// One does not simply let gvisor guest connect to host tcp port.
	// We create a unix socket, pass it to guest in stdin.
	// Guest will use it instead of dialing manager directly.
	// On host we connect to manager tcp port and proxy between the tcp and unix connections.
	socks, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	hostSock := os.NewFile(uintptr(socks[0]), "host unix proxy")
	guestSock := os.NewFile(uintptr(socks[1]), "guest unix proxy")
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%v", inst.port))
	if err != nil {
		hostSock.Close()
		guestSock.Close()
		return nil, err
	}
	go func() {
		io.Copy(hostSock, conn)
		hostSock.Close()
	}()
	go func() {
		io.Copy(conn, hostSock)
		conn.Close()
	}()
	return guestSock, nil
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	// TODO: stacks and dmesg are mostly useful for hangs/stalls, so we could do this only sometimes based on rep.
	b, err := osutil.Run(time.Minute, inst.runscCmd("debug", "-stacks", "--ps", inst.name))
	if err != nil {
		b = append(b, fmt.Sprintf("\n\nError collecting stacks: %v", err)...)
	}
	b1, err := osutil.RunCmd(time.Minute, "", "dmesg")
	b = append(b, b1...)
	if err != nil {
		b = append(b, fmt.Sprintf("\n\nError collecting kernel logs: %v", err)...)
	}
	return b, false
}

func init() {
	if os.Getenv("SYZ_GVISOR_PROXY") != "" {
		fmt.Fprint(os.Stderr, initStartMsg)
		// If we do select{}, we can get a deadlock panic.
		for range time.NewTicker(time.Hour).C {
		}
	}
}

const initStartMsg = "SYZKALLER INIT STARTED\n"

const configTempl = `
{
	"root": {
		"path": "%[1]v",
		"readonly": true
	},
	"linux": {
		"cgroupsPath": "%[3]v",
		"resources": {
			"cpu": {
				"shares": 1024,
				"period": %[6]d,
				"quota": %[5]d
			},
			"memory": {
				"limit": %[4]d,
				"reservation": %[4]d,
				"disableOOMKiller": false
			}
		},
		"sysctl": {
			"fs.nr_open": "1048576"
		}
	},
	"process":{
		"args": ["/init"],
		"cwd": "/tmp",
		"env": ["SYZ_GVISOR_PROXY=1"],
		"capabilities": {
			"bounding": [%[2]v],
			"effective": [%[2]v],
			"inheritable": [%[2]v],
			"permitted": [%[2]v],
			"ambient": [%[2]v]
		}
	}
}
`

var sandboxCaps = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
	"CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
	"CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
	"CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
}
