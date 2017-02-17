// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
)

type Config struct {
	Name     string // Instance name (used for identification and as GCE instance prefix)
	Http     string // TCP address to serve HTTP stats page (e.g. "localhost:50000")
	Rpc      string // TCP address to serve RPC for fuzzer processes (optional, only useful for type "none")
	Workdir  string
	Vmlinux  string
	Kernel   string // e.g. arch/x86/boot/bzImage
	Tag      string // arbitrary optional tag that is saved along with crash reports (e.g. kernel branch/commit)
	Cmdline  string // kernel command line
	Image    string // linux image for VMs
	Initrd   string // linux initial ramdisk. (optional)
	Cpu      int    // number of VM CPUs
	Mem      int    // amount of VM memory in MBs
	Sshkey   string // root ssh key for the image
	Bin      string // qemu/lkvm binary name
	Bin_Args string // additional command line arguments for qemu/lkvm binary
	Debug    bool   // dump all VM output to console
	Output   string // one of stdout/dmesg/file (useful only for local VM)

	Hub_Addr string
	Hub_Key  string

	Dashboard_Addr string
	Dashboard_Key  string

	Syzkaller string   // path to syzkaller checkout (syz-manager will look for binaries in bin subdir)
	Type      string   // VM type (qemu, kvm, local)
	Count     int      // number of VMs (don't secify for adb, instead specify devices)
	Devices   []string // device IDs for adb
	Procs     int      // number of parallel processes inside of every VM

	Sandbox string // type of sandbox to use during fuzzing:
	// "none": don't do anything special (has false positives, e.g. due to killing init)
	// "setuid": impersonate into user nobody (65534), default
	// "namespace": create a new namespace for fuzzer using CLONE_NEWNS/CLONE_NEWNET/CLONE_NEWPID/etc,
	//	requires building kernel with CONFIG_NAMESPACES, CONFIG_UTS_NS, CONFIG_USER_NS, CONFIG_PID_NS and CONFIG_NET_NS.

	Machine_Type string // GCE machine type (e.g. "n1-highcpu-2")

	Cover     bool // use kcov coverage (default: true)
	Leak      bool // do memory leak checking
	Reproduce bool // reproduce, localize and minimize crashers (on by default)

	Enable_Syscalls  []string
	Disable_Syscalls []string
	Suppressions     []string // don't save reports matching these regexps, but reboot VM after them
	Ignores          []string // completely ignore reports matching these regexps (don't save nor reboot)

	// Implementation details beyond this point.
	ParsedSuppressions []*regexp.Regexp `json:"-"`
	ParsedIgnores      []*regexp.Regexp `json:"-"`
}

func Parse(filename string) (*Config, map[int]bool, error) {
	if filename == "" {
		return nil, nil, fmt.Errorf("supply config in -config flag")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	return parse(data)
}

func parse(data []byte) (*Config, map[int]bool, error) {
	unknown, err := checkUnknownFields(data)
	if err != nil {
		return nil, nil, err
	}
	if unknown != "" {
		return nil, nil, fmt.Errorf("unknown field '%v' in config", unknown)
	}
	cfg := new(Config)
	cfg.Cover = true
	cfg.Reproduce = true
	cfg.Sandbox = "setuid"
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-fuzzer")); err != nil {
		return nil, nil, fmt.Errorf("bad config syzkaller param: can't find bin/syz-fuzzer")
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-executor")); err != nil {
		return nil, nil, fmt.Errorf("bad config syzkaller param: can't find bin/syz-executor")
	}
	if cfg.Http == "" {
		return nil, nil, fmt.Errorf("config param http is empty")
	}
	if cfg.Workdir == "" {
		return nil, nil, fmt.Errorf("config param workdir is empty")
	}
	if cfg.Vmlinux == "" {
		return nil, nil, fmt.Errorf("config param vmlinux is empty")
	}
	if cfg.Type == "" {
		return nil, nil, fmt.Errorf("config param type is empty")
	}
	switch cfg.Type {
	case "none":
		if cfg.Count != 0 {
			return nil, nil, fmt.Errorf("invalid config param count: %v, type \"none\" does not support param count", cfg.Count)
		}
		if cfg.Rpc == "" {
			return nil, nil, fmt.Errorf("config param rpc is empty (required for type \"none\")")
		}
		if len(cfg.Devices) != 0 {
			return nil, nil, fmt.Errorf("type %v does not support devices param", cfg.Type)
		}
	case "adb":
		if cfg.Count != 0 {
			return nil, nil, fmt.Errorf("don't specify count for adb, instead specify devices")
		}
		if len(cfg.Devices) == 0 {
			return nil, nil, fmt.Errorf("specify at least 1 adb device")
		}
		cfg.Count = len(cfg.Devices)
	case "gce":
		if cfg.Machine_Type == "" {
			return nil, nil, fmt.Errorf("machine_type parameter is empty (required for gce)")
		}
		fallthrough
	default:
		if cfg.Count <= 0 || cfg.Count > 1000 {
			return nil, nil, fmt.Errorf("invalid config param count: %v, want (1, 1000]", cfg.Count)
		}
		if len(cfg.Devices) != 0 {
			return nil, nil, fmt.Errorf("type %v does not support devices param", cfg.Type)
		}
	}
	if cfg.Rpc == "" {
		cfg.Rpc = "localhost:0"
	}
	if cfg.Procs <= 0 {
		cfg.Procs = 1
	}
	if cfg.Procs > 32 {
		return nil, nil, fmt.Errorf("config param procs has higher value '%v' then the max supported 32", cfg.Procs)
	}
	if cfg.Output == "" {
		if cfg.Type == "local" {
			cfg.Output = "none"
		} else {
			cfg.Output = "stdout"
		}
	}
	switch cfg.Output {
	case "none", "stdout", "dmesg", "file":
	default:
		return nil, nil, fmt.Errorf("config param output must contain one of none/stdout/dmesg/file")
	}
	switch cfg.Sandbox {
	case "none", "setuid", "namespace":
	default:
		return nil, nil, fmt.Errorf("config param sandbox must contain one of none/setuid/namespace")
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get wd: %v", err)
	}
	abs := func(path string) string {
		if path != "" && !filepath.IsAbs(path) {
			path = filepath.Join(wd, path)
		}
		return path
	}
	cfg.Workdir = abs(cfg.Workdir)
	cfg.Kernel = abs(cfg.Kernel)
	cfg.Vmlinux = abs(cfg.Vmlinux)
	cfg.Syzkaller = abs(cfg.Syzkaller)
	cfg.Initrd = abs(cfg.Initrd)
	cfg.Sshkey = abs(cfg.Sshkey)
	cfg.Bin = abs(cfg.Bin)

	syscalls, err := parseSyscalls(cfg)
	if err != nil {
		return nil, nil, err
	}

	if err := parseSuppressions(cfg); err != nil {
		return nil, nil, err
	}

	if cfg.Hub_Addr != "" {
		if cfg.Name == "" {
			return nil, nil, fmt.Errorf("hub_addr is set, but name is empty")
		}
		if cfg.Hub_Key == "" {
			return nil, nil, fmt.Errorf("hub_addr is set, but hub_key is empty")
		}
	}
	if cfg.Dashboard_Addr != "" {
		if cfg.Name == "" {
			return nil, nil, fmt.Errorf("dashboard_addr is set, but name is empty")
		}
		if cfg.Dashboard_Key == "" {
			return nil, nil, fmt.Errorf("dashboard_addr is set, but dashboard_key is empty")
		}
	}

	return cfg, syscalls, nil
}

func parseSyscalls(cfg *Config) (map[int]bool, error) {
	match := func(call *sys.Call, str string) bool {
		if str == call.CallName || str == call.Name {
			return true
		}
		if len(str) > 1 && str[len(str)-1] == '*' && strings.HasPrefix(call.Name, str[:len(str)-1]) {
			return true
		}
		return false
	}

	syscalls := make(map[int]bool)
	if len(cfg.Enable_Syscalls) != 0 {
		for _, c := range cfg.Enable_Syscalls {
			n := 0
			for _, call := range sys.Calls {
				if match(call, c) {
					syscalls[call.ID] = true
					n++
				}
			}
			if n == 0 {
				return nil, fmt.Errorf("unknown enabled syscall: %v", c)
			}
		}
	} else {
		for _, call := range sys.Calls {
			syscalls[call.ID] = true
		}
	}
	for _, c := range cfg.Disable_Syscalls {
		n := 0
		for _, call := range sys.Calls {
			if match(call, c) {
				delete(syscalls, call.ID)
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("unknown disabled syscall: %v", c)
		}
	}
	// mmap is used to allocate memory.
	syscalls[sys.CallMap["mmap"].ID] = true

	return syscalls, nil
}

func parseSuppressions(cfg *Config) error {
	// Add some builtin suppressions.
	supp := append(cfg.Suppressions, []string{
		"panic: failed to start executor binary",
		"panic: executor failed: pthread_create failed",
		"panic: failed to create temp dir",
		"fatal error: runtime: out of memory",
		"fatal error: runtime: cannot allocate memory",
		"fatal error: unexpected signal during runtime execution", // presubmably OOM turned into SIGBUS
		"signal SIGBUS: bus error",                                // presubmably OOM turned into SIGBUS
		"Out of memory: Kill process .* \\(syz-fuzzer\\)",
		"lowmemorykiller: Killing 'syz-fuzzer'",
		//"INFO: lockdep is turned off", // printed by some sysrq that dumps scheduler state, but also on all lockdep reports
	}...)
	for _, s := range supp {
		re, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("failed to compile suppression '%v': %v", s, err)
		}
		cfg.ParsedSuppressions = append(cfg.ParsedSuppressions, re)
	}
	for _, ignore := range cfg.Ignores {
		re, err := regexp.Compile(ignore)
		if err != nil {
			return fmt.Errorf("failed to compile ignore '%v': %v", ignore, err)
		}
		cfg.ParsedIgnores = append(cfg.ParsedIgnores, re)
	}
	return nil
}

func CreateVMConfig(cfg *Config, index int) (*vm.Config, error) {
	if index < 0 || index >= cfg.Count {
		return nil, fmt.Errorf("invalid VM index %v (count %v)", index, cfg.Count)
	}
	workdir, err := fileutil.ProcessTempDir(cfg.Workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance temp dir: %v", err)
	}
	vmCfg := &vm.Config{
		Name:        fmt.Sprintf("%v-%v-%v", cfg.Type, cfg.Name, index),
		Index:       index,
		Workdir:     workdir,
		Bin:         cfg.Bin,
		BinArgs:     cfg.Bin_Args,
		Kernel:      cfg.Kernel,
		Cmdline:     cfg.Cmdline,
		Image:       cfg.Image,
		Initrd:      cfg.Initrd,
		Sshkey:      cfg.Sshkey,
		Executor:    filepath.Join(cfg.Syzkaller, "bin", "syz-executor"),
		Cpu:         cfg.Cpu,
		Mem:         cfg.Mem,
		Debug:       cfg.Debug,
		MachineType: cfg.Machine_Type,
	}
	if len(cfg.Devices) != 0 {
		vmCfg.Device = cfg.Devices[index]
	}
	return vmCfg, nil
}

func checkUnknownFields(data []byte) (string, error) {
	// While https://github.com/golang/go/issues/15314 is not resolved
	// we don't have a better way than to enumerate all known fields.
	var fields = []string{
		"Name",
		"Http",
		"Rpc",
		"Workdir",
		"Vmlinux",
		"Kernel",
		"Tag",
		"Cmdline",
		"Image",
		"Cpu",
		"Mem",
		"Sshkey",
		"Bin",
		"Bin_Args",
		"Debug",
		"Output",
		"Hub_Addr",
		"Hub_Key",
		"Dashboard_Addr",
		"Dashboard_Key",
		"Syzkaller",
		"Type",
		"Count",
		"Devices",
		"Procs",
		"Cover",
		"Reproduce",
		"Sandbox",
		"Leak",
		"Enable_Syscalls",
		"Disable_Syscalls",
		"Suppressions",
		"Ignores",
		"Initrd",
		"Machine_Type",
	}
	f := make(map[string]interface{})
	if err := json.Unmarshal(data, &f); err != nil {
		return "", fmt.Errorf("failed to parse config file: %v", err)
	}
	for k := range f {
		ok := false
		for _, k1 := range fields {
			if strings.ToLower(k) == strings.ToLower(k1) {
				ok = true
				break
			}
		}
		if !ok {
			return k, nil
		}
	}
	return "", nil
}
