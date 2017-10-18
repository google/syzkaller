// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
)

type Config struct {
	Name       string // Instance name (used for identification and as GCE instance prefix)
	Target     string // Target OS/arch, e.g. "linux/arm64" or "linux/amd64/386" (amd64 OS with 386 test process)
	Http       string // TCP address to serve HTTP stats page (e.g. "localhost:50000")
	Rpc        string // TCP address to serve RPC for fuzzer processes (optional)
	Workdir    string
	Vmlinux    string
	Kernel_Src string // kernel source directory
	Tag        string // arbitrary optional tag that is saved along with crash reports (e.g. branch/commit)
	Image      string // linux image for VMs
	Sshkey     string // ssh key for the image (may be empty for some VM types)
	Ssh_User   string // ssh user ("root" by default)

	Hub_Client string
	Hub_Addr   string
	Hub_Key    string

	Dashboard_Client string
	Dashboard_Addr   string
	Dashboard_Key    string

	Syzkaller string // path to syzkaller checkout (syz-manager will look for binaries in bin subdir)
	Procs     int    // number of parallel processes inside of every VM

	Sandbox string // type of sandbox to use during fuzzing:
	// "none": don't do anything special (has false positives, e.g. due to killing init)
	// "setuid": impersonate into user nobody (65534), default
	// "namespace": create a new namespace for fuzzer using CLONE_NEWNS/CLONE_NEWNET/CLONE_NEWPID/etc,
	//	requires building kernel with CONFIG_NAMESPACES, CONFIG_UTS_NS, CONFIG_USER_NS, CONFIG_PID_NS and CONFIG_NET_NS.

	Cover     bool // use kcov coverage (default: true)
	Leak      bool // do memory leak checking
	Reproduce bool // reproduce, localize and minimize crashers (on by default)

	Enable_Syscalls  []string
	Disable_Syscalls []string
	Suppressions     []string // don't save reports matching these regexps, but reboot VM after them
	Ignores          []string // completely ignore reports matching these regexps (don't save nor reboot)

	Type string          // VM type (qemu, kvm, local)
	VM   json.RawMessage // VM-type-specific config

	// Implementation details beyond this point.
	ParsedSuppressions []*regexp.Regexp `json:"-"`
	ParsedIgnores      []*regexp.Regexp `json:"-"`
	// Parsed Target:
	TargetOS     string `json:"-"`
	TargetArch   string `json:"-"`
	TargetVMArch string `json:"-"`
	// Syzkaller binaries that we are going to use:
	SyzFuzzerBin   string `json:"-"`
	SyzExecprogBin string `json:"-"`
	SyzExecutorBin string `json:"-"`
}

func LoadData(data []byte) (*Config, error) {
	return load(data, "")
}

func LoadFile(filename string) (*Config, error) {
	return load(nil, filename)
}

func DefaultValues() *Config {
	return &Config{
		Ssh_User:  "root",
		Cover:     true,
		Reproduce: true,
		Sandbox:   "setuid",
		Rpc:       ":0",
		Procs:     1,
	}
}

func load(data []byte, filename string) (*Config, error) {
	cfg := DefaultValues()
	if data != nil {
		if err := config.LoadData(data, cfg); err != nil {
			return nil, err
		}
	} else {
		if err := config.LoadFile(filename, cfg); err != nil {
			return nil, err
		}
	}

	var err error
	cfg.TargetOS, cfg.TargetVMArch, cfg.TargetArch, err = SplitTarget(cfg.Target)
	if err != nil {
		return nil, err
	}

	targetBin := func(name, arch string) string {
		exe := ""
		if cfg.TargetOS == "windows" {
			exe = ".exe"
		}
		return filepath.Join(cfg.Syzkaller, "bin", cfg.TargetOS+"_"+arch, name+exe)
	}
	cfg.SyzFuzzerBin = targetBin("syz-fuzzer", cfg.TargetVMArch)
	cfg.SyzExecprogBin = targetBin("syz-execprog", cfg.TargetVMArch)
	cfg.SyzExecutorBin = targetBin("syz-executor", cfg.TargetArch)
	if !osutil.IsExist(cfg.SyzFuzzerBin) {
		return nil, fmt.Errorf("bad config syzkaller param: can't find %v", cfg.SyzFuzzerBin)
	}
	if !osutil.IsExist(cfg.SyzExecprogBin) {
		return nil, fmt.Errorf("bad config syzkaller param: can't find %v", cfg.SyzExecprogBin)
	}
	if !osutil.IsExist(cfg.SyzExecutorBin) {
		return nil, fmt.Errorf("bad config syzkaller param: can't find %v", cfg.SyzExecutorBin)
	}
	if cfg.Http == "" {
		return nil, fmt.Errorf("config param http is empty")
	}
	if cfg.Workdir == "" {
		return nil, fmt.Errorf("config param workdir is empty")
	}
	if cfg.Type == "" {
		return nil, fmt.Errorf("config param type is empty")
	}
	if cfg.Procs < 1 || cfg.Procs > 32 {
		return nil, fmt.Errorf("bad config param procs: '%v', want [1, 32]", cfg.Procs)
	}
	switch cfg.Sandbox {
	case "none", "setuid", "namespace":
	default:
		return nil, fmt.Errorf("config param sandbox must contain one of none/setuid/namespace")
	}

	cfg.Workdir = osutil.Abs(cfg.Workdir)
	cfg.Vmlinux = osutil.Abs(cfg.Vmlinux)
	cfg.Syzkaller = osutil.Abs(cfg.Syzkaller)
	if cfg.Kernel_Src == "" {
		cfg.Kernel_Src = filepath.Dir(cfg.Vmlinux) // assume in-tree build by default
	}

	if err := parseSuppressions(cfg); err != nil {
		return nil, err
	}

	if cfg.Hub_Client != "" && (cfg.Name == "" || cfg.Hub_Addr == "" || cfg.Hub_Key == "") {
		return nil, fmt.Errorf("hub_client is set, but name/hub_addr/hub_key is empty")
	}
	if cfg.Dashboard_Client != "" && (cfg.Name == "" ||
		cfg.Dashboard_Addr == "" ||
		cfg.Dashboard_Key == "") {
		return nil, fmt.Errorf("dashboard_client is set, but name/dashboard_addr/dashboard_key is empty")
	}

	return cfg, nil
}

func SplitTarget(target string) (string, string, string, error) {
	if target == "" {
		return "", "", "", fmt.Errorf("target is empty")
	}
	targetParts := strings.Split(target, "/")
	if len(targetParts) != 2 && len(targetParts) != 3 {
		return "", "", "", fmt.Errorf("bad config param target")
	}
	os := targetParts[0]
	vmarch := targetParts[1]
	arch := targetParts[1]
	if len(targetParts) == 3 {
		arch = targetParts[2]
	}
	return os, vmarch, arch, nil
}

func ParseEnabledSyscalls(cfg *Config) (map[int]bool, error) {
	match := func(call *prog.Syscall, str string) bool {
		if str == call.CallName || str == call.Name {
			return true
		}
		if len(str) > 1 && str[len(str)-1] == '*' && strings.HasPrefix(call.Name, str[:len(str)-1]) {
			return true
		}
		return false
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return nil, err
	}

	syscalls := make(map[int]bool)
	if len(cfg.Enable_Syscalls) != 0 {
		for _, c := range cfg.Enable_Syscalls {
			n := 0
			for _, call := range target.Syscalls {
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
		for _, call := range target.Syscalls {
			syscalls[call.ID] = true
		}
	}
	for _, c := range cfg.Disable_Syscalls {
		n := 0
		for _, call := range target.Syscalls {
			if match(call, c) {
				delete(syscalls, call.ID)
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("unknown disabled syscall: %v", c)
		}
	}
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

func CreateVMEnv(cfg *Config, debug bool) *vm.Env {
	return &vm.Env{
		Name:    cfg.Name,
		OS:      cfg.TargetOS,
		Arch:    cfg.TargetVMArch,
		Workdir: cfg.Workdir,
		Image:   cfg.Image,
		SshKey:  cfg.Sshkey,
		SshUser: cfg.Ssh_User,
		Debug:   debug,
		Config:  cfg.VM,
	}
}
