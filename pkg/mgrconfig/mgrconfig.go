// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys" // most mgrconfig users want targets too
	"github.com/google/syzkaller/sys/targets"
)

type Config struct {
	// Instance name (used for identification and as GCE instance prefix).
	Name string `json:"name"`
	// Target OS/arch, e.g. "linux/arm64" or "linux/amd64/386" (amd64 OS with 386 test process).
	Target string `json:"target"`
	// TCP address to serve HTTP stats page (e.g. "localhost:50000").
	HTTP string `json:"http"`
	// TCP address to serve RPC for fuzzer processes (optional).
	RPC     string `json:"rpc"`
	Workdir string `json:"workdir"`
	// Directory with kernel object files.
	KernelObj string `json:"kernel_obj"`
	// Kernel source directory (if not set defaults to KernelObj).
	KernelSrc string `json:"kernel_src"`
	// Arbitrary optional tag that is saved along with crash reports (e.g. branch/commit).
	Tag string `json:"tag"`
	// Linux image for VMs.
	Image string `json:"image"`
	// SSH key for the image (may be empty for some VM types).
	SSHKey string `json:"sshkey"`
	// SSH user ("root" by default).
	SSHUser string `json:"ssh_user"`

	HubClient string `json:"hub_client"`
	HubAddr   string `json:"hub_addr"`
	HubKey    string `json:"hub_key"`

	// syz-manager will send crash emails to this list of emails using mailx (optional).
	EmailAddrs []string `json:"email_addrs"`

	DashboardClient string `json:"dashboard_client"`
	DashboardAddr   string `json:"dashboard_addr"`
	DashboardKey    string `json:"dashboard_key"`

	// Path to syzkaller checkout (syz-manager will look for binaries in bin subdir).
	Syzkaller string `json:"syzkaller"`
	// Number of parallel processes inside of every VM.
	Procs int `json:"procs"`

	// Type of sandbox to use during fuzzing:
	// "none": don't do anything special (has false positives, e.g. due to killing init), default
	// "setuid": impersonate into user nobody (65534)
	// "namespace": create a new namespace for fuzzer using CLONE_NEWNS/CLONE_NEWNET/CLONE_NEWPID/etc,
	//	requires building kernel with CONFIG_NAMESPACES, CONFIG_UTS_NS, CONFIG_USER_NS,
	//	CONFIG_PID_NS and CONFIG_NET_NS.
	// "android_untrusted_app": (Android) Emulate permissions of an untrusted app
	Sandbox string `json:"sandbox"`

	// Use KCOV coverage (default: true).
	Cover bool `json:"cover"`
	// Reproduce, localize and minimize crashers (default: true).
	Reproduce bool `json:"reproduce"`

	EnabledSyscalls  []string `json:"enable_syscalls"`
	DisabledSyscalls []string `json:"disable_syscalls"`
	// Don't save reports matching these regexps, but reboot VM after them,
	// matched against whole report output.
	Suppressions []string `json:"suppressions"`
	// Completely ignore reports matching these regexps (don't save nor reboot),
	// must match the first line of crash message.
	Ignores []string `json:"ignores"`

	// VM type (qemu, gce, android, isolated, etc).
	Type string `json:"type"`
	// VM-type-specific config.
	VM json.RawMessage `json:"vm"`

	// Implementation details beyond this point.
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
	cfg, err := LoadPartialData(data)
	if err != nil {
		return nil, err
	}
	if err := Complete(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadFile(filename string) (*Config, error) {
	cfg, err := LoadPartialFile(filename)
	if err != nil {
		return nil, err
	}
	if err := Complete(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadPartialData(data []byte) (*Config, error) {
	cfg := defaultValues()
	if err := config.LoadData(data, cfg); err != nil {
		return nil, err
	}
	return loadPartial(cfg)
}

func LoadPartialFile(filename string) (*Config, error) {
	cfg := defaultValues()
	if err := config.LoadFile(filename, cfg); err != nil {
		return nil, err
	}
	return loadPartial(cfg)
}

func defaultValues() *Config {
	return &Config{
		SSHUser:   "root",
		Cover:     true,
		Reproduce: true,
		Sandbox:   "none",
		RPC:       ":0",
		Procs:     1,
	}
}

func loadPartial(cfg *Config) (*Config, error) {
	var err error
	cfg.TargetOS, cfg.TargetVMArch, cfg.TargetArch, err = splitTarget(cfg.Target)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func Complete(cfg *Config) error {
	if cfg.TargetOS == "" || cfg.TargetVMArch == "" || cfg.TargetArch == "" {
		return fmt.Errorf("target parameters are not filled in")
	}
	if cfg.Workdir == "" {
		return fmt.Errorf("config param workdir is empty")
	}
	cfg.Workdir = osutil.Abs(cfg.Workdir)
	if cfg.Syzkaller == "" {
		return fmt.Errorf("config param syzkaller is empty")
	}
	if err := completeBinaries(cfg); err != nil {
		return err
	}
	if cfg.HTTP == "" {
		return fmt.Errorf("config param http is empty")
	}
	if cfg.Type == "" {
		return fmt.Errorf("config param type is empty")
	}
	if cfg.Procs < 1 || cfg.Procs > 32 {
		return fmt.Errorf("bad config param procs: '%v', want [1, 32]", cfg.Procs)
	}
	switch cfg.Sandbox {
	case "none", "setuid", "namespace", "android_untrusted_app":
	default:
		return fmt.Errorf("config param sandbox must contain one of none/setuid/namespace/android_untrusted_app")
	}
	if err := checkSSHParams(cfg); err != nil {
		return err
	}

	cfg.KernelObj = osutil.Abs(cfg.KernelObj)
	if cfg.KernelSrc == "" {
		cfg.KernelSrc = cfg.KernelObj // assume in-tree build by default
	}
	cfg.KernelSrc = osutil.Abs(cfg.KernelSrc)
	if cfg.HubClient != "" && (cfg.Name == "" || cfg.HubAddr == "" || cfg.HubKey == "") {
		return fmt.Errorf("hub_client is set, but name/hub_addr/hub_key is empty")
	}
	if cfg.DashboardClient != "" && (cfg.Name == "" ||
		cfg.DashboardAddr == "" ||
		cfg.DashboardKey == "") {
		return fmt.Errorf("dashboard_client is set, but name/dashboard_addr/dashboard_key is empty")
	}

	return nil
}

func checkSSHParams(cfg *Config) error {
	if cfg.SSHUser == "" {
		return fmt.Errorf("bad config syzkaller param: ssh user is empty")
	}
	if cfg.SSHKey == "" {
		return nil
	}
	info, err := os.Stat(cfg.SSHKey)
	if err != nil {
		return err
	}
	if info.Mode()&0077 != 0 {
		return fmt.Errorf("sshkey %v is unprotected, ssh will reject it, do chmod 0600", cfg.SSHKey)
	}
	return nil
}

func completeBinaries(cfg *Config) error {
	sysTarget := targets.Get(cfg.TargetOS, cfg.TargetArch)
	if sysTarget == nil {
		return fmt.Errorf("unsupported OS/arch: %v/%v", cfg.TargetOS, cfg.TargetArch)
	}
	cfg.Syzkaller = osutil.Abs(cfg.Syzkaller)
	exe := sysTarget.ExeExtension
	targetBin := func(name, arch string) string {
		return filepath.Join(cfg.Syzkaller, "bin", cfg.TargetOS+"_"+arch, name+exe)
	}
	cfg.SyzFuzzerBin = targetBin("syz-fuzzer", cfg.TargetVMArch)
	cfg.SyzExecprogBin = targetBin("syz-execprog", cfg.TargetVMArch)
	cfg.SyzExecutorBin = targetBin("syz-executor", cfg.TargetArch)
	if !osutil.IsExist(cfg.SyzFuzzerBin) {
		return fmt.Errorf("bad config syzkaller param: can't find %v", cfg.SyzFuzzerBin)
	}
	if !osutil.IsExist(cfg.SyzExecprogBin) {
		return fmt.Errorf("bad config syzkaller param: can't find %v", cfg.SyzExecprogBin)
	}
	if !osutil.IsExist(cfg.SyzExecutorBin) {
		return fmt.Errorf("bad config syzkaller param: can't find %v", cfg.SyzExecutorBin)
	}
	return nil
}

func splitTarget(target string) (string, string, string, error) {
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

func ParseEnabledSyscalls(target *prog.Target, enabled, disabled []string) (map[int]bool, error) {
	syscalls := make(map[int]bool)
	if len(enabled) != 0 {
		for _, c := range enabled {
			n := 0
			for _, call := range target.Syscalls {
				if matchSyscall(call.Name, c) {
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
	for _, c := range disabled {
		n := 0
		for _, call := range target.Syscalls {
			if matchSyscall(call.Name, c) {
				delete(syscalls, call.ID)
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("unknown disabled syscall: %v", c)
		}
	}
	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all syscalls are disabled by disable_syscalls in config")
	}
	return syscalls, nil
}

func matchSyscall(name, pattern string) bool {
	if pattern == name || strings.HasPrefix(name, pattern+"$") {
		return true
	}
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' &&
		strings.HasPrefix(name, pattern[:len(pattern)-1]) {
		return true
	}
	return false
}
