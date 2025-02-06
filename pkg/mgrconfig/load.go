// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys" // most mgrconfig users want targets too
	"github.com/google/syzkaller/sys/targets"
)

// Derived config values that are handy to keep with the config, filled after reading user config.
type Derived struct {
	Target    *prog.Target
	SysTarget *targets.Target

	// Parsed Target:
	TargetOS     string
	TargetArch   string
	TargetVMArch string

	// Full paths to binaries we are going to use:
	ExecprogBin string
	ExecutorBin string

	Syscalls      []int
	NoMutateCalls map[int]bool // Set of IDs of syscalls which should not be mutated.
	Timeouts      targets.Timeouts

	// Special debugging/development mode specified by VM type "none".
	// In this mode syz-manager does not start any VMs, but instead a user is supposed
	// to start syz-executor process in a VM manually.
	VMLess bool

	LocalModules []*vminfo.KernelModule
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
		SSHUser:        "root",
		Cover:          true,
		Reproduce:      true,
		Sandbox:        "none",
		RPC:            ":0",
		MaxCrashLogs:   100,
		Procs:          6,
		PreserveCorpus: true,
		RunFsck:        true,
		Experimental: Experimental{
			RemoteCover:      true,
			CoverEdges:       true,
			DescriptionsMode: manualDescriptions,
		},
	}
}

type DescriptionsMode int

const (
	invalidDescriptions = iota
	ManualDescriptions
	AutoDescriptions
	AnyDescriptions
)

const manualDescriptions = "manual"

var (
	strToDescriptionsMode = map[string]DescriptionsMode{
		manualDescriptions: ManualDescriptions,
		"auto":             AutoDescriptions,
		"any":              AnyDescriptions,
	}
)

func loadPartial(cfg *Config) (*Config, error) {
	var err error
	cfg.TargetOS, cfg.TargetVMArch, cfg.TargetArch, err = splitTarget(cfg.RawTarget)
	if err != nil {
		return nil, err
	}
	cfg.Target, err = prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return nil, err
	}
	cfg.SysTarget = targets.Get(cfg.TargetOS, cfg.TargetVMArch)
	if cfg.SysTarget == nil {
		return nil, fmt.Errorf("unsupported OS/arch: %v/%v", cfg.TargetOS, cfg.TargetVMArch)
	}
	return cfg, nil
}

func Complete(cfg *Config) error {
	if err := checkNonEmpty(
		cfg.TargetOS, "target",
		cfg.TargetVMArch, "target",
		cfg.TargetArch, "target",
		cfg.Workdir, "workdir",
		cfg.Syzkaller, "syzkaller",
		cfg.Type, "type",
		cfg.SSHUser, "ssh_user",
	); err != nil {
		return err
	}
	cfg.Workdir = osutil.Abs(cfg.Workdir)
	if cfg.WorkdirTemplate != "" {
		cfg.WorkdirTemplate = osutil.Abs(cfg.WorkdirTemplate)
		if _, err := os.ReadDir(cfg.WorkdirTemplate); err != nil {
			return fmt.Errorf("failed to read workdir_template: %w", err)
		}
	}
	if cfg.Image != "" {
		if !osutil.IsExist(cfg.Image) {
			return fmt.Errorf("bad config param image: can't find %v", cfg.Image)
		}
		cfg.Image = osutil.Abs(cfg.Image)
	}
	if err := cfg.completeBinaries(); err != nil {
		return err
	}
	if cfg.Procs < 1 || cfg.Procs > prog.MaxPids {
		return fmt.Errorf("bad config param procs: '%v', want [1, %v]", cfg.Procs, prog.MaxPids)
	}
	switch cfg.Sandbox {
	case "none", "setuid", "namespace", "android":
	default:
		return fmt.Errorf("config param sandbox must contain one of none/setuid/namespace/android")
	}
	if err := cfg.checkSSHParams(); err != nil {
		return err
	}
	cfg.CompleteKernelDirs()

	if err := cfg.completeServices(); err != nil {
		return nil
	}

	if cfg.FuzzingVMs < 0 {
		return fmt.Errorf("fuzzing_vms cannot be less than 0")
	}

	var err error
	cfg.Syscalls, err = ParseEnabledSyscalls(cfg.Target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		strToDescriptionsMode[cfg.Experimental.DescriptionsMode])
	if err != nil {
		return err
	}
	cfg.NoMutateCalls, err = ParseNoMutateSyscalls(cfg.Target, cfg.NoMutateSyscalls)
	if err != nil {
		return err
	}
	if err := cfg.completeFocusAreas(); err != nil {
		return err
	}
	cfg.initTimeouts()
	cfg.VMLess = cfg.Type == "none"
	return nil
}

func (cfg *Config) completeServices() error {
	if cfg.HubClient != "" {
		if err := checkNonEmpty(
			cfg.Name, "name",
			cfg.HubAddr, "hub_addr",
		); err != nil {
			return err
		}
	}
	if cfg.HubDomain != "" &&
		!regexp.MustCompile(`^[a-zA-Z0-9-_.]{2,50}(/[a-zA-Z0-9-_.]{2,50})?$`).MatchString(cfg.HubDomain) {
		return fmt.Errorf("bad value for hub_domain")
	}
	if cfg.DashboardClient != "" {
		if err := checkNonEmpty(
			cfg.Name, "name",
			cfg.DashboardAddr, "dashboard_addr",
		); err != nil {
			return err
		}
	}
	if !cfg.AssetStorage.IsEmpty() {
		if cfg.DashboardClient == "" {
			return fmt.Errorf("asset storage also requires dashboard client")
		}
		if err := cfg.AssetStorage.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (cfg *Config) initTimeouts() {
	slowdown := 1
	switch {
	case cfg.Type == "qemu" && (runtime.GOARCH == cfg.SysTarget.Arch || runtime.GOARCH == cfg.SysTarget.VMArch):
		// If TCG is enabled for QEMU, increase the slowdown.
		if bytes.Contains(cfg.VM, []byte("-accel tcg")) {
			slowdown = 10
		}
	case cfg.Type == "qemu" && runtime.GOARCH != cfg.SysTarget.Arch && runtime.GOARCH != cfg.SysTarget.VMArch:
		// Assuming qemu emulation.
		// Quick tests of mmap syscall on arm64 show ~9x slowdown.
		slowdown = 10
	case cfg.Type == targets.GVisor && cfg.Cover && strings.Contains(cfg.Name, "-race"):
		// Go coverage+race has insane slowdown of ~350x. We can't afford such large value,
		// but a smaller value should be enough to finish at least some syscalls.
		// Note: the name check is a hack.
		slowdown = 10
	}
	// Note: we could also consider heavy debug tools (KASAN/KMSAN/KCSAN/KMEMLEAK) if necessary.
	cfg.Timeouts = cfg.SysTarget.Timeouts(slowdown)
}

func checkNonEmpty(fields ...string) error {
	for i := 0; i < len(fields); i += 2 {
		if fields[i] == "" {
			return fmt.Errorf("config param %v is empty", fields[i+1])
		}
	}
	return nil
}

func (cov *CovFilterCfg) Empty() bool {
	return len(cov.Functions)+len(cov.Files)+len(cov.RawPCs) == 0
}

func (cfg *Config) CompleteKernelDirs() {
	cfg.KernelObj = osutil.Abs(cfg.KernelObj)
	if cfg.KernelSrc == "" {
		cfg.KernelSrc = cfg.KernelObj // assume in-tree build by default
	}
	cfg.KernelSrc = osutil.Abs(cfg.KernelSrc)
	if cfg.KernelBuildSrc == "" {
		cfg.KernelBuildSrc = cfg.KernelSrc
	}
	cfg.KernelBuildSrc = osutil.Abs(cfg.KernelBuildSrc)
}

func (cfg *Config) checkSSHParams() error {
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
	cfg.SSHKey = osutil.Abs(cfg.SSHKey)
	return nil
}

func (cfg *Config) completeBinaries() error {
	cfg.Syzkaller = osutil.Abs(cfg.Syzkaller)
	exe := cfg.SysTarget.ExeExtension
	targetBin := func(name, arch string) string {
		return filepath.Join(cfg.Syzkaller, "bin", cfg.TargetOS+"_"+arch, name+exe)
	}
	cfg.ExecprogBin = targetBin("syz-execprog", cfg.TargetVMArch)
	cfg.ExecutorBin = targetBin("syz-executor", cfg.TargetArch)

	if cfg.ExecprogBinOnTarget != "" {
		cfg.SysTarget.ExecprogBin = cfg.ExecprogBinOnTarget
	}
	if cfg.ExecutorBinOnTarget != "" {
		cfg.SysTarget.ExecutorBin = cfg.ExecutorBinOnTarget
	}
	if cfg.StraceBinOnTarget && cfg.StraceBin == "" {
		cfg.StraceBin = "strace"
	}

	// If the target already provides binaries, we don't need to copy them.
	if cfg.SysTarget.ExecprogBin != "" {
		cfg.ExecprogBin = ""
	}
	if cfg.SysTarget.ExecutorBin != "" {
		cfg.ExecutorBin = ""
	}
	if cfg.ExecprogBin != "" && !osutil.IsExist(cfg.ExecprogBin) {
		return fmt.Errorf("bad config syzkaller param: can't find %v", cfg.ExecprogBin)
	}
	if cfg.ExecutorBin != "" && !osutil.IsExist(cfg.ExecutorBin) {
		return fmt.Errorf("bad config syzkaller param: can't find %v", cfg.ExecutorBin)
	}
	if !cfg.StraceBinOnTarget && cfg.StraceBin != "" {
		if !osutil.IsExist(cfg.StraceBin) {
			return fmt.Errorf("bad config param strace_bin: can't find %v", cfg.StraceBin)
		}
		cfg.StraceBin = osutil.Abs(cfg.StraceBin)
	}
	return nil
}

func (cfg *Config) completeFocusAreas() error {
	names := map[string]bool{}
	seenEmptyFilter := false
	for i, area := range cfg.Experimental.FocusAreas {
		if area.Name != "" {
			if names[area.Name] {
				return fmt.Errorf("duplicate focus area name: %q", area.Name)
			}
			names[area.Name] = true
		}
		if area.Weight <= 0 {
			return fmt.Errorf("focus area #%d: negative weight", i)
		}
		if area.Filter.Empty() {
			if seenEmptyFilter {
				return fmt.Errorf("there must be only one focus area with an empty filter")
			}
			seenEmptyFilter = true
		}
	}
	if !cfg.CovFilter.Empty() {
		if len(cfg.Experimental.FocusAreas) > 0 {
			return fmt.Errorf("you cannot use both cov_filter and focus_areas")
		}
		cfg.Experimental.FocusAreas = []FocusArea{
			{
				Name:   "filtered",
				Filter: cfg.CovFilter,
				Weight: 1.0,
			},
		}
		cfg.CovFilter = CovFilterCfg{}
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

func ParseEnabledSyscalls(target *prog.Target, enabled, disabled []string,
	descriptionsMode DescriptionsMode) ([]int, error) {
	if descriptionsMode == invalidDescriptions {
		return nil, fmt.Errorf("config param descriptions_mode must contain one of auto/manual/any")
	}

	syscalls := make(map[int]bool)
	if len(enabled) != 0 {
		for _, c := range enabled {
			n := 0
			for _, call := range target.Syscalls {
				if MatchSyscall(call.Name, c) {
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

	for call := range syscalls {
		if target.Syscalls[call].Attrs.Disabled ||
			descriptionsMode == ManualDescriptions && target.Syscalls[call].Attrs.Automatic ||
			descriptionsMode == AutoDescriptions &&
				!target.Syscalls[call].Attrs.Automatic && !target.Syscalls[call].Attrs.AutomaticHelper {
			delete(syscalls, call)
		}
	}
	for _, c := range disabled {
		n := 0
		for _, call := range target.Syscalls {
			if MatchSyscall(call.Name, c) {
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
	var arr []int
	for id := range syscalls {
		arr = append(arr, id)
	}
	return arr, nil
}

func ParseNoMutateSyscalls(target *prog.Target, syscalls []string) (map[int]bool, error) {
	var result = make(map[int]bool)

	for _, c := range syscalls {
		n := 0
		for _, call := range target.Syscalls {
			if MatchSyscall(call.Name, c) {
				result[call.ID] = true
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("unknown no_mutate syscall: %v", c)
		}
	}

	return result, nil
}

func MatchSyscall(name, pattern string) bool {
	if pattern == name || strings.HasPrefix(name, pattern+"$") {
		return true
	}
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' &&
		strings.HasPrefix(name, pattern[:len(pattern)-1]) {
		return true
	}
	return false
}
