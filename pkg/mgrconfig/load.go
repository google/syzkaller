// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys" // most mgrconfig users want targets too
	"github.com/google/syzkaller/sys/targets"
)

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
		Procs:     6,
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
	if err := checkNonEmpty(
		cfg.TargetOS, "target",
		cfg.TargetVMArch, "target",
		cfg.TargetArch, "target",
		cfg.Workdir, "workdir",
		cfg.Syzkaller, "syzkaller",
		cfg.HTTP, "http",
		cfg.Type, "type",
		cfg.SSHUser, "ssh_user",
	); err != nil {
		return err
	}
	cfg.Workdir = osutil.Abs(cfg.Workdir)
	if cfg.WorkdirTemplate != "" {
		cfg.WorkdirTemplate = osutil.Abs(cfg.WorkdirTemplate)
		if _, err := ioutil.ReadDir(cfg.WorkdirTemplate); err != nil {
			return fmt.Errorf("failed to read workdir_template: %v", err)
		}
	}
	if cfg.Image != "" {
		if !osutil.IsExist(cfg.Image) {
			return fmt.Errorf("bad config param image: can't find %v", cfg.Image)
		}
		cfg.Image = osutil.Abs(cfg.Image)
	}
	if err := completeBinaries(cfg); err != nil {
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
	if err := checkSSHParams(cfg); err != nil {
		return err
	}
	cfg.CompleteKernelDirs()

	if cfg.HubClient != "" {
		if err := checkNonEmpty(
			cfg.Name, "name",
			cfg.HubAddr, "hub_addr",
			cfg.HubKey, "hub_key",
		); err != nil {
			return err
		}
	}
	if cfg.DashboardClient != "" {
		if err := checkNonEmpty(
			cfg.Name, "name",
			cfg.DashboardAddr, "dashboard_addr",
			cfg.DashboardKey, "dashboard_key",
		); err != nil {
			return err
		}
	}
	return nil
}

func checkNonEmpty(fields ...string) error {
	for i := 0; i < len(fields); i += 2 {
		if fields[i] == "" {
			return fmt.Errorf("config param %v is empty", fields[i+1])
		}
	}
	return nil
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

func checkSSHParams(cfg *Config) error {
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

func ParseEnabledSyscalls(target *prog.Target, enabled, disabled []string) ([]int, error) {
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
	for call := range syscalls {
		if target.Syscalls[call].Attrs.Disabled {
			delete(syscalls, call)
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
	var arr []int
	for id := range syscalls {
		arr = append(arr, id)
	}
	return arr, nil
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
