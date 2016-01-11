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
	Http    string
	Workdir string
	Vmlinux string
	Kernel  string // e.g. arch/x86/boot/bzImage
	Cmdline string // kernel command line
	Image   string // linux image for VMs
	Cpu     int    // number of VM CPUs
	Mem     int    // amount of VM memory in MBs
	Sshkey  string // root ssh key for the image
	Port    int    // VM ssh port to use
	Bin     string // qemu/lkvm binary name
	Debug   bool   // dump all VM output to console
	Output  string // one of stdout/dmesg/file (useful only for local VM)

	Syzkaller string // path to syzkaller checkout (syz-manager will look for binaries in bin subdir)
	Type      string // VM type (qemu, kvm, local)
	Count     int    // number of VMs
	Procs     int    // number of parallel processes inside of every VM

	NoCover     bool
	NoDropPrivs bool
	Leak        bool // do memory leak checking

	ConsoleDev string // console device for adb vm

	Enable_Syscalls  []string
	Disable_Syscalls []string
	Suppressions     []string
}

func Parse(filename string) (*Config, map[int]bool, []*regexp.Regexp, error) {
	if filename == "" {
		return nil, nil, nil, fmt.Errorf("supply config in -config flag")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-fuzzer")); err != nil {
		return nil, nil, nil, fmt.Errorf("bad config syzkaller param: can't find bin/syz-fuzzer")
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-executor")); err != nil {
		return nil, nil, nil, fmt.Errorf("bad config syzkaller param: can't find bin/syz-executor")
	}
	if _, err := os.Stat(filepath.Join(cfg.Syzkaller, "bin/syz-execprog")); err != nil {
		return nil, nil, nil, fmt.Errorf("bad config syzkaller param: can't find bin/syz-execprog")
	}
	if cfg.Http == "" {
		return nil, nil, nil, fmt.Errorf("config param http is empty")
	}
	if cfg.Workdir == "" {
		return nil, nil, nil, fmt.Errorf("config param workdir is empty")
	}
	if cfg.Vmlinux == "" {
		return nil, nil, nil, fmt.Errorf("config param vmlinux is empty")
	}
	if cfg.Type == "" {
		return nil, nil, nil, fmt.Errorf("config param type is empty")
	}
	if cfg.Count <= 0 || cfg.Count > 1000 {
		return nil, nil, nil, fmt.Errorf("invalid config param count: %v, want (1, 1000]", cfg.Count)
	}
	if cfg.Procs <= 0 {
		cfg.Procs = 1
	}
	if cfg.Output == "" {
		cfg.Output = "stdout"
	}
	switch cfg.Output {
	case "stdout", "dmesg", "file":
	default:
		return nil, nil, nil, fmt.Errorf("config param output must contain one of stdout/dmesg/file")
	}

	syscalls, err := parseSyscalls(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	suppressions, err := parseSuppressions(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	return cfg, syscalls, suppressions, nil
}

func parseSyscalls(cfg *Config) (map[int]bool, error) {
	if len(cfg.Enable_Syscalls) == 0 && len(cfg.Disable_Syscalls) == 0 {
		return nil, nil
	}

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
	// They will be generated anyway.
	syscalls[sys.CallMap["mmap"].ID] = true
	syscalls[sys.CallMap["clock_gettime"].ID] = true

	return syscalls, nil
}

func parseSuppressions(cfg *Config) ([]*regexp.Regexp, error) {
	// Add some builtin suppressions.
	supp := append(cfg.Suppressions, []string{
		"panic: failed to start executor binary",
		"panic: executor failed: pthread_create failed",
		"panic: failed to create temp dir",
		"fatal error: runtime: out of memory",
		"Out of memory: Kill process .* \\(syz-fuzzer\\)",
		"WARNING: KASAN doesn't support memory hot-add",
	}...)
	var suppressions []*regexp.Regexp
	for _, s := range supp {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("failed to compile suppression '%v': %v", s, err)
		}
		suppressions = append(suppressions, re)
	}

	return suppressions, nil
}

func CreateVMConfig(cfg *Config) (*vm.Config, error) {
	workdir, index, err := fileutil.ProcessTempDir(cfg.Workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance temp dir: %v", err)
	}
	vmCfg := &vm.Config{
		Name:       fmt.Sprintf("%v-%v", cfg.Type, index),
		Index:      index,
		Workdir:    workdir,
		Bin:        cfg.Bin,
		Kernel:     cfg.Kernel,
		Cmdline:    cfg.Cmdline,
		Image:      cfg.Image,
		Sshkey:     cfg.Sshkey,
		ConsoleDev: cfg.ConsoleDev,
		Cpu:        cfg.Cpu,
		Mem:        cfg.Mem,
		Debug:      cfg.Debug,
	}
	return vmCfg, nil
}
