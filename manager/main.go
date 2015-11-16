// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
	_ "github.com/google/syzkaller/vm/kvm"
	_ "github.com/google/syzkaller/vm/local"
	_ "github.com/google/syzkaller/vm/qemu"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagV      = flag.Int("v", 0, "verbosity")
)

type Config struct {
	Name             string
	Http             string
	Master           string
	Workdir          string
	Vmlinux          string
	Type             string
	Count            int
	Port             int
	Nocover          bool
	Params           map[string]interface{}
	Enable_Syscalls  []string
	Disable_Syscalls []string
}

func main() {
	flag.Parse()
	cfg, syscalls := parseConfig()
	params, err := json.Marshal(cfg.Params)
	if err != nil {
		fatalf("failed to marshal config params: %v", err)
	}
	enabledSyscalls := ""
	if len(syscalls) != 0 {
		buf := new(bytes.Buffer)
		for c := range syscalls {
			fmt.Fprintf(buf, ",%v", c)
		}
		enabledSyscalls = buf.String()[1:]
		logf(1, "enabled syscalls: %v", enabledSyscalls)
	}
	vmCfg := &vm.Config{
		Workdir:         cfg.Workdir,
		ManagerPort:     cfg.Port,
		Params:          params,
		EnabledSyscalls: enabledSyscalls,
		NoCover:         cfg.Nocover,
	}
	var instances []vm.Instance
	for i := 0; i < cfg.Count; i++ {
		inst, err := vm.Create(cfg.Type, vmCfg, i)
		if err != nil {
			fatalf("failed to create an instance: %v", err)
		}
		instances = append(instances, inst)
	}
	RunManager(cfg, syscalls, instances)
}

func parseConfig() (*Config, map[int]bool) {
	if *flagConfig == "" {
		fatalf("supply config file name in -config flag")
	}
	data, err := ioutil.ReadFile(*flagConfig)
	if err != nil {
		fatalf("failed to read config file: %v", err)
	}
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		fatalf("failed to parse config file: %v", err)
	}
	if cfg.Name == "" {
		fatalf("config param name is empty")
	}
	if cfg.Http == "" {
		fatalf("config param http is empty")
	}
	if cfg.Master == "" {
		fatalf("config param master is empty")
	}
	if cfg.Workdir == "" {
		fatalf("config param workdir is empty")
	}
	if cfg.Vmlinux == "" {
		fatalf("config param vmlinux is empty")
	}
	if cfg.Type == "" {
		fatalf("config param type is empty")
	}
	if cfg.Count <= 0 || cfg.Count > 1000 {
		fatalf("invalid config param count: %v, want (1, 1000]", cfg.Count)
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

	var syscalls map[int]bool
	if len(cfg.Enable_Syscalls) != 0 || len(cfg.Disable_Syscalls) != 0 {
		syscalls = make(map[int]bool)
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
					fatalf("unknown enabled syscall: %v", c)
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
				fatalf("unknown disabled syscall: %v", c)
			}
		}
		// They will be generated anyway.
		syscalls[sys.CallMap["mmap"].ID] = true
		syscalls[sys.CallMap["clock_gettime"].ID] = true
	}

	return cfg, syscalls
}

func logf(v int, msg string, args ...interface{}) {
	if *flagV >= v {
		log.Printf(msg, args...)
	}
}

func fatalf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
