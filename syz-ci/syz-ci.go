// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-ci is a continuous fuzzing system for syzkaller.
// It runs several syz-manager's, polls and rebuilds images for managers
// and polls and rebuilds syzkaller binaries.
// For usage instructions see: docs/ci.md
package main

// Implementation details:
//
// 2 main components:
//  - SyzUpdater: handles syzkaller updates
//  - Manager: handles kernel build and syz-manager process (one per manager)
// Both operate in a similar way and keep 2 builds:
//  - latest: latest known good build (i.e. we tested it)
//    preserved across restarts/reboots, i.e. we can start fuzzing even when
//    current syzkaller/kernel git head is broken, or git is down, or anything else
//  - current: currently used build (a copy of one of the latest builds)
// Other important points:
//  - syz-ci is always built on the same revision as the rest of syzkaller binaries,
//    this allows us to handle e.g. changes in manager config format.
//  - consequently, syzkaller binaries are never updated on-the-fly,
//    instead we re-exec and then update
//  - we understand when the latest build is fresh even after reboot,
//    i.e. we store enough information to identify it (git hash, compiler identity, etc),
//    so we don't rebuild unnecessary (kernel builds take time)
//  - we generally avoid crashing the process and handle all errors gracefully
//    (this is a continuous system), except for some severe/user errors during start
//    (e.g. bad config file, or can't create necessary dirs)
//
// Directory/file structure:
// syz-ci			: current executable
// syz-ci.tag			: tag of the current executable (syzkaller git hash)
// syzkaller/
//	latest/			: latest good syzkaller build
//	current/		: syzkaller build currently in use
// managers/
//	manager1/		: one dir per manager
//		kernel/		: kernel checkout
//		workdir/	: manager workdir (never deleted)
//		latest/		: latest good kernel image build
//		current/	: kernel image currently in use
//
// Current executable, syzkaller and kernel builds are marked with tag files.
// Tag files uniquely identify the build (git hash, compiler identity, kernel config, etc).
// For tag files both contents and modification time are important,
// modification time allows us to understand if we need to rebuild after a restart.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/google/syzkaller/pkg/config"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
)

var flagConfig = flag.String("config", "", "config file")

type Config struct {
	Name                   string
	Http                   string
	Dashboard_Addr         string // Optional.
	Hub_Addr               string // Optional.
	Hub_Key                string // Optional.
	Goroot                 string // Go 1.8+ toolchain dir.
	Syzkaller_Repo         string
	Syzkaller_Branch       string
	Syzkaller_Descriptions string // Dir with additional syscall descriptions (.txt and .const files).
	Managers               []*ManagerConfig
}

type ManagerConfig struct {
	Name             string
	Dashboard_Client string
	Dashboard_Key    string
	Repo             string
	Branch           string
	Compiler         string
	Userspace        string
	Kernel_Config    string
	Kernel_Cmdline   string // File with kernel cmdline values (optional).
	Kernel_Sysctl    string // File with sysctl values (e.g. output of sysctl -a, optional).
	Manager_Config   json.RawMessage
}

func main() {
	flag.Parse()
	EnableLogCaching(1000, 1<<20)
	cfg, err := loadConfig(*flagConfig)
	if err != nil {
		Fatalf("failed to load config: %v", err)
	}

	shutdownPending := make(chan struct{})
	osutil.HandleInterrupts(shutdownPending)

	updater := NewSyzUpdater(cfg)
	updater.UpdateOnStart(shutdownPending)
	updatePending := make(chan struct{})
	go func() {
		updater.WaitForUpdate()
		close(updatePending)
	}()

	stop := make(chan struct{})
	go func() {
		select {
		case <-shutdownPending:
		case <-updatePending:
		}
		close(stop)
	}()

	var wg sync.WaitGroup
	wg.Add(len(cfg.Managers))
	managers := make([]*Manager, len(cfg.Managers))
	for i, mgrcfg := range cfg.Managers {
		managers[i] = createManager(cfg, mgrcfg, stop)
	}
	for _, mgr := range managers {
		mgr := mgr
		go func() {
			defer wg.Done()
			mgr.loop()
		}()
	}

	<-stop
	wg.Wait()

	select {
	case <-shutdownPending:
	case <-updatePending:
		updater.UpdateAndRestart()
	}
}

func loadConfig(filename string) (*Config, error) {
	cfg := &Config{
		Syzkaller_Repo:   "https://github.com/google/syzkaller.git",
		Syzkaller_Branch: "master",
		Goroot:           os.Getenv("GOROOT"),
	}
	if err := config.LoadFile(filename, cfg); err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("param 'name' is empty")
	}
	if cfg.Http == "" {
		return nil, fmt.Errorf("param 'http' is empty")
	}
	if len(cfg.Managers) == 0 {
		return nil, fmt.Errorf("no managers specified")
	}
	for i, mgr := range cfg.Managers {
		if mgr.Name == "" {
			return nil, fmt.Errorf("param 'managers[%v].name' is empty", i)
		}
		mgrcfg := new(mgrconfig.Config)
		if err := config.LoadData(mgr.Manager_Config, mgrcfg); err != nil {
			return nil, fmt.Errorf("manager %v: %v", mgr.Name, err)
		}
	}
	return cfg, nil
}
