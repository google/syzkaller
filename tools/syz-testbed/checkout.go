// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	syz_instance "github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

type Checkout struct {
	Path string
	Name string

	ManagerConfig json.RawMessage
	Running       map[Instance]bool
	Completed     []RunResult
	LastRunning   time.Time
	reporter      *report.Reporter
	mu            sync.Mutex
}

func (checkout *Checkout) GetReporter() *report.Reporter {
	checkout.mu.Lock()
	defer checkout.mu.Unlock()
	if checkout.reporter == nil {
		// Unfortunately, we have no other choice but to parse the config to use our own parser.
		// TODO: add some tool to syzkaller that would just parse logs and then execute it here?
		mgrCfg, err := mgrconfig.LoadPartialData(checkout.ManagerConfig)
		if err != nil {
			tool.Failf("failed to parse mgr config for %s: %s", checkout.Name, err)
		}
		checkout.reporter, err = report.NewReporter(mgrCfg)
		if err != nil {
			tool.Failf("failed to get reporter for %s: %s", checkout.Name, err)
		}
	}
	return checkout.reporter
}

func (checkout *Checkout) AddRunning(instance Instance) {
	checkout.mu.Lock()
	defer checkout.mu.Unlock()
	checkout.Running[instance] = true
	checkout.LastRunning = time.Now()
}

func (checkout *Checkout) ArchiveInstance(instance Instance) error {
	checkout.mu.Lock()
	defer checkout.mu.Unlock()
	result, err := instance.FetchResult()
	if err != nil {
		return err
	}
	checkout.Completed = append(checkout.Completed, result)
	delete(checkout.Running, instance)
	return nil
}

func (checkout *Checkout) GetRunningResults() []RunResult {
	checkout.mu.Lock()
	defer checkout.mu.Unlock()
	running := []RunResult{}
	for instance := range checkout.Running {
		result, err := instance.FetchResult()
		if err == nil {
			running = append(running, result)
		}
	}
	return running
}

func (checkout *Checkout) GetCompletedResults() []RunResult {
	checkout.mu.Lock()
	defer checkout.mu.Unlock()
	return append([]RunResult{}, checkout.Completed...)
}

func (ctx *TestbedContext) NewCheckout(config *CheckoutConfig, mgrConfig json.RawMessage) (*Checkout, error) {
	checkout := &Checkout{
		Name:          config.Name,
		Path:          filepath.Join(ctx.Config.Workdir, "checkouts", config.Name),
		ManagerConfig: mgrConfig,
		Running:       make(map[Instance]bool),
	}
	log.Printf("[%s] Checking out", checkout.Name)
	if osutil.IsExist(checkout.Path) {
		return nil, fmt.Errorf("path %s already exists", checkout.Path)
	}
	repo := vcs.NewSyzkallerRepo(checkout.Path)
	commit, err := repo.Poll(config.Repo, config.Branch)
	if err != nil {
		return nil, fmt.Errorf("failed to checkout %s (%s): %s", config.Repo, config.Branch, err)
	}
	log.Printf("[%s] Done. Latest commit: %s", checkout.Name, commit)
	log.Printf("[%s] Building", checkout.Name)
	if _, err := osutil.RunCmd(time.Hour, checkout.Path, syz_instance.MakeBin); err != nil {
		return nil, fmt.Errorf("[%s] Make failed: %s", checkout.Name, err)
	}
	return checkout, nil
}
