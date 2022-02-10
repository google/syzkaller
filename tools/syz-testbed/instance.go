// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
)

// The essential information about an active instance.
type Instance struct {
	Name            string
	Workdir         string
	BenchFile       string
	LogFile         string
	ExecCommand     string
	ExecCommandArgs []string
	stopChannel     chan bool
}

func (inst *Instance) Run() error {
	const stopDelay = time.Minute

	logfile, err := os.Create(inst.LogFile)
	if err != nil {
		return fmt.Errorf("[%s] failed to create logfile: %s", inst.Name, err)
	}
	log.Printf("[%s] starting", inst.Name)
	cmd := osutil.GraciousCommand(inst.ExecCommand, inst.ExecCommandArgs...)
	cmd.Stdout = logfile
	cmd.Stderr = logfile

	complete := make(chan error)
	go func() {
		complete <- cmd.Run()
	}()

	select {
	case err := <-complete:
		return fmt.Errorf("[%s] stopped: %s", inst.Name, err)
	case <-inst.stopChannel:
		// TODO: handle other OSes?
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-complete:
			// The manager has exited.
		case <-time.After(stopDelay):
			// The manager did not exit - kill it.
			log.Printf("[%s] instance did not exit itself, killing it", inst.Name)
			cmd.Process.Kill()
			<-complete
		}
		return nil
	}
}

func (inst *Instance) Stop() {
	select {
	case inst.stopChannel <- true:
	default:
	}
}

func (inst *Instance) FetchResult() (*RunResult, error) {
	bugs, err := collectBugs(inst.Workdir)
	if err != nil {
		return nil, err
	}
	records, err := readBenches(inst.BenchFile)
	if err != nil {
		return nil, err
	}
	return &RunResult{
		Workdir:     inst.Workdir,
		Bugs:        bugs,
		StatRecords: records,
	}, nil
}

func (ctx *TestbedContext) NewInstance(checkout *Checkout, mgrName string) (*Instance, error) {
	defer func() {
		ctx.NextInstanceID++
	}()
	name := fmt.Sprintf("%s-%d", checkout.Name, ctx.NextInstanceID)
	managerCfgPath := filepath.Join(checkout.Path, fmt.Sprintf("syz-%d.cnf", ctx.NextInstanceID))
	workdir := filepath.Join(checkout.Path, fmt.Sprintf("workdir_%d", ctx.NextInstanceID))
	bench := filepath.Join(checkout.Path, fmt.Sprintf("bench-%d.txt", ctx.NextInstanceID))
	logFile := filepath.Join(checkout.Path, fmt.Sprintf("log-%d.txt", ctx.NextInstanceID))

	log.Printf("[%s] Generating workdir", name)
	err := osutil.MkdirAll(workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to create workdir %s", workdir)
	}

	if ctx.Config.Corpus != "" {
		log.Printf("[%s] Copying corpus", name)
		corpusPath := filepath.Join(workdir, "corpus.db")
		err = osutil.CopyFile(ctx.Config.Corpus, corpusPath)
		if err != nil {
			return nil, fmt.Errorf("failed to copy corpus from %s: %s", ctx.Config.Corpus, err)
		}
	}

	log.Printf("[%s] Generating syz-manager config", name)
	managerCfg, err := config.PatchJSON(checkout.ManagerConfig, map[string]interface{}{
		"name":      mgrName,
		"workdir":   workdir,
		"syzkaller": checkout.Path,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to patch mgr config")
	}

	err = osutil.WriteFile(managerCfgPath, managerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to save manager config to %s: %s", managerCfgPath, err)
	}

	return &Instance{
		Name:            name,
		Workdir:         workdir,
		BenchFile:       bench,
		LogFile:         logFile,
		ExecCommand:     filepath.Join(checkout.Path, "bin", "syz-manager"),
		ExecCommandArgs: []string{"-config", managerCfgPath, "-bench", bench},
		stopChannel:     make(chan bool, 1),
	}, nil
}
