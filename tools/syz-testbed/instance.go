// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
)

type Instance interface {
	Run() error
	Stop()
	FetchResult() (RunResult, error)
	Uptime() time.Duration
}

// The essential information about an active instance.
type InstanceCommon struct {
	Name            string
	LogFile         string
	ExecCommand     string
	ExecCommandArgs []string
	StartedAt       time.Time
	StoppedAt       time.Time
	stopChannel     chan bool
}

func (inst *InstanceCommon) Run() error {
	const stopDelay = time.Minute

	log.Printf("[%s] starting", inst.Name)
	cmd := osutil.GraciousCommand(inst.ExecCommand, inst.ExecCommandArgs...)

	if inst.LogFile != "" {
		logfile, err := os.Create(inst.LogFile)
		if err != nil {
			return fmt.Errorf("[%s] failed to create logfile: %s", inst.Name, err)
		}
		cmd.Stdout = logfile
		cmd.Stderr = logfile
	}

	complete := make(chan error)
	inst.StartedAt = time.Now()
	cmd.Start()
	go func() {
		complete <- cmd.Wait()
	}()

	select {
	case err := <-complete:
		return err
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
	}
	inst.StoppedAt = time.Now()
	return nil
}

func (inst *InstanceCommon) Stop() {
	select {
	case inst.stopChannel <- true:
	default:
	}
}

func (inst *InstanceCommon) Uptime() time.Duration {
	if !inst.StartedAt.IsZero() && inst.StoppedAt.IsZero() {
		return time.Since(inst.StartedAt)
	}
	return inst.StoppedAt.Sub(inst.StartedAt)
}

type SyzManagerInstance struct {
	InstanceCommon
	SyzkallerInfo
	RunTime time.Duration
}

func (inst *SyzManagerInstance) FetchResult() (RunResult, error) {
	bugs, err := collectBugs(inst.Workdir)
	if err != nil {
		return nil, err
	}
	records, err := readBenches(inst.BenchFile)
	if err != nil {
		return nil, err
	}
	return &SyzManagerResult{
		Bugs:        bugs,
		StatRecords: records,
	}, nil
}

func (inst *SyzManagerInstance) Run() error {
	ret := make(chan error, 1)
	go func() {
		ret <- inst.InstanceCommon.Run()
	}()

	select {
	case err := <-ret:
		// Syz-managers are not supposed to stop themselves under normal circumstances.
		// If one of them did stop, there must have been a very good reason to do so.
		return fmt.Errorf("[%s] stopped: %v", inst.Name, err)
	case <-time.After(inst.RunTime):
		inst.Stop()
		<-ret
		return nil
	}
}

type SyzkallerInfo struct {
	Workdir   string
	CfgFile   string
	BenchFile string
}

func SetupSyzkallerInstance(mgrName, folder string, checkout *Checkout) (*SyzkallerInfo, error) {
	workdir := filepath.Join(folder, "workdir")
	log.Printf("[%s] Generating workdir", mgrName)
	err := osutil.MkdirAll(workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to create workdir %s", workdir)
	}
	log.Printf("[%s] Generating syz-manager config", mgrName)
	cfgFile := filepath.Join(folder, "manager.cfg")
	managerCfg, err := config.PatchJSON(checkout.ManagerConfig, map[string]interface{}{
		"name":      mgrName,
		"workdir":   workdir,
		"syzkaller": checkout.Path,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to patch mgr config")
	}
	err = osutil.WriteFile(cfgFile, managerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to save manager config to %s: %s", cfgFile, err)
	}
	return &SyzkallerInfo{
		Workdir:   workdir,
		CfgFile:   cfgFile,
		BenchFile: filepath.Join(folder, "bench.txt"),
	}, nil
}

func (t *SyzManagerTarget) newSyzManagerInstance(slotName, uniqName string, checkout *Checkout) (Instance, error) {
	folder := filepath.Join(checkout.Path, fmt.Sprintf("run-%s", uniqName))
	common, err := SetupSyzkallerInstance(slotName, folder, checkout)
	if err != nil {
		return nil, err
	}
	if t.config.Corpus != "" {
		log.Printf("[%s] Copying corpus", uniqName)
		corpusPath := filepath.Join(common.Workdir, "corpus.db")
		err = osutil.CopyFile(t.config.Corpus, corpusPath)
		if err != nil {
			return nil, fmt.Errorf("failed to copy corpus from %s: %s", t.config.Corpus, err)
		}
	}
	return &SyzManagerInstance{
		InstanceCommon: InstanceCommon{
			Name:            uniqName,
			LogFile:         filepath.Join(folder, "log.txt"),
			ExecCommand:     filepath.Join(checkout.Path, "bin", "syz-manager"),
			ExecCommandArgs: []string{"-config", common.CfgFile, "-bench", common.BenchFile},
			stopChannel:     make(chan bool, 1),
		},
		SyzkallerInfo: *common,
		RunTime:       t.config.RunTime.Duration,
	}, nil
}

type SyzReproInstance struct {
	InstanceCommon
	SyzkallerInfo
	Input      *SyzReproInput
	ReproFile  string
	CReproFile string
	TitleFile  string
}

func (inst *SyzReproInstance) FetchResult() (RunResult, error) {
	result := &SyzReproResult{
		Input:       inst.Input,
		ReproFound:  osutil.IsExist(inst.ReproFile),
		CReproFound: osutil.IsExist(inst.CReproFile),
		Duration:    inst.Uptime(),
	}
	outTitle, _ := ioutil.ReadFile(inst.TitleFile)
	if outTitle != nil {
		result.ReproTitle = strings.TrimSpace(string(outTitle))
		if result.ReproTitle != inst.Input.origTitle {
			// If we found a different bug, treat the reproduction as unsuccessful.
			result.ReproFound = false
			result.CReproFound = false
		}
	}
	return result, nil
}

func (t *SyzReproTarget) newSyzReproInstance(slotName, uniqName string, input *SyzReproInput,
	checkout *Checkout) (Instance, error) {
	folder := filepath.Join(checkout.Path, fmt.Sprintf("run-%s", uniqName))
	common, err := SetupSyzkallerInstance(slotName, folder, checkout)
	if err != nil {
		return nil, err
	}

	reproFile := filepath.Join(folder, "repro.txt")
	cReproFile := filepath.Join(folder, "crepro.txt")
	titleFile := filepath.Join(folder, "title.txt")
	newExecLog := filepath.Join(folder, "execution-log.txt")
	err = osutil.CopyFile(input.Path, newExecLog)
	if err != nil {
		return nil, err
	}
	return &SyzReproInstance{
		InstanceCommon: InstanceCommon{
			Name:        uniqName,
			LogFile:     filepath.Join(folder, "log.txt"),
			ExecCommand: filepath.Join(checkout.Path, "bin", "syz-repro"),
			ExecCommandArgs: []string{
				"-config", common.CfgFile,
				"-output", reproFile,
				"-crepro", cReproFile,
				"-title", titleFile,
				newExecLog,
			},
			stopChannel: make(chan bool, 1),
		},
		SyzkallerInfo: *common,
		Input:         input,
		ReproFile:     reproFile,
		CReproFile:    cReproFile,
		TitleFile:     titleFile,
	}, nil
}
