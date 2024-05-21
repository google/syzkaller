// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"fmt"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

type StraceResult struct {
	Report *report.Report
	Output []byte
	Error  error
}

const (
	straceOutputLogSize = 2048 << 10
)

func RunStrace(result *Result, cfg *mgrconfig.Config, reporter *report.Reporter,
	vmPool *vm.Pool, vmIndex int) *StraceResult {
	if cfg.StraceBin == "" {
		return straceFailed(fmt.Errorf("strace binary is not set in the config"))
	}
	inst, err := instance.CreateExecProgInstance(vmPool, vmIndex, cfg, reporter,
		&instance.OptionalConfig{
			StraceBin:        cfg.StraceBin,
			BeforeContextLen: straceOutputLogSize,
		})
	if err != nil {
		return straceFailed(fmt.Errorf("failed to set up instance: %w", err))
	}
	defer inst.VMInstance.Close()

	var runRes *instance.RunResult
	if result.CRepro {
		log.Logf(1, "running C repro under strace")
		runRes, err = inst.RunCProg(result.Prog, result.Duration, result.Opts)
	} else {
		log.Logf(1, "running syz repro under strace")
		runRes, err = inst.RunSyzProg(result.Prog.Serialize(), result.Duration,
			result.Opts, instance.SyzExitConditions)
	}
	if err != nil {
		return straceFailed(fmt.Errorf("failed to generate strace log: %w", err))
	}
	return &StraceResult{
		Report: runRes.Report,
		Output: runRes.Output,
	}
}

func straceFailed(err error) *StraceResult {
	return &StraceResult{Error: err}
}

func (strace *StraceResult) IsSameBug(repro *Result) bool {
	if strace == nil || strace.Report == nil || repro.Report == nil {
		return false
	}
	return strace.Report.Title == repro.Report.Title
}
