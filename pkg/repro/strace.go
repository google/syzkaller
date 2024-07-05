// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"context"
	"fmt"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
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
	pool *dispatcher.Pool[*vm.Instance]) *StraceResult {
	if cfg.StraceBin == "" {
		return straceFailed(fmt.Errorf("strace binary is not set in the config"))
	}
	var runRes *instance.RunResult
	var err error
	pool.Run(func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
		updInfo(func(info *dispatcher.Info) {
			info.Status = "running strace"
		})
		ret, setupErr := instance.SetupExecProg(inst, cfg, reporter,
			&instance.OptionalConfig{
				StraceBin:        cfg.StraceBin,
				BeforeContextLen: straceOutputLogSize,
			})
		if setupErr != nil {
			err = fmt.Errorf("failed to set up instance: %w", setupErr)
			return
		}
		if result.CRepro {
			log.Logf(1, "running C repro under strace")
			runRes, err = ret.RunCProg(result.Prog, result.Duration, result.Opts)
		} else {
			log.Logf(1, "running syz repro under strace")
			runRes, err = ret.RunSyzProg(result.Prog.Serialize(), result.Duration,
				result.Opts, instance.SyzExitConditions)
		}
	})
	if err != nil {
		return straceFailed(err)
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
