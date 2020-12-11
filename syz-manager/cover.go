// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

var (
	initCoverOnce   sync.Once
	initCoverError  error
	reportGenerator *cover.ReportGenerator
)

func initCover(cfg *mgrconfig.Config) error {
	initCoverOnce.Do(func() {
		if cfg.KernelObj == "" {
			initCoverError = fmt.Errorf("kernel_obj is not specified")
			return
		}
		reportGenerator, initCoverError = cover.MakeReportGenerator(
			cfg.SysTarget, cfg.Type, cfg.KernelObj, cfg.KernelSrc, cfg.KernelBuildSrc)
	})
	return initCoverError
}

func coverToPCs(target *targets.Target, cov []uint32) []uint64 {
	pcs := make([]uint64, 0, len(cov))
	for _, pc := range cov {
		fullPC := cover.RestorePC(pc, reportGenerator.TextOffset)
		prevPC := cover.PreviousInstructionPC(target, fullPC)
		pcs = append(pcs, prevPC)
	}
	return pcs
}
