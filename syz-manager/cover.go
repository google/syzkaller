// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

var (
	cachedRepGenMu sync.Mutex
	cachedRepGen   *cover.ReportGenerator
)

func getReportGenerator(cfg *mgrconfig.Config, modules []cover.KernelModule) (*cover.ReportGenerator, error) {
	cachedRepGenMu.Lock()
	defer cachedRepGenMu.Unlock()
	if cachedRepGen == nil {
		log.Logf(0, "initializing coverage information...")
		rg, err := cover.MakeReportGenerator(cfg, cfg.KernelSubsystem, modules, cfg.RawCover)
		if err != nil {
			return nil, err
		}
		cachedRepGen = rg
	}
	return cachedRepGen, nil
}

func resetReportGenerator() {
	cachedRepGenMu.Lock()
	defer cachedRepGenMu.Unlock()
	cachedRepGen = nil
}

func coverToPCs(cfg *mgrconfig.Config, cov []uint64) []uint64 {
	pcs := make([]uint64, 0, len(cov))
	for _, pc := range cov {
		prev := backend.PreviousInstructionPC(cfg.SysTarget, cfg.Type, pc)
		pcs = append(pcs, prev)
	}
	return pcs
}
