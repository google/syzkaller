// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

var (
	cachedRepGenMu sync.Mutex
	cachedRepGen   *cover.ReportGenerator
)

func getReportGenerator(cfg *mgrconfig.Config, modules []host.KernelModule) (*cover.ReportGenerator, error) {
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

func coverToPCs(rg *cover.ReportGenerator, cov []uint32) []uint64 {
	pcs := make([]uint64, 0, len(cov))
	for _, pc := range cov {
		pcs = append(pcs, rg.RestorePC(pc))
	}
	return pcs
}
