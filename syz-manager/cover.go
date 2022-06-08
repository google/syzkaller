// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

var getReportGenerator = func() func(cfg *mgrconfig.Config,
	modules []host.KernelModule) (*cover.ReportGenerator, error) {
	var once sync.Once
	var rg *cover.ReportGenerator
	var err error
	return func(cfg *mgrconfig.Config, modules []host.KernelModule) (*cover.ReportGenerator, error) {
		once.Do(func() {
			start := time.Now()
			log.Logf(0, "initializing coverage information...")
			rg, err = cover.MakeReportGenerator(cfg.SysTarget, cfg.Type, cfg.KernelObj, cfg.KernelSrc,
				cfg.KernelBuildSrc, cfg.KernelSubsystem, cfg.ModuleObj, modules, cfg.RawCover)
			diff := time.Since(start)
			log.Logf(0, "MakeReportGenerator took %s", diff)
		})
		return rg, err
	}
}()

func coverToPCs(rg *cover.ReportGenerator, cov []uint32) []uint64 {
	pcs := make([]uint64, 0, len(cov))
	for _, pc := range cov {
		pcs = append(pcs, rg.RestorePC(pc))
	}
	return pcs
}
