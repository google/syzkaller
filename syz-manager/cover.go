// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

var getReportGenerator = func() func(cfg *mgrconfig.Config,
	modules []host.KernelModule) (*cover.ReportGenerator, error) {
	var once sync.Once
	var rg *cover.ReportGenerator
	var err error
	return func(cfg *mgrconfig.Config, modules []host.KernelModule) (*cover.ReportGenerator, error) {
		once.Do(func() {
			log.Logf(0, "initializing coverage information...")
			rg, err = cover.MakeReportGenerator(cfg.SysTarget, cfg.Type, cfg.KernelObj, cfg.KernelSrc,
				cfg.KernelBuildSrc, cfg.KernelSubsystem, cfg.ModuleObj, modules)
		})
		return rg, err
	}
}()

func coverToPCs(target *targets.Target, modules []host.KernelModule, rg *cover.ReportGenerator, cov map[string][]uint32) []uint64 {
	var pcs []uint64
	if len(modules) == 0 {
		modules = append(modules, host.KernelModule{
			Name: "",
		})
	}
	for mod, offsets := range cov {
		for _, offset := range offsets {
			for _, module := range modules {
				if module.Name == mod {
					if module.Name == "" {
						pcs = append(pcs, backend.NextInstructionPC(target, rg.RestorePC(offset)))
					} else {
						pcs = append(pcs, module.Addr+uint64(offset))
					}
					break
				}
			}
		}
	}
	return pcs
}
