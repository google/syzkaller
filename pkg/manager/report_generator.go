// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vminfo"
)

type ReportGeneratorWrapper struct {
	cfg     *mgrconfig.Config
	modules []*vminfo.KernelModule

	mu          sync.Mutex
	initialized bool
	cached      *cover.ReportGenerator
}

func ReportGeneratorCache(cfg *mgrconfig.Config) *ReportGeneratorWrapper {
	return &ReportGeneratorWrapper{cfg: cfg}
}

func (w *ReportGeneratorWrapper) Get() (*cover.ReportGenerator, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized {
		return nil, fmt.Errorf("report generator creation before Init() is called")
	}
	if w.cached == nil {
		log.Logf(0, "initializing coverage information...")
		rg, err := cover.MakeReportGenerator(w.cfg, w.cfg.KernelSubsystem, w.modules, w.cfg.RawCover)
		if err != nil {
			return nil, err
		}
		w.cached = rg
	}
	return w.cached, nil
}

func (w *ReportGeneratorWrapper) Init(modules []*vminfo.KernelModule) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.initialized {
		panic("Init() called twice")
	}
	w.initialized = true
	w.modules = modules
}

func (w *ReportGeneratorWrapper) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cached = nil
}

func CoverToPCs(cfg *mgrconfig.Config, cov []uint64) []uint64 {
	pcs := make([]uint64, 0, len(cov))
	for _, pc := range cov {
		prev := backend.PreviousInstructionPC(cfg.SysTarget, cfg.Type, pc)
		pcs = append(pcs, prev)
	}
	return pcs
}

func PCsToCover(cfg *mgrconfig.Config, pcs map[uint64]struct{}) map[uint64]struct{} {
	ret := make(map[uint64]struct{})
	for pc := range pcs {
		next := backend.NextInstructionPC(cfg.SysTarget, cfg.Type, pc)
		ret[next] = struct{}{}
	}
	return ret
}
