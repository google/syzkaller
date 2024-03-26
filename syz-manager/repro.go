// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"golang.org/x/sync/semaphore"
)

type reproManagerInterface interface {
	runRepro(crash *Crash, vmIndexes []int, putInstances func(...int)) *ReproResult
	needRepro(crash *Crash) bool
	saveRepro(res *ReproResult)
	saveFailedRepro(rep *report.Report, stats *repro.Stats)
}

type ReproResult struct {
	instances     []int
	report0       *report.Report // the original report we started reproducing
	repro         *repro.Result
	strace        *repro.StraceResult
	stats         *repro.Stats
	err           error
	fromHub       bool
	fromDashboard bool
	originalTitle string // crash title before we started bug reproduction
}

type reproLoop struct {
	ctx context.Context
	mgr reproManagerInterface

	maxVMs int

	// Public fields.
	NumReproducing atomic.Uint32
	NumPending     atomic.Uint32

	// We want to limit the number of simultaneous calls to needRepro().
	triageMu sync.Mutex

	// TODO: can we use just one sem?
	maxVMSem    *semaphore.Weighted // to ensure we don't take more than maxVMs at the same time
	reproVMs    *ResourcePool
	needVMsMu   sync.Mutex
	needVMs     int
	reproducing sync.Map
}

func newReproLoop(ctx context.Context, reproVMs int, mgr reproManagerInterface) *reproLoop {
	return &reproLoop{
		ctx:      ctx,
		mgr:      mgr,
		maxVMs:   reproVMs,
		maxVMSem: semaphore.NewWeighted(int64(reproVMs)),
		reproVMs: EmptyResourcePool(ctx, reproVMs),
	}
}

func (rl *reproLoop) Process(crash *Crash, putInstances func(...int)) {
	if rl.maxVMs == 0 {
		return
	}
	if _, loaded := rl.reproducing.LoadOrStore(crash.Title, true); loaded {
		return
	}
	defer rl.reproducing.Delete(crash.Title)

	rl.NumPending.Add(1)
	if !rl.needRepro(crash) {
		log.Logf(1, "repro loop: don't need to reproduce '%v'", crash.Title)
		rl.NumPending.Add(^uint32(0))
		return
	}
	log.Logf(1, "repro loop: added '%v' to the queue", crash.Title)

	vmIndices := rl.takeVMs(rl.vmsForCrash(crash))
	if vmIndices == nil {
		return
	}

	rl.NumPending.Add(^uint32(0))
	rl.NumReproducing.Add(1)
	defer rl.NumReproducing.Add(^uint32(0))

	log.Logf(0, "repro loop: starting repro of '%v' on instances %+v", crash.Title, vmIndices)

	result := rl.mgr.runRepro(crash, vmIndices, func(ids ...int) {
		// By releasing the semaphore before returning the VM to the
		// caller we make sure that the following call to TakeInstance()
		// definitely returns true.
		rl.maxVMSem.Release(int64(len(ids)))
		putInstances(ids...)
	})
	rl.saveResult(result)
}

// TakeInstance() records that a new instance has become available.
// If the instance is to be reserved for reproduction, it returns true.
func (rl *reproLoop) TakeInstance(idx int) bool {
	if rl == nil {
		return false
	}
	rl.needVMsMu.Lock()
	defer rl.needVMsMu.Unlock()

	if rl.needVMs == 0 || !rl.maxVMSem.TryAcquire(1) {
		return false
	}
	log.Logf(0, "took %d", idx)
	rl.needVMs--
	rl.reproVMs.Put(idx)
	return true
}

func (rl *reproLoop) WantVMs() bool {
	rl.needVMsMu.Lock()
	defer rl.needVMsMu.Unlock()
	if rl.needVMs == 0 {
		return false
	}
	if !rl.maxVMSem.TryAcquire(1) {
		return false
	}
	rl.maxVMSem.Release(1)
	return true
}

// Reproducing() returns a snapshot of the currently reproduced bug titles.
func (rl *reproLoop) Reproducing() map[string]bool {
	ret := map[string]bool{}
	rl.reproducing.Range(func(key, _ any) bool {
		ret[key.(string)] = true
		return true
	})
	return ret
}

func (rl *reproLoop) takeVMs(needVMs int) []int {
	rl.needVMsMu.Lock()
	rl.needVMs += needVMs
	rl.needVMsMu.Unlock()
	return rl.reproVMs.Take(needVMs)
}

func (rl *reproLoop) vmsForCrash(crash *Crash) int {
	const hubVMs = 2
	const normalVMs = 3

	ret := normalVMs
	if crash.fromHub || crash.fromDashboard {
		// We need fewer VMs for hub reproducers since they are already extracted and minimized.
		ret = hubVMs
	}
	if ret > rl.maxVMs {
		return rl.maxVMs
	}
	return ret
}

func (rl *reproLoop) needRepro(crash *Crash) bool {
	// We don't care much about the specific order,
	// but we do want to call mgr.needRepro() sequentially.
	rl.triageMu.Lock()
	defer rl.triageMu.Unlock()
	return rl.mgr.needRepro(crash)
}

func (rl *reproLoop) saveResult(res *ReproResult) {
	crepro := false
	title := ""
	if res.repro != nil {
		crepro = res.repro.CRepro
		title = res.repro.Report.Title
	}
	log.Logf(0, "repro loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'"+
		" hub=%v from_dashboard=%v",
		res.instances, res.report0.Title, res.repro != nil, crepro, title,
		res.fromHub, res.fromDashboard,
	)
	if res.err != nil {
		reportReproError(res.err)
	}
	if res.repro == nil {
		if res.fromHub {
			log.Logf(1, "repro '%v' came from syz-hub, not reporting the failure",
				res.report0.Title)
		} else {
			log.Logf(1, "report repro failure of '%v'", res.report0.Title)
			rl.mgr.saveFailedRepro(res.report0, res.stats)
		}
	} else {
		rl.mgr.saveRepro(res)
	}
}
