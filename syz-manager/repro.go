// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stats"
)

type reproManagerView interface {
	runRepro(crash *Crash) *ReproResult // TODO: consider moving runRepro() to repro.go.
	needRepro(crash *Crash) bool
	resizeReproPool(size int)
}

type reproManager struct {
	Done chan *ReproResult

	statNumReproducing *stats.Val
	statPending        *stats.Val

	onlyOnce  bool
	mgr       reproManagerView
	parallel  chan struct{}
	pingQueue chan struct{}
	reproVMs  int

	mu          sync.Mutex
	queue       []*Crash
	reproducing map[string]bool
}

func newReproManager(mgr reproManagerView, reproVMs int, onlyOnce bool) *reproManager {
	ret := &reproManager{
		Done: make(chan *ReproResult, 10),

		mgr:         mgr,
		onlyOnce:    onlyOnce,
		parallel:    make(chan struct{}, reproVMs),
		reproVMs:    reproVMs,
		reproducing: map[string]bool{},
		pingQueue:   make(chan struct{}, 1),
	}
	ret.statNumReproducing = stats.Create("reproducing", "Number of crashes being reproduced",
		stats.Console, stats.NoGraph, func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.reproducing)
		})
	ret.statPending = stats.Create("pending", "Number of pending repro tasks",
		stats.Console, stats.NoGraph, func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.queue)
		})
	return ret
}

// startReproduction() is assumed to be called only once.
// The agument is the maximum number of VMs dedicated to the bug reproduction.
func (m *reproManager) StartReproduction() {
	log.Logf(1, "starting reproductions (max %d VMs)", m.reproVMs)

	for count := 1; m.calculateReproVMs(count) <= m.reproVMs; count++ {
		m.parallel <- struct{}{}
	}
}

func (m *reproManager) calculateReproVMs(repros int) int {
	// Let's allocate 1.33 VMs per a reproducer thread.
	if m.reproVMs == 1 && repros == 1 {
		// With one exception -- if we have only one VM, let's still do one repro.
		return 1
	}
	return (repros*4 + 2) / 3
}

func (m *reproManager) CanReproMore() bool {
	return len(m.parallel) != 0
}

func (m *reproManager) Reproducing() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.reproducing)
}

// Empty returns true if there are neither running nor planned bug reproductions.
func (m *reproManager) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reproducing) == 0 && len(m.queue) == 0
}

func (m *reproManager) Enqueue(crash *Crash) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.onlyOnce {
		// Try to reproduce each bug at most 1 time in this mode.
		// Since we don't upload bugs/repros to dashboard, it likely won't have
		// the reproducer even if we succeeded last time, and will repeatedly
		// say it needs a repro.
		for _, queued := range m.queue {
			if queued.Title == crash.Title {
				return
			}
		}
	}
	log.Logf(1, "scheduled a reproduction of '%v'", crash.Title)
	m.queue = append(m.queue, crash)

	// Ping the loop.
	select {
	case m.pingQueue <- struct{}{}:
	default:
	}
}

func (m *reproManager) popCrash() *Crash {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, crash := range m.queue {
		if m.reproducing[crash.Title] {
			continue
		}
		m.queue = slices.Delete(m.queue, i, i+1)
		return crash
	}
	return nil
}

func (m *reproManager) Loop(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		crash := m.popCrash()
		for crash == nil {
			select {
			case <-m.pingQueue:
				crash = m.popCrash()
			case <-ctx.Done():
				return
			}
			if crash == nil || !m.mgr.needRepro(crash) {
				continue
			}
		}

		// Now wait until we can schedule another runner.
		select {
		case <-m.parallel:
		case <-ctx.Done():
			return
		}

		m.mu.Lock()
		m.reproducing[crash.Title] = true
		m.adjustPoolSizeLocked()
		m.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()

			m.handle(crash)

			m.mu.Lock()
			delete(m.reproducing, crash.Title)
			m.adjustPoolSizeLocked()
			m.mu.Unlock()

			m.parallel <- struct{}{}
			m.pingQueue <- struct{}{}
		}()
	}
}

func (m *reproManager) handle(crash *Crash) {
	log.Logf(0, "start reproducing '%v'", crash.Title)

	res := m.mgr.runRepro(crash)

	crepro := false
	title := ""
	if res.repro != nil {
		crepro = res.repro.CRepro
		title = res.repro.Report.Title
	}
	log.Logf(0, "repro finished '%v', repro=%v crepro=%v desc='%v' hub=%v from_dashboard=%v",
		res.report0.Title, res.repro != nil, crepro, title, res.fromHub, res.fromDashboard,
	)
	m.Done <- res
}

func (m *reproManager) adjustPoolSizeLocked() {
	// Avoid the +-1 jitter by considering the repro queue size as well.

	// We process same-titled crashes sequentially, so only count unique ones.
	uniqueTitles := maps.Clone(m.reproducing)
	for _, crash := range m.queue {
		uniqueTitles[crash.Title] = true
	}

	needRepros := len(uniqueTitles)
	VMs := min(m.reproVMs, m.calculateReproVMs(needRepros))
	m.mgr.resizeReproPool(VMs)
}
