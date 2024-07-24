// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stat"
)

type reproManagerView interface {
	runRepro(crash *Crash) *ReproResult // TODO: consider moving runRepro() to repro.go.
	needRepro(crash *Crash) bool
	resizeReproPool(size int)
}

type reproManager struct {
	Done chan *ReproResult

	statNumReproducing *stat.Val
	statPending        *stat.Val

	onlyOnce  bool
	mgr       reproManagerView
	parallel  chan struct{}
	pingQueue chan struct{}
	reproVMs  int

	mu          sync.Mutex
	queue       []*Crash
	reproducing map[string]bool
	attempted   map[string]bool
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
		attempted:   map[string]bool{},
	}
	ret.statNumReproducing = stat.New("reproducing", "Number of crashes being reproduced",
		stat.Console, stat.NoGraph, func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.reproducing)
		})
	ret.statPending = stat.New("pending", "Number of pending repro tasks",
		stat.Console, stat.NoGraph, func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.queue)
		})
	return ret
}

// startReproduction() is assumed to be called only once.
// The agument is the maximum number of VMs dedicated to the bug reproduction.
func (m *reproManager) StartReproduction() {
	count := 0
	for ; m.calculateReproVMs(count+1) <= m.reproVMs; count++ {
		m.parallel <- struct{}{}
	}
	log.Logf(0, "starting bug reproductions (max %d VMs, %d repros)", m.reproVMs, count)
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

	title := crash.FullTitle()
	if m.onlyOnce && m.attempted[title] {
		// Try to reproduce each bug at most 1 time in this mode.
		// Since we don't upload bugs/repros to dashboard, it likely won't have
		// the reproducer even if we succeeded last time, and will repeatedly
		// say it needs a repro.
		return
	}
	log.Logf(1, "scheduled a reproduction of '%v'", title)
	m.attempted[title] = true
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

	newBetter := func(base, new *Crash) bool {
		// First, serve manual requests.
		if new.manual != base.manual {
			return new.manual
		}
		// Then, deprioritize hub reproducers.
		if new.fromHub != base.fromHub {
			return !new.fromHub
		}
		return false
	}

	idx := -1
	for i, crash := range m.queue {
		if m.reproducing[crash.FullTitle()] {
			continue
		}
		if idx == -1 || newBetter(m.queue[idx], m.queue[i]) {
			idx = i
		}
	}
	if idx == -1 {
		return nil
	}
	crash := m.queue[idx]
	m.queue = slices.Delete(m.queue, idx, idx+1)
	return crash
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
		m.reproducing[crash.FullTitle()] = true
		m.adjustPoolSizeLocked()
		m.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()

			m.handle(crash)

			m.mu.Lock()
			delete(m.reproducing, crash.FullTitle())
			m.adjustPoolSizeLocked()
			m.mu.Unlock()

			m.parallel <- struct{}{}
			m.pingQueue <- struct{}{}
		}()
	}
}

func (m *reproManager) handle(crash *Crash) {
	log.Logf(0, "start reproducing '%v'", crash.FullTitle())

	res := m.mgr.runRepro(crash)

	crepro := false
	title := ""
	if res.repro != nil {
		crepro = res.repro.CRepro
		title = res.repro.Report.Title
	}
	log.Logf(0, "repro finished '%v', repro=%v crepro=%v desc='%v' hub=%v from_dashboard=%v",
		crash.FullTitle(), res.repro != nil, crepro, title, crash.fromHub, crash.fromDashboard,
	)
	m.Done <- res
}

func (m *reproManager) adjustPoolSizeLocked() {
	// Avoid the +-1 jitter by considering the repro queue size as well.

	// We process same-titled crashes sequentially, so only count unique ones.
	uniqueTitles := maps.Clone(m.reproducing)
	for _, crash := range m.queue {
		uniqueTitles[crash.FullTitle()] = true
	}

	needRepros := len(uniqueTitles)
	VMs := min(m.reproVMs, m.calculateReproVMs(needRepros))
	m.mgr.resizeReproPool(VMs)
}
