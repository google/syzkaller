// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/stat"
)

type ReproResult struct {
	Crash  *Crash // the original crash
	Repro  *repro.Result
	Strace *repro.StraceResult
	Stats  *repro.Stats
	Err    error
}

type Crash struct {
	InstanceIndex int
	FromHub       bool // this crash was created based on a repro from syz-hub
	FromDashboard bool // .. or from dashboard
	Manual        bool
	FullRepro     bool // used by the diff fuzzer to do a full scale reproduction
	*report.Report
	TailReports []*report.Report
	MemoryDump  string
}

func (c *Crash) FullTitle() string {
	suffix := ""
	if c.FullRepro {
		suffix = " (full)"
	}
	if c.Report.Title != "" {
		return c.Report.Title + suffix
	}
	// Just use some unique, but stable titles.
	if c.FromDashboard {
		return fmt.Sprintf("dashboard crash %p%s", c, suffix)
	} else if c.FromHub {
		return fmt.Sprintf("crash from hub %p%s", c, suffix)
	}
	panic("the crash is expected to have a report")
}

type ReproManagerView interface {
	RunRepro(ctx context.Context, crash *Crash) *ReproResult
	NeedRepro(crash *Crash) bool
	ResizeReproPool(size int)
}

type ReproLoop struct {
	statNumReproducing *stat.Val
	statPending        *stat.Val

	onlyOnce  bool
	mgr       ReproManagerView
	parallel  chan struct{}
	pingQueue chan struct{}
	reproVMs  int

	mu          sync.Mutex
	queue       []*Crash
	reproducing map[string]bool
	enqueued    map[string]bool
	attempts    map[string]int
}

func NewReproLoop(mgr ReproManagerView, reproVMs int, onlyOnce bool) *ReproLoop {
	ret := &ReproLoop{
		mgr:         mgr,
		onlyOnce:    onlyOnce,
		parallel:    make(chan struct{}, reproVMs),
		reproVMs:    reproVMs,
		reproducing: map[string]bool{},
		pingQueue:   make(chan struct{}, 1),
		enqueued:    map[string]bool{},
		attempts:    map[string]int{},
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

func (r *ReproLoop) CanReproMore() bool {
	return len(r.parallel) != 0
}

func (r *ReproLoop) Reproducing() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.reproducing)
}

// Empty returns true if there are neither running nor planned bug reproductions.
func (r *ReproLoop) Empty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reproducing) == 0 && len(r.queue) == 0
}

func (r *ReproLoop) Enqueue(crash *Crash) {
	r.mu.Lock()
	defer r.mu.Unlock()

	title := crash.FullTitle()
	if r.onlyOnce && r.enqueued[title] {
		// Try to reproduce each bug at most 1 time in this mode.
		// Since we don't upload bugs/repros to dashboard, it likely won't have
		// the reproducer even if we succeeded last time, and will repeatedly
		// say it needs a repro.
		return
	}
	log.Logf(1, "scheduled a reproduction of '%v'", title)
	r.enqueued[title] = true
	r.queue = append(r.queue, crash)

	// Ping the loop.
	select {
	case r.pingQueue <- struct{}{}:
	default:
	}
}

func (r *ReproLoop) popCrash() *Crash {
	r.mu.Lock()
	defer r.mu.Unlock()

	newBetter := func(base, new *Crash) bool {
		// If diff fuzzed has requested a full reproduction, do it first.
		if base.FullRepro != new.FullRepro {
			return new.FullRepro
		}
		// The more times we failed, the less likely we are to actually
		// find a reproducer. Give preference to not yet attempted repro runs.
		baseTitle, newTitle := base.FullTitle(), new.FullTitle()
		if r.attempts[baseTitle] != r.attempts[newTitle] {
			return r.attempts[newTitle] < r.attempts[baseTitle]
		}
		// First, serve manual requests.
		if new.Manual != base.Manual {
			return new.Manual
		}
		// Then, deprioritize hub reproducers.
		if new.FromHub != base.FromHub {
			return !new.FromHub
		}
		return false
	}

	idx := -1
	for i, crash := range r.queue {
		if r.reproducing[crash.FullTitle()] {
			continue
		}
		if idx == -1 || newBetter(r.queue[idx], r.queue[i]) {
			idx = i
		}
	}
	if idx == -1 {
		return nil
	}
	crash := r.queue[idx]
	r.queue = slices.Delete(r.queue, idx, idx+1)
	return crash
}

func (r *ReproLoop) Loop(ctx context.Context) {
	defer log.Logf(1, "repro loop terminated")

	count := 0
	for ; r.calculateReproVMs(count+1) <= r.reproVMs; count++ {
		r.parallel <- struct{}{}
	}
	log.Logf(0, "starting bug reproductions (max %d VMs, %d repros)", r.reproVMs, count)

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		crash := r.popCrash()
		for {
			if crash != nil && !r.mgr.NeedRepro(crash) {
				log.Logf(1, "reproduction of %q aborted: it's no longer needed", crash.FullTitle())
				// Now we might not need that many VMs.
				r.mu.Lock()
				r.adjustPoolSizeLocked()
				r.mu.Unlock()

				// Immediately check if there was any other crash in the queue, so that we fall back
				// to waiting on pingQueue only if there were really no other crashes in the queue.
				crash = r.popCrash()
				continue
			}
			if crash != nil {
				break
			}
			select {
			case <-r.pingQueue:
				crash = r.popCrash()
			case <-ctx.Done():
				return
			}
		}

		// Now wait until we can schedule another runner.
		select {
		case <-r.parallel:
		case <-ctx.Done():
			return
		}

		title := crash.FullTitle()
		r.mu.Lock()
		r.attempts[title]++
		r.reproducing[title] = true
		r.adjustPoolSizeLocked()
		r.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()

			r.handle(ctx, crash)

			r.mu.Lock()
			delete(r.reproducing, title)
			r.adjustPoolSizeLocked()
			r.mu.Unlock()

			r.parallel <- struct{}{}
			// If the context is cancelled, no one is listening on pingQueue.
			select {
			case r.pingQueue <- struct{}{}:
			default:
			}
		}()
	}
}

func (r *ReproLoop) calculateReproVMs(repros int) int {
	// Let's allocate 1.33 VMs per a reproducer thread.
	if r.reproVMs == 1 && repros == 1 {
		// With one exception -- if we have only one VM, let's still do one repro.
		return 1
	}
	return (repros*4 + 2) / 3
}

func (r *ReproLoop) handle(ctx context.Context, crash *Crash) {
	log.Logf(0, "start reproducing '%v'", crash.FullTitle())

	res := r.mgr.RunRepro(ctx, crash)

	crepro := false
	title := ""
	if res.Repro != nil {
		crepro = res.Repro.CRepro
		title = res.Repro.Report.Title
	}
	log.Logf(0, "repro finished '%v', repro=%v crepro=%v desc='%v' hub=%v from_dashboard=%v",
		crash.FullTitle(), res.Repro != nil, crepro, title, crash.FromHub, crash.FromDashboard,
	)
}

func (r *ReproLoop) adjustPoolSizeLocked() {
	// Avoid the +-1 jitter by considering the repro queue size as well.
	// We process same-titled crashes sequentially, so only count unique ones.
	uniqueTitles := maps.Clone(r.reproducing)
	for _, crash := range r.queue {
		uniqueTitles[crash.FullTitle()] = true
	}

	needRepros := len(uniqueTitles)
	VMs := min(r.reproVMs, r.calculateReproVMs(needRepros))
	r.mgr.ResizeReproPool(VMs)
}
