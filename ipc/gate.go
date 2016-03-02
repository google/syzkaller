// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"sync"
)

// Gate limits concurrency level and window to the given value.
// Limitation of concurrency window means that if a very old activity is still
// running it will not let new activities to start even if concurrency level is low.
type Gate struct {
	cv      *sync.Cond
	busy    []bool
	pos     int
	running int
	stop    bool
	f       func()
}

// If f is not nil, it will be called after each batch of c activities.
func NewGate(c int, f func()) *Gate {
	return &Gate{
		cv:   sync.NewCond(new(sync.Mutex)),
		busy: make([]bool, c),
		f:    f,
	}
}

func (g *Gate) Enter() int {
	g.cv.L.Lock()
	for g.busy[g.pos] || g.stop {
		g.cv.Wait()
	}
	idx := g.pos
	g.pos++
	if g.pos >= len(g.busy) {
		g.pos = 0
	}
	g.busy[idx] = true
	g.running++
	if g.running > len(g.busy) {
		panic("broken gate")
	}
	g.cv.L.Unlock()
	return idx
}

func (g *Gate) Leave(idx int) {
	g.cv.L.Lock()
	if !g.busy[idx] {
		panic("broken gate")
	}
	g.busy[idx] = false
	g.running--
	if g.running < 0 {
		panic("broken gate")
	}
	if idx == 0 && g.f != nil {
		if g.stop {
			panic("broken gate")
		}
		g.stop = true
		for g.running != 0 {
			g.cv.Wait()
		}
		g.stop = false
		g.f()
		g.cv.Broadcast()
	}
	if idx == g.pos && !g.stop || g.running == 0 && g.stop {
		g.cv.Broadcast()
	}
	g.cv.L.Unlock()
}
