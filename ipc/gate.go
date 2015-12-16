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
	cv   *sync.Cond
	busy []bool
	pos  int
}

func NewGate(c int) *Gate {
	return &Gate{
		cv:   sync.NewCond(new(sync.Mutex)),
		busy: make([]bool, c),
	}
}

func (g *Gate) Enter() int {
	g.cv.L.Lock()
	for g.busy[g.pos] {
		g.cv.Wait()
	}
	idx := g.pos
	g.pos++
	if g.pos >= len(g.busy) {
		g.pos = 0
	}
	g.busy[idx] = true
	g.cv.L.Unlock()
	return idx
}

func (g *Gate) Leave(idx int, f func()) {
	g.cv.L.Lock()
	if !g.busy[idx] {
		panic("broken gate")
	}
	if f != nil {
		f()
	}
	g.busy[idx] = false
	if idx == g.pos {
		g.cv.Broadcast()
	}
	g.cv.L.Unlock()
}
