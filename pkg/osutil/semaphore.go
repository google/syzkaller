// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
)

type Semaphore struct {
	ch chan struct{}
}

func NewSemaphore(count int) *Semaphore {
	s := &Semaphore{
		ch: make(chan struct{}, count),
	}
	for i := 0; i < count; i++ {
		s.Signal()
	}
	return s
}

func (s *Semaphore) Wait() {
	<-s.ch
}

func (s *Semaphore) WaitC() <-chan struct{} {
	return s.ch
}

func (s *Semaphore) Available() int {
	return len(s.ch)
}

func (s *Semaphore) Signal() {
	if av := s.Available(); av == cap(s.ch) {
		// Not super reliable, but let it be here just in case.
		panic(fmt.Sprintf("semaphore capacity (%v) is exceeded (%v)", cap(s.ch), av))
	}
	s.ch <- struct{}{}
}
