// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sync/atomic"
)

type Stat uint64

type Stats struct {
	crashes          Stat
	crashTypes       Stat
	crashSuppressed  Stat
	vmRestarts       Stat
	newInputs        Stat
	execTotal        Stat
	hubSendProgAdd   Stat
	hubSendProgDel   Stat
	hubSendRepro     Stat
	hubRecvProg      Stat
	hubRecvProgDrop  Stat
	hubRecvRepro     Stat
	hubRecvReproDrop Stat
}

func (stats *Stats) all() map[string]uint64 {
	return map[string]uint64{
		"crashes":              stats.crashes.get(),
		"crash types":          stats.crashTypes.get(),
		"suppressed":           stats.crashSuppressed.get(),
		"vm restarts":          stats.vmRestarts.get(),
		"manager new inputs":   stats.newInputs.get(),
		"exec total":           stats.execTotal.get(),
		"hub: send prog add":   stats.hubSendProgAdd.get(),
		"hub: send prog del":   stats.hubSendProgDel.get(),
		"hub: send repro":      stats.hubSendRepro.get(),
		"hub: recv prog":       stats.hubRecvProg.get(),
		"hub: recv prog drop":  stats.hubRecvProgDrop.get(),
		"hub: recv repro":      stats.hubRecvRepro.get(),
		"hub: recv repro drop": stats.hubRecvReproDrop.get(),
	}
}

func (s *Stat) get() uint64 {
	return atomic.LoadUint64((*uint64)(s))
}

func (s *Stat) inc() {
	s.add(1)
}

func (s *Stat) add(v int) {
	atomic.AddUint64((*uint64)(s), uint64(v))
}
