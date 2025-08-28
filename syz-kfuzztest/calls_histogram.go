package main

import (
	"fmt"
	"sync"

	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/prog"
)

type stats struct {
	// One entry per call name.
	entries map[string]*statEntry
}

// Per-call stat entry.
type statEntry struct {
	mutex        sync.Mutex
	failures     uint64
	execs        uint64
	lastExecuted *prog.Call
}

func (s *stats) Poll() (uint64, uint64) {
	totalExecs := uint64(0)
	totalFailures := uint64(0)

	for _, statEntry := range s.entries {
		statEntry.mutex.Lock()
		totalExecs += statEntry.execs
		totalFailures += statEntry.failures
		statEntry.mutex.Unlock()
	}

	return totalExecs, totalFailures
}

func (s *stats) Report(res kfuzztest.ExecResult) error {
	callName, ok := kfuzztest.GetTestName(res.Call.Meta)
	if !ok {
		return fmt.Errorf("report for non-syz_kfuzztest_run call")
	}

	entry, ok := s.entries[callName]
	if !ok {
		return fmt.Errorf("no entry for %s", res.Call.Meta.CallName)
	}

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	entry.execs++
	if !res.Success {
		entry.failures++
	} else {
		entry.lastExecuted = res.Call
	}
	return nil
}

func newStats(callNames []string) *stats {
	var ret stats
	ret.entries = make(map[string]*statEntry)

	for _, call := range callNames {
		ret.entries[call] = &statEntry{}
	}

	return &ret
}
