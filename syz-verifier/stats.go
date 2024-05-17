// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
)

type StatUint64 struct {
	uint64
	mu *sync.Mutex
}

func (s *StatUint64) Inc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uint64++
}

func (s *StatUint64) Get() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uint64
}

type StatTime struct {
	time.Time
	mu *sync.Mutex
}

func (s *StatTime) Set(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Time = t
}

func (s *StatTime) Get() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Time
}

type mapStringToCallStats map[string]*CallStats

type StatMapStringToCallStats struct {
	mapStringToCallStats
	mu *sync.Mutex
}

func (stat *StatMapStringToCallStats) IncCallOccurrenceCount(key string) {
	stat.mu.Lock()
	stat.mapStringToCallStats[key].Occurrences++
	stat.mu.Unlock()
}

func (stat *StatMapStringToCallStats) AddState(key string, state ReturnState) {
	stat.mu.Lock()
	stat.mapStringToCallStats[key].States[state] = true
	stat.mu.Unlock()
}

func (stat *StatMapStringToCallStats) SetCallInfo(key string, info *CallStats) {
	stat.mu.Lock()
	stat.mapStringToCallStats[key] = info
	stat.mu.Unlock()
}

func (stat *StatMapStringToCallStats) totalExecuted() uint64 {
	stat.mu.Lock()
	defer stat.mu.Unlock()

	var t uint64
	for _, cs := range stat.mapStringToCallStats {
		t += cs.Occurrences
	}
	return t
}

func (stat *StatMapStringToCallStats) orderedStats() []*CallStats {
	stat.mu.Lock()
	defer stat.mu.Unlock()

	css := make([]*CallStats, 0)
	for _, cs := range stat.mapStringToCallStats {
		if cs.Mismatches > 0 {
			css = append(css, cs)
		}
	}

	sort.Slice(css, func(i, j int) bool {
		return getPercentage(css[i].Mismatches, css[i].Occurrences) > getPercentage(css[j].Mismatches, css[j].Occurrences)
	})

	return css
}

// Stats encapsulates data for creating statistics related to the results
// of the verification process.
type Stats struct {
	mu                  sync.Mutex
	TotalCallMismatches StatUint64
	TotalProgs          StatUint64
	ExecErrorProgs      StatUint64
	FlakyProgs          StatUint64
	MismatchingProgs    StatUint64
	StartTime           StatTime
	// Calls stores statistics for all supported system calls.
	Calls StatMapStringToCallStats
}

func (stats *Stats) Init() *Stats {
	stats.TotalCallMismatches.mu = &stats.mu
	stats.TotalProgs.mu = &stats.mu
	stats.ExecErrorProgs.mu = &stats.mu
	stats.FlakyProgs.mu = &stats.mu
	stats.MismatchingProgs.mu = &stats.mu
	stats.StartTime.mu = &stats.mu
	stats.Calls.mu = &stats.mu
	return stats
}

func (stats *Stats) MismatchesFound() bool {
	return stats.TotalCallMismatches.Get() != 0
}

func (stats *Stats) IncCallMismatches(key string) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	stats.Calls.mapStringToCallStats[key].Mismatches++
	stats.TotalCallMismatches.uint64++
}

// CallStats stores information used to generate statistics for the
// system call.
type CallStats struct {
	// Name is the system call name.
	Name string
	// Mismatches stores the number of errno mismatches identified in the
	// verified programs for this system call.
	Mismatches uint64
	// Occurrences is the number of times the system call appeared in a
	// verified program.
	Occurrences uint64
	// States stores the kernel return state that caused mismatches.
	States map[ReturnState]bool
}

func (stats *CallStats) orderedStates() []string {
	states := stats.States
	ss := make([]string, 0, len(states))
	for s := range states {
		ss = append(ss, fmt.Sprintf("%q", s))
	}
	sort.Strings(ss)
	return ss
}

// MakeStats creates a stats object.
func MakeStats() *Stats {
	return (&Stats{
		Calls: StatMapStringToCallStats{
			mapStringToCallStats: make(mapStringToCallStats),
		},
	}).Init()
}

func (stats *Stats) SetCallInfo(key string, info *CallStats) {
	stats.Calls.SetCallInfo(key, info)
}

// SetSyscallMask initializes the allowed syscall list.
func (stats *Stats) SetSyscallMask(calls map[*prog.Syscall]bool) {
	stats.StartTime.Set(time.Now())

	for syscall := range calls {
		stats.SetCallInfo(syscall.Name, &CallStats{
			Name:   syscall.Name,
			States: make(map[ReturnState]bool)})
	}
}

// ReportGlobalStats creates a report with statistics about all the
// supported system calls for which errno mismatches were identified in
// the verified programs, shown in decreasing order.
func (stats *Stats) GetTextDescription(deltaTime float64) string {
	var result strings.Builder

	tc := stats.Calls.totalExecuted()
	fmt.Fprintf(&result, "total number of mismatches / total number of calls "+
		"executed: %d / %d (%0.2f %%)\n\n",
		stats.TotalCallMismatches.Get(), tc, getPercentage(stats.TotalCallMismatches.Get(), tc))
	fmt.Fprintf(&result, "programs / minute: %0.2f\n\n", float64(stats.TotalProgs.Get())/deltaTime)
	fmt.Fprintf(&result, "true mismatching programs: %d / total number of programs: %d (%0.2f %%)\n",
		stats.MismatchingProgs.Get(), stats.TotalProgs.Get(),
		getPercentage(stats.MismatchingProgs.Get(), stats.TotalProgs.Get()))
	fmt.Fprintf(&result, "flaky programs: %d / total number of programs: %d (%0.2f %%)\n\n",
		stats.FlakyProgs.Get(), stats.TotalProgs.Get(), getPercentage(stats.FlakyProgs.Get(), stats.TotalProgs.Get()))
	cs := stats.Calls.orderedStats()
	for _, c := range cs {
		fmt.Fprintf(&result, "%s\n", stats.getCallStatsTextDescription(c.Name))
	}

	return result.String()
}

// getCallStatsTextDescription creates a report with the current statistics for call.
func (stats *Stats) getCallStatsTextDescription(call string) string {
	totalCallMismatches := stats.TotalCallMismatches.Get()
	stats.mu.Lock()
	defer stats.mu.Unlock()
	syscallStat, ok := stats.Calls.mapStringToCallStats[call]
	if !ok {
		return ""
	}
	syscallName, mismatches, occurrences := syscallStat.Name, syscallStat.Mismatches, syscallStat.Occurrences
	return fmt.Sprintf("statistics for %s:\n"+
		"\t↳ mismatches of %s / occurrences of %s: %d / %d (%0.2f %%)\n"+
		"\t↳ mismatches of %s / total number of mismatches: "+
		"%d / %d (%0.2f %%)\n"+
		"\t↳ %d distinct states identified: %v\n", syscallName, syscallName, syscallName, mismatches, occurrences,
		getPercentage(mismatches, occurrences), syscallName, mismatches, totalCallMismatches,
		getPercentage(mismatches, totalCallMismatches),
		len(syscallStat.States), syscallStat.orderedStates())
}

func getPercentage(value, total uint64) float64 {
	return float64(value) / float64(total) * 100
}
