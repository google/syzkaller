// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/google/syzkaller/prog"
)

// Stats encapsulates data for creating statistics related to the results
// of the verification process.
type Stats struct {
	// Calls stores statistics for all supported system calls.
	Calls            map[string]*CallStats
	TotalMismatches  int
	TotalProgs       int
	FlakyProgs       int
	MismatchingProgs int
	StartTime        time.Time
}

// CallStats stores information used to generate statistics for the
// system call.
type CallStats struct {
	// Name is the system call name.
	Name string
	// Mismatches stores the number of errno mismatches identifed in the
	// verified programs for this system call.
	Mismatches int
	// Occurrences is the number of times the system call appeared in a
	// verified program.
	Occurrences int
	// States stores the kernel return state that caused mismatches.
	States map[ReturnState]bool
}

// InitStats creates a stats object that will report verification
// statistics when an os.Interrupt occurs.
func InitStats(calls map[*prog.Syscall]bool, w io.Writer) *Stats {
	s := &Stats{
		Calls:     make(map[string]*CallStats),
		StartTime: time.Now(),
	}
	for c := range calls {
		s.Calls[c.Name] = &CallStats{
			Name:   c.Name,
			States: make(map[ReturnState]bool)}
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		dt := time.Since(s.StartTime).Minutes()
		if s.TotalMismatches < 0 {
			fmt.Fprint(w, "No mismatches occurred until syz-verifier was stopped.")
			os.Exit(0)
		}
		s.ReportGlobalStats(w, dt)
		os.Exit(0)
	}()

	return s
}

// ReportCallStats creates a report with the current statistics for call.
func (s *Stats) ReportCallStats(call string) string {
	cs, ok := s.Calls[call]
	if !ok {
		return ""
	}
	name, m, o := cs.Name, cs.Mismatches, cs.Occurrences
	data := fmt.Sprintf("statistics for %s:\n"+
		"\t↳ mismatches of %s / occurrences of %s: %d / %d (%0.2f %%)\n"+
		"\t↳ mismatches of %s / total number of mismatches: "+
		"%d / %d (%0.2f %%)\n"+
		"\t↳ %d distinct states identified: %v\n", name, name, name, m, o,
		getPercentage(m, o), name, m, s.TotalMismatches,
		getPercentage(m, s.TotalMismatches), len(cs.States), s.getOrderedStates(name))
	return data
}

func getPercentage(value, total int) float64 {
	return float64(value) / float64(total) * 100
}

// ReportGlobalStats creates a report with statistics about all the
// supported system calls for which errno mismatches were identified in
// the verified programs, shown in decreasing order.
func (s *Stats) ReportGlobalStats(w io.Writer, deltaTime float64) {
	tc := s.totalCallsExecuted()
	fmt.Fprintf(w, "total number of mismatches / total number of calls "+
		"executed: %d / %d (%0.2f %%)\n\n", s.TotalMismatches, tc, getPercentage(s.TotalMismatches, tc))
	fmt.Fprintf(w, "programs / minute: %0.2f\n\n", float64(s.TotalProgs)/deltaTime)
	fmt.Fprintf(w, "true mismatching programs: %d / total number of programs: %d (%0.2f %%)\n",
		s.MismatchingProgs, s.TotalProgs, getPercentage(s.MismatchingProgs, s.TotalProgs))
	fmt.Fprintf(w, "flaky programs: %d / total number of programs: %d (%0.2f %%)\n\n",
		s.FlakyProgs, s.TotalProgs, getPercentage(s.FlakyProgs, s.TotalProgs))
	cs := s.getOrderedStats()
	for _, c := range cs {
		fmt.Fprintf(w, "%s\n", s.ReportCallStats(c.Name))
	}
}

func (s *Stats) totalCallsExecuted() int {
	t := 0
	for _, cs := range s.Calls {
		t += cs.Occurrences
	}
	return t
}

func (s *Stats) getOrderedStats() []*CallStats {
	css := make([]*CallStats, 0)
	for _, cs := range s.Calls {
		if cs.Mismatches > 0 {
			css = append(css, cs)
		}
	}

	sort.Slice(css, func(i, j int) bool {
		return getPercentage(css[i].Mismatches, css[i].Occurrences) > getPercentage(css[j].Mismatches, css[j].Occurrences)
	})

	return css
}

func (s *Stats) getOrderedStates(call string) []string {
	states := s.Calls[call].States
	ss := make([]string, 0, len(states))
	for s := range states {
		ss = append(ss, fmt.Sprintf("%q", s))
	}
	sort.Strings(ss)
	return ss
}
