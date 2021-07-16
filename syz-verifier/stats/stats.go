// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package stats contains utilities that aid gathering statistics of
// system call mismatches in the verified programs.
package stats

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"

	"github.com/google/syzkaller/prog"
)

// Stats encapsulates data for creating statistics related to the results
// of the verification process.
type Stats struct {
	// Calls stores statistics for all supported system calls.
	Calls           map[string]*CallStats
	TotalMismatches int
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
	// States stores all possible kernel return values identified for the
	// system call.
	States map[int]bool
}

// InitStats creates a stats object that will report verification
// statistics when an os.Interrupt occurs.
func InitStats(calls map[*prog.Syscall]bool, w io.Writer) *Stats {
	s := &Stats{Calls: make(map[string]*CallStats)}
	for c := range calls {
		s.Calls[c.Name] = &CallStats{Name: c.Name, States: make(map[int]bool)}
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		if s.TotalMismatches < 0 {
			fmt.Fprint(w, "No mismatches occurred until syz-verifier was stopped.")
			os.Exit(0)
		}
		s.ReportGlobalStats(w)
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
func (s *Stats) ReportGlobalStats(w io.Writer) {
	tc := s.totalCallsExecuted()
	fmt.Fprintf(w, "total number of mismatches / total number of calls "+
		"executed: %d / %d (%0.2f %%)\n\n", s.TotalMismatches, tc, getPercentage(s.TotalMismatches, tc))
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
		return css[i].Mismatches > css[j].Mismatches
	})

	return css
}

func (s *Stats) getOrderedStates(call string) []int {
	states := s.Calls[call].States
	ss := make([]int, 0, len(states))
	for s := range states {
		ss = append(ss, s)
	}
	sort.Ints(ss)
	return ss
}
