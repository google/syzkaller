// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package verf contains utilities for verifying the execution of the same
// program on different kernels yield the same results.
package verf

import (
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-verifier/stats"
)

// Result stores the results of executing a program.
type Result struct {
	// Pool is the index of the pool.
	Pool int
	// Hanged is set to true when a program was killed due to hanging.
	Hanged bool
	// Info contains information about the execution of each system call
	// in the generated programs.
	Info ipc.ProgInfo
}

type ResultReport struct {
	// Prog is the serialized program.
	Prog string
	// Reports contains information about each system call.
	Reports []CallReport
}

type CallReport struct {
	Call string
	// Errno is a map between pools and the errno returned by executing the
	// system call on a VM spawned by the respective pool.
	Errnos map[int]int
	// Flags is a map between pools and call flags (see pkg/ipc/ipc.go).
	Flags map[int]ipc.CallFlags
	// Mismatch is set to true if the returned error codes were not the same.
	Mismatch bool
}

// Verify checks whether the Results of the same program, executed on different
// kernels are the same. If that's not the case, it returns a ResultReport
// which highlights the differences.
func Verify(res []*Result, prog *prog.Prog, s *stats.Stats) *ResultReport {
	rr := &ResultReport{
		Prog: string(prog.Serialize()),
	}
	c0 := res[0].Info.Calls
	for idx, c := range c0 {
		call := prog.Calls[idx].Meta.Name
		cr := CallReport{
			Call:   call,
			Errnos: map[int]int{res[0].Pool: c.Errno},
			Flags:  map[int]ipc.CallFlags{res[0].Pool: c.Flags},
		}

		rr.Reports = append(rr.Reports, cr)
		cs := s.Calls[call]
		cs.Occurrences++
		cs.States[c.Errno] = true
	}

	var send bool
	for i := 1; i < len(res); i++ {
		resi := res[i]
		ci := resi.Info.Calls
		for idx, c := range ci {
			cr := rr.Reports[idx]
			cs := s.Calls[cr.Call]
			if c.Errno != c0[idx].Errno {
				rr.Reports[idx].Mismatch = true
				send = true

				s.TotalMismatches++
				cs.Mismatches++
				cs.States[c.Errno] = true
			}

			cr.Errnos[resi.Pool] = c.Errno
			cr.Flags[resi.Pool] = c.Flags
		}
	}

	if send {
		return rr
	}
	return nil
}
