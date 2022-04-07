// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"syscall"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// ExecResult stores the results of executing a program.
type ExecResult struct {
	// Pool is the index of the pool.
	Pool int
	// Hanged is set to true when a program was killed due to hanging.
	Hanged bool
	// Info contains information about the execution of each system call
	// in the generated programs.
	Info ipc.ProgInfo
	// Crashed is set to true if a crash occurred while executing the program.
	// TODO: is not used properly. Crashes are just an errors now.
	Crashed bool
	// Source task ID is used to route result back to the caller.
	ExecTaskID int64
	// To signal the processing errors.
	Error error
}

func (l *ExecResult) IsEqual(r *ExecResult) bool {
	if l.Crashed || r.Crashed {
		return false
	}

	lCalls := l.Info.Calls
	rCalls := r.Info.Calls

	if len(lCalls) != len(rCalls) {
		return false
	}

	for i := 0; i < len(lCalls); i++ {
		if lCalls[i].Errno != rCalls[i].Errno ||
			lCalls[i].Flags != rCalls[i].Flags {
			return false
		}
	}

	return true
}

type ResultReport struct {
	// Prog is the serialized program.
	Prog string
	// Reports contains information about each system call.
	Reports []*CallReport
	// Mismatch says whether the Reports differ.
	Mismatch bool
}

type CallReport struct {
	// Call is the name of the system call.
	Call string
	// States is a map between pools and their return state when executing the system call.
	States map[int]ReturnState
	// Mismatch is set to true if the returned error codes were not the same.
	Mismatch bool
}

// ReturnState stores the results of executing a system call.
type ReturnState struct {
	// Errno is returned by executing the system call.
	Errno int
	// Flags stores the call flags (see pkg/ipc/ipc.go).
	Flags ipc.CallFlags
	// Crashed is set to true if the kernel crashed while executing the program
	// that contains the system call.
	Crashed bool
}

func (s ReturnState) String() string {
	state := ""

	if s.Crashed {
		return "Crashed"
	}

	state += fmt.Sprintf("Flags: %d, ", s.Flags)
	errDesc := "success"
	if s.Errno != 0 {
		errDesc = syscall.Errno(s.Errno).Error()
	}
	state += fmt.Sprintf("Errno: %d (%s)", s.Errno, errDesc)
	return state
}

// CompareResults checks whether the ExecResult of the same program,
// executed on different kernels, are the same.
// It returns s ResultReport, highlighting the differences.
func CompareResults(res []*ExecResult, prog *prog.Prog) *ResultReport {
	rr := &ResultReport{
		Prog: string(prog.Serialize()),
	}

	// Build the CallReport for each system call in the program.
	for idx, call := range prog.Calls {
		cn := call.Meta.Name

		cr := &CallReport{
			Call:   cn,
			States: map[int]ReturnState{},
		}

		for _, r := range res {
			if r.Crashed {
				cr.States[r.Pool] = ReturnState{Crashed: true}
				continue
			}

			ci := r.Info.Calls[idx]
			cr.States[r.Pool] = ReturnState{Errno: ci.Errno, Flags: ci.Flags}
		}
		rr.Reports = append(rr.Reports, cr)
	}

	pool0 := res[0].Pool
	for _, cr := range rr.Reports {
		for _, state := range cr.States {
			// For each CallReport, verify whether the ReturnStates from all
			// the pools that executed the program are the same
			if state0 := cr.States[pool0]; state0 != state {
				cr.Mismatch = true
				rr.Mismatch = true
			}
		}
	}

	return rr
}
