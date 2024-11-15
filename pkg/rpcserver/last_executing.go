// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
)

// LastExecuting keeps the given number of last executed programs
// for each proc in a VM, and allows to query this set after a crash.
type LastExecuting struct {
	count     int
	procs     []ExecRecord
	hanged    []ExecRecord // hanged programs, kept forever
	positions []int
}

type ExecRecord struct {
	ID   int
	Proc int
	Prog []byte
	Time time.Duration
}

func MakeLastExecuting(procs, count int) *LastExecuting {
	return &LastExecuting{
		count:     count,
		procs:     make([]ExecRecord, procs*count),
		positions: make([]int, procs),
	}
}

// Note execution of the 'prog' on 'proc' at time 'now'.
func (last *LastExecuting) Note(id, proc int, progData []byte, now time.Duration) {
	pos := &last.positions[proc]
	last.procs[proc*last.count+*pos] = ExecRecord{
		ID:   id,
		Proc: proc,
		Prog: progData,
		Time: now,
	}
	*pos++
	if *pos == last.count {
		*pos = 0
	}
}

// Note a hanged program.
func (last *LastExecuting) Hanged(id, proc int, progData []byte, now time.Duration) {
	last.hanged = append(last.hanged, ExecRecord{
		ID: id,
		// Use unique proc for these programs b/c pkg/repro will either use the program with matching ID,
		// of take the last program from each proc, and we want the hanged programs to be included.
		Proc: prog.MaxPids + len(last.hanged),
		Prog: progData,
		Time: now,
	})
}

// Returns a sorted set of last executing programs.
// The records are sorted by time in ascending order.
// ExecRecord.Time is the difference in start executing time between this
// program and the program that started executing last.
func (last *LastExecuting) Collect() []ExecRecord {
	procs := append(last.procs, last.hanged...)
	last.procs = nil // The type must not be used after this.
	last.hanged = nil
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].Time < procs[j].Time
	})
	max := procs[len(procs)-1].Time
	for i := len(procs) - 1; i >= 0; i-- {
		if procs[i].Time == 0 {
			procs = procs[i+1:]
			break
		}
		procs[i].Time = max - procs[i].Time
	}
	return procs
}

func PrependExecuting(rep *report.Report, lastExec []ExecRecord) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "last executing test programs:\n\n")
	for _, exec := range lastExec {
		fmt.Fprintf(buf, "%v ago: executing program %v (id=%v):\n%s\n", exec.Time, exec.Proc, exec.ID, exec.Prog)
	}
	fmt.Fprintf(buf, "kernel console output (not intermixed with test programs):\n\n")
	rep.Output = append(buf.Bytes(), rep.Output...)
	n := len(buf.Bytes())
	rep.StartPos += n
	rep.EndPos += n
	rep.SkipPos += n
}
