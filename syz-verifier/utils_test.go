// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func createTestVerifier(t *testing.T) *Verifier {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to initialise test target: %v", err)
	}
	vrf := &Verifier{
		target:      target,
		choiceTable: target.DefaultChoiceTable(),
		progIdx:     3,
		reruns:      1,
	}
	vrf.resultsdir = makeTestResultDirectory(t)
	vrf.stats = emptyTestStats()
	vrf.srv, err = startRPCServer(vrf)
	if err != nil {
		t.Fatalf("failed to initialise RPC server: %v", err)
	}
	return vrf
}

func getTestProgram(t *testing.T) *prog.Prog {
	p := "breaks_returns()\n" +
		"minimize$0(0x1, 0x1)\n" +
		"test$res0()\n"
	target := prog.InitTargetTest(t, "test", "64")
	prog, err := target.Deserialize([]byte(p), prog.Strict)
	if err != nil {
		t.Fatalf("failed to deserialise test program: %v", err)
	}
	return prog
}

func makeTestResultDirectory(t *testing.T) string {
	return osutil.Abs(t.TempDir())
}

func makeExecResult(pool int, errnos []int, flags ...int) *ExecResult {
	r := &ExecResult{Pool: pool, Info: ipc.ProgInfo{Calls: []ipc.CallInfo{}}}
	for _, e := range errnos {
		r.Info.Calls = append(r.Info.Calls, ipc.CallInfo{Errno: e})
	}

	for idx, f := range flags {
		r.Info.Calls[idx].Flags = ipc.CallFlags(f)
	}
	return r
}

func makeExecResultCrashed(pool int) *ExecResult {
	return &ExecResult{Pool: pool, Crashed: true}
}

func emptyTestStats() *Stats {
	return (&Stats{
		Calls: StatMapStringToCallStats{
			mapStringToCallStats: mapStringToCallStats{
				"breaks_returns": {Name: "breaks_returns", States: map[ReturnState]bool{}},
				"minimize$0":     {Name: "minimize$0", States: map[ReturnState]bool{}},
				"test$res0":      {Name: "test$res0", States: map[ReturnState]bool{}},
			},
		},
	}).Init()
}

func makeCallStats(name string, occurrences, mismatches uint64, states map[ReturnState]bool) *CallStats {
	return &CallStats{Name: name,
		Occurrences: occurrences,
		Mismatches:  mismatches,
		States:      states}
}

func returnState(errno int, flags ...int) ReturnState {
	rs := ReturnState{Errno: errno}
	if flags != nil {
		rs.Flags = ipc.CallFlags(flags[0])
	}
	return rs
}

func crashedReturnState() ReturnState {
	return ReturnState{Crashed: true}
}
