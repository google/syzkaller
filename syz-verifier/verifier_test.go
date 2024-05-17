// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

func TestFinalizeCallSet(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to initialise test target: %v", err)
	}

	vrf := Verifier{
		target: target,
		reasons: map[*prog.Syscall]string{
			target.SyscallMap["test$res0"]:  "foo",
			target.SyscallMap["minimize$0"]: "bar",
		},
		calls: map[*prog.Syscall]bool{
			target.SyscallMap["minimize$0"]: true,
			target.SyscallMap["test$res0"]:  true,
			target.SyscallMap["disabled1"]:  true,
		},
		reportReasons: true,
	}

	out := bytes.Buffer{}
	vrf.finalizeCallSet(&out)
	wantLines := []string{
		"The following calls have been disabled:\n",
		"\ttest$res0: foo\n",
		"\tminimize$0: bar\n",
	}
	output := out.String()
	for _, line := range wantLines {
		if !strings.Contains(output, line) {
			t.Errorf("finalizeCallSet: %q missing in reported output", line)
		}
	}

	wantCalls, gotCalls := map[*prog.Syscall]bool{
		target.SyscallMap["disabled1"]: true,
	}, vrf.calls
	if diff := cmp.Diff(wantCalls, gotCalls); diff != "" {
		t.Errorf("srv.calls mismatch (-want +got):\n%s", diff)
	}
}

func TestUpdateUnsupported(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to initialise test target: %v", err)
	}

	tests := []struct {
		name           string
		vrfPools       map[int]*poolInfo
		wantPools      map[int]*poolInfo
		wantCalls      map[*prog.Syscall]bool
		wantNotChecked int
		nilCT          bool
	}{
		{
			name:           "choice table not generated",
			vrfPools:       map[int]*poolInfo{0: {}, 1: {}},
			wantPools:      map[int]*poolInfo{0: {checked: true}, 1: {}},
			wantNotChecked: 1,
			wantCalls: map[*prog.Syscall]bool{
				target.SyscallMap["minimize$0"]:     true,
				target.SyscallMap["breaks_returns"]: true,
				target.SyscallMap["test$res0"]:      true,
				target.SyscallMap["test$union0"]:    true,
			},
			nilCT: true,
		},
		{
			name:           "choice table generated",
			vrfPools:       map[int]*poolInfo{0: {}},
			wantPools:      map[int]*poolInfo{0: {checked: true}},
			wantNotChecked: 0,
			wantCalls: map[*prog.Syscall]bool{
				target.SyscallMap["minimize$0"]:     true,
				target.SyscallMap["breaks_returns"]: true,
			},
			nilCT: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vrf := Verifier{
				target:        target,
				pools:         test.vrfPools,
				reasons:       make(map[*prog.Syscall]string),
				reportReasons: true,
				calls: map[*prog.Syscall]bool{
					target.SyscallMap["minimize$0"]:     true,
					target.SyscallMap["breaks_returns"]: true,
					target.SyscallMap["test$res0"]:      true,
					target.SyscallMap["test$union0"]:    true,
				},
				stats: MakeStats(),
			}
			vrf.Init()

			a := &rpctype.UpdateUnsupportedArgs{
				Pool: 0,
				UnsupportedCalls: []rpctype.SyscallReason{
					{ID: target.SyscallMap["test$res0"].ID, Reason: "foo"},
					{ID: 2, Reason: "bar"},
					{ID: target.SyscallMap["test$union0"].ID, Reason: "tar"},
				}}
			if err := vrf.srv.UpdateUnsupported(a, nil); err != nil {
				t.Fatalf("srv.UpdateUnsupported failed: %v", err)
			}

			if diff := cmp.Diff(test.wantPools, vrf.pools, cmp.AllowUnexported(poolInfo{})); diff != "" {
				t.Errorf("srv.pools mismatch (-want +got):\n%s", diff)
			}

			wantReasons := map[*prog.Syscall]string{
				target.SyscallMap["test$res0"]:   "foo",
				target.SyscallMap["test$union0"]: "tar",
			}
			if diff := cmp.Diff(wantReasons, vrf.reasons); diff != "" {
				t.Errorf("srv.reasons mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(test.wantCalls, vrf.calls); diff != "" {
				t.Errorf("srv.calls mismatch (-want +got):\n%s", diff)
			}

			if want, got := test.wantNotChecked, vrf.srv.notChecked; want != got {
				t.Errorf("srv.notChecked: got %d want %d", got, want)
			}

			if want, got := test.nilCT, vrf.choiceTable == nil; want != got {
				t.Errorf("vrf.choiceTable == nil: want nil, got: %v", vrf.choiceTable)
			}
		})
	}
}

func TestUpdateUnsupportedNotCalledTwice(t *testing.T) {
	vrf := Verifier{
		pools: map[int]*poolInfo{
			0: {checked: false},
			1: {checked: false},
		},
	}
	srv, err := startRPCServer(&vrf)
	if err != nil {
		t.Fatalf("failed to initialise RPC server: %v", err)
	}
	a := &rpctype.UpdateUnsupportedArgs{Pool: 0}

	if err := srv.UpdateUnsupported(a, nil); err != nil {
		t.Fatalf("srv.UpdateUnsupported failed: %v", err)
	}
	if want, got := 1, srv.notChecked; want != got {
		t.Errorf("srv.notChecked: got %d want %d", got, want)
	}

	if err := srv.UpdateUnsupported(a, nil); err != nil {
		t.Fatalf("srv.UpdateUnsupported failed: %v", err)
	}
	if want, got := 1, srv.notChecked; want != got {
		t.Fatalf("srv.UpdateUnsupported called twice")
	}

	wantPools := map[int]*poolInfo{
		0: {checked: true},
		1: {checked: false},
	}
	if diff := cmp.Diff(wantPools, vrf.pools, cmp.AllowUnexported(poolInfo{})); diff != "" {
		t.Errorf("srv.pools mismatch (-want +got):\n%s", diff)
	}
}

func TestSaveDiffResults(t *testing.T) {
	tests := []struct {
		name      string
		res       []*ExecResult
		prog      string
		wantExist bool
		wantStats *Stats
	}{
		{
			name: "report written",
			res: []*ExecResult{
				makeExecResult(0, []int{1, 3, 2}),
				makeExecResult(1, []int{1, 3, 5}),
			},
			wantExist: true,
			wantStats: (&Stats{
				TotalCallMismatches: StatUint64{1, nil},
				Calls: StatMapStringToCallStats{
					mapStringToCallStats: mapStringToCallStats{
						"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[ReturnState]bool{}),
						"test$res0":      makeCallStats("test$res0", 1, 1, map[ReturnState]bool{{Errno: 2}: true, {Errno: 5}: true}),
						"minimize$0":     makeCallStats("minimize$0", 1, 0, map[ReturnState]bool{}),
					},
				},
			}).Init(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prog := getTestProgram(t)
			vrf := Verifier{
				resultsdir: makeTestResultDirectory(t),
				stats:      emptyTestStats(),
			}
			resultFile := filepath.Join(vrf.resultsdir, "result-0")

			vrf.AddCallsExecutionStat(test.res, prog)
			vrf.SaveDiffResults(test.res, prog)

			if diff := cmp.Diff(test.wantStats,
				vrf.stats,
				cmp.AllowUnexported(
					Stats{},
					StatUint64{},
					StatTime{},
					sync.Mutex{},
					StatMapStringToCallStats{},
				)); diff != "" {
				t.Errorf("vrf.stats mismatch (-want +got):\n%s", diff)
			}

			if got, want := osutil.IsExist(resultFile), test.wantExist; got != want {
				t.Errorf("osutil.IsExist report file: got %v want %v", got, want)
			}
			os.Remove(filepath.Join(vrf.resultsdir, "result-0"))
		})
	}
}

func TestCreateReport(t *testing.T) {
	rr := ResultReport{
		Prog: "breaks_returns()\n" +
			"minimize$0(0x1, 0x1)\n" +
			"test$res0()\n",
		Reports: []*CallReport{
			{Call: "breaks_returns", States: map[int]ReturnState{
				0: returnState(1, 1),
				1: returnState(1, 1),
				2: returnState(1, 1)}},
			{Call: "minimize$0", States: map[int]ReturnState{
				0: returnState(3, 3),
				1: returnState(3, 3),
				2: returnState(3, 3)}},
			{Call: "test$res0", States: map[int]ReturnState{
				0: returnState(2, 7),
				1: returnState(5, 3),
				2: returnState(22, 1)},
				Mismatch: true},
		},
	}
	got := string(createReport(&rr, 3))
	want := "ERRNO mismatches found for program:\n\n" +
		"[=] breaks_returns()\n" +
		"\t↳ Pool: 0, Flags: 1, Errno: 1 (operation not permitted)\n" +
		"\t↳ Pool: 1, Flags: 1, Errno: 1 (operation not permitted)\n" +
		"\t↳ Pool: 2, Flags: 1, Errno: 1 (operation not permitted)\n\n" +
		"[=] minimize$0(0x1, 0x1)\n" +
		"\t↳ Pool: 0, Flags: 3, Errno: 3 (no such process)\n" +
		"\t↳ Pool: 1, Flags: 3, Errno: 3 (no such process)\n" +
		"\t↳ Pool: 2, Flags: 3, Errno: 3 (no such process)\n\n" +
		"[!] test$res0()\n" +
		"\t↳ Pool: 0, Flags: 7, Errno: 2 (no such file or directory)\n" +
		"\t↳ Pool: 1, Flags: 3, Errno: 5 (input/output error)\n" +
		"\t↳ Pool: 2, Flags: 1, Errno: 22 (invalid argument)\n\n"
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("createReport: (-want +got):\n%s", diff)
	}
}
