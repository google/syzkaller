// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

func TestNewProgram(t *testing.T) {
	tests := []struct {
		name                           string
		pool, vm, retProgIdx, srvProgs int
	}{
		{
			name:       "doesn't generate new program",
			pool:       1,
			vm:         1,
			retProgIdx: 3,
			srvProgs:   2,
		},
		{
			name:       "generates new program",
			pool:       2,
			vm:         2,
			retProgIdx: 4,
			srvProgs:   3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := createTestServer(t)
			srv.pools = map[int]*poolInfo{
				1: {
					runners: map[int]runnerProgs{
						1: {1: {}},
					},
					progs: []*progInfo{{idx: 3}},
				},
				2: {runners: map[int]runnerProgs{
					2: {1: {}}},
					progs: []*progInfo{},
				},
			}

			srv.progs = map[int]*progInfo{
				1: {idx: 1},
				3: {idx: 3},
			}

			_, gotProgIdx, _ := srv.newProgram(test.pool, test.vm)
			if gotProgIdx != test.retProgIdx {
				t.Errorf("srv.newProgram returned idx: got %d, want %d", gotProgIdx, test.retProgIdx)
			}

			if got, want := len(srv.progs), test.srvProgs; got != want {
				t.Errorf("len(srv.progs): got %d, want %d", got, want)
			}
		})
	}
}

func TestNewResult(t *testing.T) {
	tests := []struct {
		name      string
		idx       int
		wantReady bool
	}{
		{
			name:      "Results ready for verification",
			idx:       3,
			wantReady: true,
		},
		{
			name:      "No results ready for verification",
			idx:       1,
			wantReady: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := createTestServer(t)
			srv.pools = map[int]*poolInfo{0: {}, 1: {}}
			srv.progs = map[int]*progInfo{
				1: {idx: 1,
					res: func() [][]*Result {
						res := make([][]*Result, 1)
						res[0] = make([]*Result, 2)
						return res
					}(),
				},
				3: {idx: 3,
					res: func() [][]*Result {
						res := make([][]*Result, 1)
						res[0] = make([]*Result, 2)
						res[0][1] = &Result{Pool: 1}
						return res
					}(),
					received: 1,
				},
			}
			gotReady := srv.newResult(&Result{Pool: 0}, srv.progs[test.idx])
			if test.wantReady != gotReady {
				t.Errorf("srv.newResult: got %v want %v", gotReady, test.wantReady)
			}
		})
	}
}

func TestConnect(t *testing.T) {
	srv := createTestServer(t)
	srv.pools = map[int]*poolInfo{
		1: {
			runners: map[int]runnerProgs{
				0: {1: {idx: 1}},
			},
			progs: []*progInfo{{
				idx: 3}},
		}}
	a := &rpctype.RunnerConnectArgs{
		Pool: 1,
		VM:   1,
	}
	r := &rpctype.RunnerConnectRes{}
	if err := srv.Connect(a, r); err != nil {
		t.Fatalf("srv.Connect failed: %v", err)
	}
	if diff := cmp.Diff(&rpctype.RunnerConnectRes{CheckUnsupportedCalls: true}, r); diff != "" {
		t.Errorf("Connect result mismatch (-want +got):\n%s", diff)
	}
	want, got := map[int]runnerProgs{
		0: {1: {idx: 1}},
		1: {},
	}, srv.pools[a.Pool].runners
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(progInfo{})); diff != "" {
		t.Errorf("srv.progs[a.Name] mismatch (-want +got):\n%s", diff)
	}
}

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
			}
			srv, err := startRPCServer(&vrf)
			if err != nil {
				t.Fatalf("failed to initialise RPC server: %v", err)
			}

			a := &rpctype.UpdateUnsupportedArgs{
				Pool: 0,
				UnsupportedCalls: []rpctype.SyscallReason{
					{ID: 137, Reason: "foo"},
					{ID: 2, Reason: "bar"},
					{ID: 151, Reason: "tar"},
				}}
			if err := srv.UpdateUnsupported(a, nil); err != nil {
				t.Fatalf("srv.UpdateUnsupported failed: %v", err)
			}

			if diff := cmp.Diff(test.wantPools, srv.pools, cmp.AllowUnexported(poolInfo{})); diff != "" {
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

			if want, got := test.wantNotChecked, srv.notChecked; want != got {
				t.Errorf("srv.notChecked: got %d want %d", got, want)
			}

			if want, got := test.nilCT, vrf.choiceTable == nil; want != got {
				t.Errorf("vrf.choiceTable == nil: want nil, got: %v", srv.vrf.choiceTable)
			}
		})
	}
}

func TestUpdateUnsupportedNotCalledTwice(t *testing.T) {
	vrf := Verifier{
		pools: map[int]*poolInfo{
			0: {runners: map[int]runnerProgs{0: nil, 1: nil}, checked: false},
			1: {runners: map[int]runnerProgs{}, checked: false},
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
		0: {runners: map[int]runnerProgs{0: nil, 1: nil}, checked: true},
		1: {runners: map[int]runnerProgs{}, checked: false},
	}
	if diff := cmp.Diff(wantPools, srv.pools, cmp.AllowUnexported(poolInfo{}, progInfo{})); diff != "" {
		t.Errorf("srv.pools mismatch (-want +got):\n%s", diff)
	}
}

func TestProcessResults(t *testing.T) {
	tests := []struct {
		name      string
		res       []*Result
		prog      string
		wantExist bool
		wantStats *Stats
	}{
		{
			name: "report written",
			res: []*Result{
				makeResult(0, []int{1, 3, 2}),
				makeResult(1, []int{1, 3, 5}),
			},
			wantExist: true,
			wantStats: &Stats{
				TotalMismatches: 1,
				TotalProgs:      1,
				Calls: map[string]*CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[ReturnState]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 1, map[ReturnState]bool{{Errno: 2}: true, {Errno: 5}: true}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[ReturnState]bool{}),
				},
			},
		},
		{
			name: "no report written",
			res: []*Result{
				makeResult(0, []int{11, 33, 22}),
				makeResult(1, []int{11, 33, 22}),
			},
			wantStats: &Stats{
				TotalProgs: 1,
				Calls: map[string]*CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[ReturnState]bool{}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[ReturnState]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 0, map[ReturnState]bool{}),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prog := getTestProgram(t)
			pi := &progInfo{
				prog: prog,
				res: func() [][]*Result {
					res := make([][]*Result, 1)
					res[0] = test.res
					return res
				}()}
			vrf := Verifier{
				resultsdir: makeTestResultDirectory(t),
				stats:      emptyTestStats(),
			}
			resultFile := filepath.Join(vrf.resultsdir, "result-0")

			vrf.processResults(pi)

			if diff := cmp.Diff(test.wantStats, vrf.stats); diff != "" {
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

func TestCleanup(t *testing.T) {
	prog := getTestProgram(t)
	tests := []struct {
		name       string
		progs      map[int]*progInfo
		wantProg   *progInfo
		wantStats  *Stats
		progExists bool
		fileExists bool
	}{
		{
			name: "results not ready for verification",
			progs: map[int]*progInfo{
				4: {
					idx:      4,
					received: 0,
					res: func() [][]*Result {
						res := make([][]*Result, 1)
						res[0] = make([]*Result, 3)
						return res
					}(),
				}},
			wantProg: &progInfo{
				idx:      4,
				received: 1,
				res:      [][]*Result{{makeResultCrashed(0), nil, nil}},
			},
			wantStats:  emptyTestStats(),
			fileExists: false,
		},
		{
			name: "results sent for verification, no report generated",
			progs: map[int]*progInfo{
				4: {
					idx:      4,
					prog:     prog,
					received: 2,
					res: func() [][]*Result {
						res := make([][]*Result, 1)
						res[0] = make([]*Result, 3)
						res[0][1] = makeResultCrashed(1)
						res[0][2] = makeResultCrashed(2)
						return res
					}(),
				}},
			wantStats: &Stats{
				TotalProgs: 1,
				Calls: map[string]*CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[ReturnState]bool{}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[ReturnState]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 0, map[ReturnState]bool{}),
				},
			},
			fileExists: false,
		},
		{
			name: "results sent for verification, report generation",
			progs: map[int]*progInfo{
				4: {
					idx:      4,
					prog:     prog,
					received: 2,
					res: func() [][]*Result {
						res := make([][]*Result, 1)
						res[0] = make([]*Result, 3)
						res[0][1] = makeResult(1, []int{11, 33, 44})
						res[0][2] = makeResult(2, []int{11, 33, 22})
						return res
					}(),
				}},
			wantStats: &Stats{
				TotalMismatches:  3,
				TotalProgs:       1,
				MismatchingProgs: 1,
				Calls: map[string]*CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 1,
						map[ReturnState]bool{
							crashedReturnState(): true,
							returnState(11):      true}),
					"minimize$0": makeCallStats("minimize$0", 1, 1,
						map[ReturnState]bool{
							crashedReturnState(): true,
							returnState(33):      true}),
					"test$res0": makeCallStats("test$res0", 1, 1,
						map[ReturnState]bool{
							crashedReturnState(): true,
							returnState(22):      true,
							returnState(44):      true}),
				},
			},
			fileExists: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := createTestServer(t)
			srv.progs = test.progs
			srv.pools = map[int]*poolInfo{
				0: {runners: map[int]runnerProgs{
					0: {4: srv.progs[4]}},
				}, 1: {}, 2: {}}
			resultFile := filepath.Join(srv.vrf.resultsdir, "result-0")

			srv.cleanup(0, 0)

			prog := srv.progs[4]
			if diff := cmp.Diff(test.wantProg, prog, cmp.AllowUnexported(progInfo{})); diff != "" {
				t.Errorf("srv.progs[4] mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(test.wantStats, srv.vrf.stats); diff != "" {
				t.Errorf("srv.vrf.stats mismatch (-want +got):\n%s", diff)
			}

			if got, want := osutil.IsExist(resultFile), test.fileExists; got != want {
				t.Errorf("osutil.IsExist report file: got %v want %v", got, want)
			}
			os.Remove(filepath.Join(srv.vrf.resultsdir, "result-0"))
		})
	}
}
