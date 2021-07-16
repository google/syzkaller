// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-verifier/stats"
	"github.com/google/syzkaller/syz-verifier/verf"
)

var (
	srv *RPCServer
)

func createTestServer(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to initialise test target: %v", err)
	}
	vrf := Verifier{
		target:      target,
		choiceTable: target.DefaultChoiceTable(),
		rnd:         rand.New(rand.NewSource(time.Now().UnixNano())),
		progIdx:     3,
	}
	vrf.resultsdir = makeTestResultDirectory(t)
	vrf.stats = getTestStats()
	srv, err = startRPCServer(&vrf)
	if err != nil {
		t.Fatalf("failed to initialise RPC server: %v", err)
	}
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

func getTestStats() *stats.Stats {
	return &stats.Stats{
		Calls: map[string]*stats.CallStats{
			"breaks_returns": {Name: "breaks_returns", States: map[int]bool{}},
			"minimize$0":     {Name: "minimize$0", States: map[int]bool{}},
			"test$res0":      {Name: "test$res0", States: map[int]bool{}},
		},
	}
}

func makeCallStats(name string, occurrences, mismatches int, states map[int]bool) *stats.CallStats {
	return &stats.CallStats{Name: name,
		Occurrences: occurrences,
		Mismatches:  mismatches,
		States:      states}
}

func makeTestResultDirectory(t *testing.T) string {
	resultsdir := "test"
	err := osutil.MkdirAll(resultsdir)
	if err != nil {
		t.Fatalf("failed to create results directory: %v", err)
	}
	resultsdir, err = filepath.Abs(resultsdir)
	if err != nil {
		t.Fatalf("failed to get absolute path of resultsdir: %v", err)
	}
	return resultsdir
}

func makeResult(pool int, errnos []int) *verf.Result {
	r := &verf.Result{Pool: pool, Info: ipc.ProgInfo{Calls: []ipc.CallInfo{}}}
	for _, e := range errnos {
		r.Info.Calls = append(r.Info.Calls, ipc.CallInfo{Errno: e})
	}
	return r
}

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
			createTestServer(t)
			srv.pools = map[int]*poolInfo{
				1: {
					vmRunners: map[int][]*progInfo{
						0: {{
							idx: 1, left: map[int]bool{1: true, 2: true}}},
					},
					progs: []*progInfo{{
						idx: 3, left: map[int]bool{1: true}}},
				},
				2: {vmRunners: map[int][]*progInfo{
					2: {{
						idx: 1, left: map[int]bool{1: true, 2: true}}},
				},
					progs: []*progInfo{},
				},
			}
			srv.progs = map[int]*progInfo{
				1: {idx: 1, left: map[int]bool{1: true, 2: true}},
				3: {idx: 3, left: map[int]bool{1: true}},
			}

			_, gotProgIdx := srv.newProgram(test.pool, test.vm)
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
		res       verf.Result
		left      map[int]bool
		wantReady bool
	}{
		{
			name:      "Results ready for verification",
			idx:       3,
			res:       verf.Result{Pool: 1},
			wantReady: true,
			left:      map[int]bool{},
		},
		{
			name:      "No results ready for verification",
			idx:       1,
			res:       verf.Result{Pool: 1},
			wantReady: false,
			left: map[int]bool{
				2: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			createTestServer(t)
			srv.progs = map[int]*progInfo{
				1: {idx: 1,
					left: map[int]bool{1: true, 2: true}},
				3: {idx: 3,
					left: map[int]bool{1: true}},
			}
			gotReady := srv.newResult(&test.res, srv.progs[test.idx])
			if test.wantReady != gotReady {
				t.Errorf("srv.newResult: got %v want %v", gotReady, test.wantReady)
			}
			if diff := cmp.Diff(test.left, srv.progs[test.idx].left); diff != "" {
				t.Errorf("srv.left mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConnect(t *testing.T) {
	createTestServer(t)
	srv.pools = map[int]*poolInfo{
		1: {
			vmRunners: map[int][]*progInfo{
				0: {{
					idx: 1, left: map[int]bool{1: true, 2: true}}},
			},
			progs: []*progInfo{{
				idx: 3, left: map[int]bool{1: true}}},
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
	want, got := map[int][]*progInfo{
		0: {{idx: 1, left: map[int]bool{1: true, 2: true}}},
		1: nil,
	}, srv.pools[a.Pool].vmRunners
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
			0: {vmRunners: map[int][]*progInfo{0: nil, 1: nil}, checked: false},
			1: {vmRunners: map[int][]*progInfo{}, checked: false},
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
		0: {vmRunners: map[int][]*progInfo{0: nil, 1: nil}, checked: true},
		1: {vmRunners: map[int][]*progInfo{}, checked: false},
	}
	if diff := cmp.Diff(wantPools, srv.pools, cmp.AllowUnexported(poolInfo{}, progInfo{})); diff != "" {
		t.Errorf("srv.pools mismatch (-want +got):\n%s", diff)
	}
}

func TestProcessResults(t *testing.T) {
	tests := []struct {
		name      string
		res       []*verf.Result
		prog      string
		wantExist bool
		wantStats *stats.Stats
	}{
		{
			name: "report written",
			res: []*verf.Result{
				makeResult(1, []int{1, 3, 2}),
				makeResult(4, []int{1, 3, 5}),
			},
			wantExist: true,
			wantStats: &stats.Stats{
				TotalMismatches: 1,
				Progs:           1,
				Calls: map[string]*stats.CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[int]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 1, map[int]bool{2: true, 5: true}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[int]bool{}),
				},
			},
		},
		{
			name: "no report written",
			res: []*verf.Result{
				makeResult(2, []int{11, 33, 22}),
				makeResult(3, []int{11, 33, 22}),
			},
			wantStats: &stats.Stats{
				Progs: 1,
				Calls: map[string]*stats.CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[int]bool{}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[int]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 0, map[int]bool{}),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prog := getTestProgram(t)
			vrf := Verifier{
				resultsdir: makeTestResultDirectory(t),
				stats:      getTestStats(),
			}
			resultFile := filepath.Join(vrf.resultsdir, "result-0")

			vrf.processResults(test.res, prog)

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
	rr := verf.ResultReport{
		Prog: "breaks_returns()\n" +
			"minimize$0(0x1, 0x1)\n" +
			"test$res0()\n",
		Reports: []verf.CallReport{
			{Call: "breaks_returns", Errnos: map[int]int{1: 1, 2: 1, 3: 1},
				Flags: map[int]ipc.CallFlags{1: 1, 2: 1, 3: 1}},
			{Call: "minimize$0", Errnos: map[int]int{1: 3, 2: 3, 3: 3},
				Flags: map[int]ipc.CallFlags{1: 3, 2: 3, 3: 3}},
			{Call: "test$res0", Errnos: map[int]int{1: 2, 2: 5, 3: 22},
				Flags: map[int]ipc.CallFlags{1: 7, 2: 3, 3: 1}, Mismatch: true},
		},
	}
	got := string(createReport(&rr, 3))
	want := "ERRNO mismatches found for program:\n\n" +
		"[=] breaks_returns()\n" +
		"\t↳ Pool: 1, Errno: 1, Flag: 1\n" +
		"\t↳ Pool: 2, Errno: 1, Flag: 1\n\n" +
		"[=] minimize$0(0x1, 0x1)\n" +
		"\t↳ Pool: 1, Errno: 3, Flag: 3\n" +
		"\t↳ Pool: 2, Errno: 3, Flag: 3\n\n" +
		"[!] test$res0()\n" +
		"\t↳ Pool: 1, Errno: 2, Flag: 7\n" +
		"\t↳ Pool: 2, Errno: 5, Flag: 3\n\n"
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
		wantStats  *stats.Stats
		progExists bool
		fileExists bool
	}{
		{
			name: "results not ready for verification",
			progs: map[int]*progInfo{
				4: {
					idx:  4,
					left: map[int]bool{0: true, 1: true, 2: true},
				}},
			wantProg: &progInfo{
				idx:  4,
				left: map[int]bool{1: true, 2: true},
			},
			wantStats:  getTestStats(),
			fileExists: false,
		},
		{
			name: "results sent for verification, no report generated",
			progs: map[int]*progInfo{
				4: {
					idx:  4,
					left: map[int]bool{0: true},
					prog: prog,
					res: []*verf.Result{
						makeResult(1, []int{11, 33, 22}),
						makeResult(2, []int{11, 33, 22}),
					},
				}},
			wantStats: &stats.Stats{
				Progs: 1,
				Calls: map[string]*stats.CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[int]bool{}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[int]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 0, map[int]bool{}),
				},
			},
			fileExists: false,
		},
		{
			name: "results sent for verification, report generation",
			progs: map[int]*progInfo{
				4: {
					idx:  4,
					left: map[int]bool{0: true},
					prog: prog,
					res: []*verf.Result{
						makeResult(1, []int{11, 33, 44}),
						makeResult(2, []int{11, 33, 22}),
					},
				}},
			wantStats: &stats.Stats{
				TotalMismatches: 1,
				Progs:           1,
				Calls: map[string]*stats.CallStats{
					"breaks_returns": makeCallStats("breaks_returns", 1, 0, map[int]bool{}),
					"minimize$0":     makeCallStats("minimize$0", 1, 0, map[int]bool{}),
					"test$res0":      makeCallStats("test$res0", 1, 1, map[int]bool{22: true, 44: true}),
				},
			},
			fileExists: true,
		},
		{
			name: "not enough results to send for verification",
			progs: map[int]*progInfo{
				4: {
					idx:  4,
					left: map[int]bool{0: true},
					res: []*verf.Result{
						makeResult(2, []int{11, 33, 22}),
					},
				}},
			wantStats:  getTestStats(),
			wantProg:   nil,
			fileExists: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			createTestServer(t)
			srv.progs = test.progs
			srv.pools = map[int]*poolInfo{
				0: {vmRunners: map[int][]*progInfo{
					0: {srv.progs[4]}},
				}}
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
