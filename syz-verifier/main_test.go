// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
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
	if err := srv.Connect(a, nil); err != nil {
		t.Fatalf("srv.Connect failed: %v", err)
	}
	want, got := map[int][]*progInfo{
		0: {{idx: 1, left: map[int]bool{1: true, 2: true}}},
		1: nil,
	}, srv.pools[a.Pool].vmRunners
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(progInfo{})); diff != "" {
		t.Errorf("srv.progs[a.Name] mismatch (-want +got):\n%s", diff)
	}
}

func TestProcessResults(t *testing.T) {
	tests := []struct {
		name      string
		res       []*verf.Result
		prog      string
		wantExist bool
	}{
		{
			name: "report written",
			res: []*verf.Result{
				makeResult(1, []int{1, 3, 2}),
				makeResult(4, []int{1, 3, 5}),
			},
			wantExist: true,
		},
		{
			name: "no report written",
			res: []*verf.Result{
				makeResult(2, []int{11, 33, 22}),
				makeResult(3, []int{11, 33, 22}),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prog := getTestProgram(t)
			vrf := Verifier{
				resultsdir: makeTestResultDirectory(t)}
			resultFile := filepath.Join(vrf.resultsdir, "result-3")

			vrf.processResults(test.res, prog)

			if got, want := osutil.IsExist(resultFile), test.wantExist; got != want {
				t.Errorf("osutil.IsExist report file: got %v want %v", got, want)
			}
			os.Remove(filepath.Join(vrf.resultsdir, "result-3"))
		})
	}
}

func TestCreateReport(t *testing.T) {
	rr := verf.ResultReport{
		Prog: "breaks_returns()\n" +
			"minimize$0(0x1, 0x1)\n" +
			"test$res0()\n",
		Reports: []verf.CallReport{
			{Errnos: map[int]int{1: 1, 2: 1, 3: 1}, Flags: map[int]ipc.CallFlags{1: 1, 2: 1, 3: 1}},
			{Errnos: map[int]int{1: 3, 2: 3, 3: 3}, Flags: map[int]ipc.CallFlags{1: 3, 2: 3, 3: 3}},
			{Errnos: map[int]int{1: 2, 2: 5, 3: 22}, Flags: map[int]ipc.CallFlags{1: 7, 2: 3, 3: 1}, Mismatch: true},
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
	if got != want {
		t.Errorf("createReport: got %q want %q", got, want)
	}
}

func TestCleanup(t *testing.T) {
	prog := getTestProgram(t)
	tests := []struct {
		name       string
		progs      map[int]*progInfo
		wantProg   *progInfo
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

			if got, want := osutil.IsExist(resultFile), test.fileExists; got != want {
				t.Errorf("osutil.IsExist report file: got %v want %v", got, want)
			}
			os.Remove(filepath.Join(srv.vrf.resultsdir, "result-0"))
		})
	}
}
