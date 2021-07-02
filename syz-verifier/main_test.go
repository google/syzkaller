// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"log"
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

func setup(t *testing.T) {
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
	srv, err = startRPCServer(&vrf)
	if err != nil {
		t.Fatalf("failed to initialise RPC server: %v", err)
	}
	srv.pools = map[int]*poolInfo{
		1: {
			vmRunners: map[int][]*progInfo{
				0: {&progInfo{idx: 1, left: map[int]bool{1: true, 2: true}}},
			},
			progs: []*progInfo{{idx: 3, left: map[int]bool{1: true}}},
		},
		2: {vmRunners: map[int][]*progInfo{
			2: {&progInfo{idx: 1, left: map[int]bool{1: true, 2: true}}},
		},
			progs: []*progInfo{},
		},
	}
	srv.progs = map[int]*progInfo{
		1: {idx: 1, left: map[int]bool{1: true, 2: true}},
		3: {idx: 3, left: map[int]bool{1: true}},
	}
}

func TestNewProgram(t *testing.T) {
	tests := []struct {
		name                             string
		pool, vm, retProgIdx, vrfProgIdx int
		progs                            map[int]*progInfo
	}{
		{
			name:       "NewProgram doesn't generate new program",
			pool:       1,
			vm:         1,
			retProgIdx: 3,
			vrfProgIdx: 3,
			progs: map[int]*progInfo{
				1: {idx: 1, left: map[int]bool{1: true, 2: true}},
				3: {idx: 3, left: map[int]bool{2: true}},
			},
		},
		{
			name:       "NewProgram generates new program",
			pool:       2,
			vm:         2,
			retProgIdx: 4,
			vrfProgIdx: 4,
			progs: map[int]*progInfo{
				1: {idx: 1, left: map[int]bool{1: true, 2: true}},
				3: {idx: 3, left: map[int]bool{2: true}},
				4: {idx: 4, left: map[int]bool{1: true, 2: true}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setup(t)
			_, gotProgIdx := srv.newProgram(test.pool, test.vm)
			if gotProgIdx != test.retProgIdx {
				t.Errorf("srv.newProgram returned idx: got %d, want %d", gotProgIdx, test.retProgIdx)
			}
			if srv.vrf.progIdx != test.vrfProgIdx {
				t.Errorf("srv.progIdx: got %d, want %d", srv.vrf.progIdx, test.vrfProgIdx)
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
			setup(t)
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
	setup(t)
	a := &rpctype.RunnerConnectArgs{
		Pool: 1,
		VM:   1,
	}
	if err := srv.Connect(a, nil); err != nil {
		t.Fatalf("srv.Connect failed: %v", err)
	}
	want, got := map[int][]*progInfo{
		0: {&progInfo{idx: 1, left: map[int]bool{1: true, 2: true}}},
		1: nil,
	}, srv.pools[a.Pool].vmRunners
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(progInfo{})); diff != "" {
		t.Errorf("srv.progs[a.Name] mismatch (-want +got):\n%s", diff)
	}
}

func makeResult(pool int, errnos []int) *verf.Result {
	r := &verf.Result{Pool: pool, Info: ipc.ProgInfo{Calls: []ipc.CallInfo{}}}
	for _, e := range errnos {
		r.Info.Calls = append(r.Info.Calls, ipc.CallInfo{Errno: e})
	}
	return r
}

func TestProcessResults(t *testing.T) {
	p := "breaks_returns()\n" +
		"minimize$0(0x1, 0x1)\n" +
		"test$res0()\n"
	tests := []struct {
		name       string
		res        []*verf.Result
		prog       string
		wantExist  bool
		wantResIdx int
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
			target := prog.InitTargetTest(t, "test", "64")
			prog, err := target.Deserialize([]byte(p), prog.Strict)
			if err != nil {
				t.Fatalf("failed to deserialise test program: %v", err)
			}

			resultsdir := "test"
			err = osutil.MkdirAll(resultsdir)
			if err != nil {
				t.Fatalf("failed to create results directory: %v", err)
			}
			vrf := Verifier{}
			vrf.resultsdir, err = filepath.Abs(resultsdir)
			if err != nil {
				t.Fatalf("failed to get absolute path of resultsdir: %v", err)
			}
			resultFile := filepath.Join(vrf.resultsdir, "result-3")

			vrf.processResults(test.res, prog)

			if got, want := osutil.IsExist(resultFile), test.wantExist; got != want {
				log.Printf("%v", test.wantExist)
				t.Errorf("osutil.IsExist report file: got %v want %v", got, want)
			}
			os.Remove(filepath.Join(vrf.resultsdir, "result-3"))
		})
	}
}
