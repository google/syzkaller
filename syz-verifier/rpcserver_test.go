// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/rpctype"
)

func TestConnect(t *testing.T) {
	vrf := createTestVerifier(t)
	vrf.pools = make(map[int]*poolInfo)
	vrf.pools[1] = &poolInfo{}

	a := &rpctype.RunnerConnectArgs{
		Pool: 1,
		VM:   1,
	}

	r := &rpctype.RunnerConnectRes{}

	if err := vrf.srv.Connect(a, r); err != nil {
		t.Fatalf("srv.Connect failed: %v", err)
	}

	if diff := cmp.Diff(&rpctype.RunnerConnectRes{CheckUnsupportedCalls: true}, r); diff != "" {
		t.Errorf("connect result mismatch (-want +got):\n%s", diff)
	}
}
