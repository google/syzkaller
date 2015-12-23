// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"testing"
)

func TestParseSingle(t *testing.T) {
	const execLog = `getpid()
gettid()	
`
	entries := ParseLog([]byte(execLog))
	if len(entries) != 1 {
		t.Fatalf("got %v programs, want 1", len(entries))
	}
	ent := entries[0]
	if ent.Start != 0 {
		t.Fatalf("start offset %v, want 0", ent.Start)
	}
	if ent.End != len(execLog) {
		t.Fatalf("end offset %v, want %v", ent.End, len(execLog))
	}
	if ent.Proc != 0 {
		t.Fatalf("proc %v, want 0", ent.Proc)
	}
	want := "getpid-gettid"
	got := ent.P.String()
	if got != want {
		t.Fatalf("bad program: %s, want %s", got, want)
	}
}

func TestParseMulti(t *testing.T) {
	entries := ParseLog([]byte(execLog))
	if len(entries) != 5 {
		for i, ent := range entries {
			t.Logf("program #%v: %s\n", i, ent.P)
		}
		t.Fatalf("got %v programs, want 5", len(entries))
	}
	off := 0
	for _, ent := range entries {
		if off > ent.Start || ent.Start > ent.End || ent.End > len(execLog) {
			t.Fatalf("bad offsets")
		}
	}
	if entries[0].Proc != 0 ||
		entries[1].Proc != 1 ||
		entries[2].Proc != 2 ||
		entries[3].Proc != 33 ||
		entries[4].Proc != 9 {
		t.Fatalf("bad procs")
	}
	if s := entries[0].P.String(); s != "getpid-gettid" {
		t.Fatalf("bad program 0: %s", s)
	}
	if s := entries[1].P.String(); s != "getpid-gettid-munlockall" {
		t.Fatalf("bad program 0: %s", s)
	}
	if s := entries[2].P.String(); s != "getpid-gettid" {
		t.Fatalf("bad program 1: %s", s)
	}
	if s := entries[3].P.String(); s != "gettid-getpid" {
		t.Fatalf("bad program 2: %s", s)
	}
	if s := entries[4].P.String(); s != "munlockall" {
		t.Fatalf("bad program 3: %s", s)
	}
}

const execLog = `
getpid()
gettid()
2015/12/21 12:18:05 executing program 1:
getpid()
[ 2351.935478] Modules linked in:
gettid()
munlockall()
2015/12/21 12:18:05 executing program 2:
[ 2351.935478] Modules linked in:
getpid()
gettid()
2015/12/21 12:18:05 executing program 33:
gettid()
getpid()
[ 2351.935478] Modules linked in:
2015/12/21 12:18:05 executing program 9:
munlockall()
`
