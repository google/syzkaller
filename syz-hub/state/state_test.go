// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/rpctype"
)

type TestState struct {
	t     *testing.T
	dir   string
	state *State
}

func MakeTestState(t *testing.T) *TestState {
	t.Parallel()
	dir := t.TempDir()
	state, err := Make(dir)
	if err != nil {
		t.Fatalf("failed to make state: %v", err)
	}
	return &TestState{t, dir, state}
}

func (ts *TestState) Reload() {
	ts.state.Flush()
	state, err := Make(ts.dir)
	if err != nil {
		ts.t.Fatalf("failed to make state: %v", err)
	}
	ts.state = state
}

func (ts *TestState) Connect(name, domain string, fresh bool, calls []string, corpus [][]byte) {
	ts.t.Helper()
	if err := ts.state.Connect(name, domain, fresh, calls, corpus); err != nil {
		ts.t.Fatalf("Connect failed: %v", err)
	}
}

func (ts *TestState) Sync(name string, add [][]byte, del []string) (string, []rpctype.HubInput, int) {
	ts.t.Helper()
	domain, inputs, pending, err := ts.state.Sync(name, add, del)
	if err != nil {
		ts.t.Fatalf("Sync failed: %v", err)
	}
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].Domain != inputs[j].Domain {
			return inputs[i].Domain < inputs[j].Domain
		}
		return string(inputs[i].Prog) < string(inputs[j].Prog)
	})
	return domain, inputs, pending
}

func (ts *TestState) AddRepro(name string, repro []byte) {
	ts.t.Helper()
	if err := ts.state.AddRepro(name, repro); err != nil {
		ts.t.Fatalf("AddRepro failed: %v", err)
	}
}

func (ts *TestState) PendingRepro(name string) []byte {
	ts.t.Helper()
	repro, err := ts.state.PendingRepro(name)
	if err != nil {
		ts.t.Fatalf("PendingRepro failed: %v", err)
	}
	return repro
}

func TestBasic(t *testing.T) {
	st := MakeTestState(t)

	if _, _, _, err := st.state.Sync("foo", nil, nil); err == nil {
		t.Fatalf("synced with unconnected manager")
	}
	calls := []string{"read", "write"}
	st.Connect("foo", "", false, calls, nil)
	st.Sync("foo", nil, nil)
}

func TestRepro(t *testing.T) {
	st := MakeTestState(t)

	st.Connect("foo", "", false, []string{"open", "read", "write"}, nil)
	st.Connect("bar", "", false, []string{"open", "read", "close"}, nil)

	expectPendingRepro := func(name, result string) {
		t.Helper()
		repro := st.PendingRepro(name)
		if string(repro) != result {
			t.Fatalf("got %q, want %q", string(repro), result)
		}
	}
	expectPendingRepro("foo", "")
	expectPendingRepro("bar", "")
	st.AddRepro("foo", []byte("open()"))
	expectPendingRepro("foo", "")
	expectPendingRepro("bar", "open()")
	expectPendingRepro("bar", "")

	// This repro is already present.
	st.AddRepro("bar", []byte("open()"))
	st.AddRepro("bar", []byte("read()"))
	st.AddRepro("bar", []byte("open()\nread()"))
	// This does not satisfy foo's call set.
	st.AddRepro("bar", []byte("close()"))
	expectPendingRepro("bar", "")

	// Check how persistence works.
	st.Reload()
	st.Connect("foo", "", false, []string{"open", "read", "write"}, nil)
	st.Connect("bar", "", false, []string{"open", "read", "close"}, nil)
	expectPendingRepro("bar", "")
	expectPendingRepro("foo", "read()")
	expectPendingRepro("foo", "open()\nread()")
	expectPendingRepro("foo", "")
}

func TestDomain(t *testing.T) {
	st := MakeTestState(t)

	st.Connect("client0", "", false, []string{"open"}, nil)
	st.Connect("client1", "domain1", false, []string{"open"}, nil)
	st.Connect("client2", "domain2", false, []string{"open"}, nil)
	st.Connect("client3", "domain3", false, []string{"open"}, nil)
	{
		domain, inputs, pending := st.Sync("client0", [][]byte{[]byte("open(0x0)")}, nil)
		if domain != "" || len(inputs) != 0 || pending != 0 {
			t.Fatalf("bad sync result: %v, %v, %v", domain, inputs, pending)
		}
	}
	{
		domain, inputs, pending := st.Sync("client0", [][]byte{[]byte("open(0x1)")}, nil)
		if domain != "" || len(inputs) != 0 || pending != 0 {
			t.Fatalf("bad sync result: %v, %v, %v", domain, inputs, pending)
		}
	}
	{
		domain, inputs, pending := st.Sync("client1", [][]byte{[]byte("open(0x2)"), []byte("open(0x1)")}, nil)
		if domain != "domain1" || pending != 0 {
			t.Fatalf("bad sync result: %v, %v, %v", domain, inputs, pending)
		}
		if diff := cmp.Diff(inputs, []rpctype.HubInput{
			{Domain: "", Prog: []byte("open(0x0)")},
		}); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		_, inputs, _ := st.Sync("client2", [][]byte{[]byte("open(0x3)")}, nil)
		if diff := cmp.Diff(inputs, []rpctype.HubInput{
			{Domain: "", Prog: []byte("open(0x0)")},
			{Domain: "domain1", Prog: []byte("open(0x1)")},
			{Domain: "domain1", Prog: []byte("open(0x2)")},
		}); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		_, inputs, _ := st.Sync("client0", nil, nil)
		if diff := cmp.Diff(inputs, []rpctype.HubInput{
			{Domain: "domain1", Prog: []byte("open(0x2)")},
			{Domain: "domain2", Prog: []byte("open(0x3)")},
		}); diff != "" {
			t.Fatal(diff)
		}
	}
	st.Reload()
	st.Connect("client3", "domain3", false, []string{"open"}, nil)
	{
		_, inputs, _ := st.Sync("client3", nil, nil)
		if diff := cmp.Diff(inputs, []rpctype.HubInput{
			{Domain: "", Prog: []byte("open(0x0)")},
			{Domain: "domain1", Prog: []byte("open(0x1)")},
			{Domain: "domain1", Prog: []byte("open(0x2)")},
			{Domain: "domain2", Prog: []byte("open(0x3)")},
		}); diff != "" {
			t.Fatal(diff)
		}
	}
}
