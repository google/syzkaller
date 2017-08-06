// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestState(t *testing.T) {
	dir, err := ioutil.TempDir("", "syz-hub-state-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	st, err := Make(dir)
	if err != nil {
		t.Fatalf("failed to make state: %v", err)
	}
	_, _, err = st.Sync("foo", nil, nil)
	if err == nil {
		t.Fatalf("synced with unconnected manager")
	}
	calls := []string{"read", "write"}
	if err := st.Connect("foo", false, calls, nil); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	_, _, err = st.Sync("foo", nil, nil)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
}

func TestRepro(t *testing.T) {
	dir, err := ioutil.TempDir("", "syz-hub-state-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	st, err := Make(dir)
	if err != nil {
		t.Fatalf("failed to make state: %v", err)
	}

	if err := st.Connect("foo", false, []string{"open", "read", "write"}, nil); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if err := st.Connect("bar", false, []string{"open", "read", "close"}, nil); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	checkPendingRepro(t, st, "foo", "")
	checkPendingRepro(t, st, "bar", "")

	if err := st.AddRepro("foo", []byte("open()")); err != nil {
		t.Fatalf("AddRepro failed: %v", err)
	}
	checkPendingRepro(t, st, "foo", "")
	checkPendingRepro(t, st, "bar", "open()")
	checkPendingRepro(t, st, "bar", "")

	// This repro is already present.
	if err := st.AddRepro("bar", []byte("open()")); err != nil {
		t.Fatalf("AddRepro failed: %v", err)
	}
	if err := st.AddRepro("bar", []byte("read()")); err != nil {
		t.Fatalf("AddRepro failed: %v", err)
	}
	if err := st.AddRepro("bar", []byte("open()\nread()")); err != nil {
		t.Fatalf("AddRepro failed: %v", err)
	}
	// This does not satisfy foo's call set.
	if err := st.AddRepro("bar", []byte("close()")); err != nil {
		t.Fatalf("AddRepro failed: %v", err)
	}
	checkPendingRepro(t, st, "bar", "")

	// Check how persistence works.
	st, err = Make(dir)
	if err != nil {
		t.Fatalf("failed to make state: %v", err)
	}
	if err := st.Connect("foo", false, []string{"open", "read", "write"}, nil); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if err := st.Connect("bar", false, []string{"open", "read", "close"}, nil); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	checkPendingRepro(t, st, "bar", "")
	checkPendingRepro(t, st, "foo", "read()")
	checkPendingRepro(t, st, "foo", "open()\nread()")
	checkPendingRepro(t, st, "foo", "")
}

func checkPendingRepro(t *testing.T, st *State, name, result string) {
	repro, err := st.PendingRepro(name)
	if err != nil {
		t.Fatalf("\n%v: PendingRepro failed: %v", caller(1), err)
	}
	if string(repro) != result {
		t.Fatalf("\n%v: PendingRepro returned %q, want %q", caller(1), string(repro), result)
	}
}

func caller(skip int) string {
	_, file, line, _ := runtime.Caller(skip + 1)
	return fmt.Sprintf("%v:%v", filepath.Base(file), line)
}
