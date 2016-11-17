// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestState(t *testing.T) {
	dir, err := ioutil.TempDir("", "syz-gce-state-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	st, err := Make(dir)
	if err != nil {
		t.Fatalf("failed to make state: %v", err)
	}
	_, err = st.Sync("foo", nil, nil)
	if err == nil {
		t.Fatalf("synced with unconnected manager")
	}
}
