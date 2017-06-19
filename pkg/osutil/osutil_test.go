// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"os"
	"testing"
)

func TestIsExist(t *testing.T) {
	if f := os.Args[0]; !IsExist(f) {
		t.Fatalf("executable %v does not exist", f)
	}
	if f := os.Args[0] + "-foo-bar-buz"; IsExist(f) {
		t.Fatalf("file %v exists", f)
	}
}
