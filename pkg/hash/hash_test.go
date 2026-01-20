// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package hash

import (
	"testing"
)

func TestHash(t *testing.T) {
	type X struct {
		Int int
	}
	if String([]byte{}) == String([]byte{0}) {
		t.Fatal("equal hashes")
	}
	if String("foo") == String("bar") {
		t.Fatal("equal hashes")
	}
	if String(X{0}) == String(X{1}) {
		t.Fatal("equal hashes")
	}
}
