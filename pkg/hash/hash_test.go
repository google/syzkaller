// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package hash

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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

func TestFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile")
	content := []byte("hello syzkaller file hashing")
	err := os.WriteFile(filePath, content, 0600)
	require.NoError(t, err)

	sig, err := File(filePath)
	require.NoError(t, err)
	require.Equal(t, "25a4c3561ef3167a6dedd74da7fd6e2f2c03c286", sig.String())

	_, err = File(filepath.Join(dir, "nonexistent"))
	require.Error(t, err)
}
