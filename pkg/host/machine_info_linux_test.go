// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/osutil"
)

func TestGetGlobsInfo(t *testing.T) {
	dir := t.TempDir()
	if err := osutil.MkdirAll(filepath.Join(dir, "a", "b", "c", "d")); err != nil {
		t.Fatal(err)
	}
	if err := osutil.MkdirAll(filepath.Join(dir, "a", "b", "c", "e")); err != nil {
		t.Fatal(err)
	}
	if err := osutil.MkdirAll(filepath.Join(dir, "a", "c", "d")); err != nil {
		t.Fatal(err)
	}
	if err := osutil.MkdirAll(filepath.Join(dir, "a", "c", "e")); err != nil {
		t.Fatal(err)
	}

	glob := filepath.Join(dir, "a/**/*") + ":-" + filepath.Join(dir, "a/c/e")
	globs := map[string]bool{
		glob: true,
	}
	infos, err := getGlobsInfo(globs)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(dir, "a/b/c"),
		filepath.Join(dir, "a/c/d"),
	}
	if diff := cmp.Diff(infos[glob], want); diff != "" {
		t.Fatal(diff)
	}
}
