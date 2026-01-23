// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestIsExist(t *testing.T) {
	if f := os.Args[0]; !IsExist(f) {
		t.Fatalf("executable %v does not exist", f)
	}
	if f := os.Args[0] + "-foo-bar-buz"; IsExist(f) {
		t.Fatalf("file %v exists", f)
	}
}

func TestCopyFiles(t *testing.T) {
	type Test struct {
		files    []string
		patterns map[string]bool
		err      string
	}
	tests := []Test{
		{
			files: []string{
				"foo",
				"bar",
				"baz/foo",
				"baz/bar",
			},
			patterns: map[string]bool{
				"foo":     true,
				"bar":     false,
				"qux":     false,
				"baz/foo": true,
				"baz/bar": false,
			},
		},
		{
			files: []string{
				"foo",
			},
			patterns: map[string]bool{
				"bar": true,
			},
			err: "file bar does not exist",
		},
		{
			files: []string{
				"baz/foo",
				"baz/bar",
			},
			patterns: map[string]bool{
				"baz/*": true,
			},
		},
		{
			files: []string{
				"qux/foo/foo",
				"qux/foo/bar",
				"qux/bar/foo",
				"qux/bar/bar",
			},
			patterns: map[string]bool{
				"qux/*/*": false,
			},
		},
	}
	for _, link := range []bool{false, true} {
		fn, fnName := CopyFiles, "CopyFiles"
		if link {
			fn, fnName = LinkFiles, "LinkFiles"
		}
		t.Run(fnName, func(t *testing.T) {
			for i, test := range tests {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					dir := t.TempDir()
					src := filepath.Join(dir, "src")
					dst := filepath.Join(dir, "dst")
					for _, file := range test.files {
						file = filepath.Join(src, filepath.FromSlash(file))
						if err := MkdirAll(filepath.Dir(file)); err != nil {
							t.Fatal(err)
						}
						if err := WriteFile(file, []byte{'a'}); err != nil {
							t.Fatal(err)
						}
					}
					if err := fn(src, dst, test.patterns); err != nil {
						if test.err != "" {
							if strings.Contains(err.Error(), test.err) {
								return
							}
							t.Fatalf("got err %q, want %q", err, test.err)
						}
						t.Fatal(err)
					} else if test.err != "" {
						t.Fatalf("got no err, want %q", test.err)
					}
					if err := os.RemoveAll(src); err != nil {
						t.Fatal(err)
					}
					for _, file := range test.files {
						if !IsExist(filepath.Join(dst, filepath.FromSlash(file))) {
							t.Fatalf("%v does not exist in dst", file)
						}
					}
					if !FilesExist(dst, test.patterns) {
						t.Fatalf("dst files don't exist after copy")
					}
				})
			}
		})
	}
}

func TestMonotonicNano(t *testing.T) {
	start := MonotonicNano()
	time.Sleep(100 * time.Millisecond)
	diff := MonotonicNano() - start
	if diff <= 0 || diff > 10*time.Second {
		t.Fatalf("diff %v", diff)
	}
}

func TestReadWriteJSON(t *testing.T) {
	type Test struct {
		X int
		Y string
	}
	test := Test{10, "foo"}
	file := filepath.Join(t.TempDir(), "file")
	if err := WriteJSON(file, test); err != nil {
		t.Fatal(err)
	}
	test2, err := ReadJSON[Test](file)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(test, test2); diff != "" {
		t.Fatal(diff)
	}
}

func TestDiskUsage(t *testing.T) {
	if runtime.GOOS != "linux" {
		// The test uses some hardcoded numbers for disk usage,
		// it's hard to get it working on all possible OSes.
		t.Skip("skipping on non-linux")
	}
	dir := t.TempDir()
	var currentUsage uint64
	expectUsage := func(minIncrease, maxIncrease uint64) {
		usage, err := DiskUsage(dir)
		if err != nil {
			t.Fatal(err)
		}
		expectMin := currentUsage + minIncrease
		expectMax := currentUsage + maxIncrease
		t.Logf("got usage %v when expected (%v, %v)", usage, expectMin, expectMax)
		if usage <= expectMin || usage >= expectMax {
			t.Fatalf("bad usage %v, expect (%v, %v)", usage, expectMin, expectMax)
		}
		currentUsage = usage
	}
	expectUsage(1, 5<<10)
	if err := MkdirAll(filepath.Join(dir, "nested")); err != nil {
		t.Fatal(err)
	}
	expectUsage(1, 5<<10)
	if err := WriteFile(filepath.Join(dir, "nested", "foo"), bytes.Repeat([]byte{'a'}, 1<<10)); err != nil {
		t.Fatal(err)
	}
	expectUsage(1<<10, 5<<10)
	if err := WriteFile(filepath.Join(dir, "nested", "bar"), bytes.Repeat([]byte{'a'}, 10<<10)); err != nil {
		t.Fatal(err)
	}
	expectUsage(10<<10, 14<<10)
	// Symlinks must not be counted twice.
	if err := os.Symlink(filepath.Join(dir, "nested"), filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	expectUsage(1, 1<<10)

	if err := os.Symlink(filepath.Join(dir, "nested", "bar"), filepath.Join(dir, "filelink")); err != nil {
		t.Fatal(err)
	}
	expectUsage(1, 1<<10)
}
