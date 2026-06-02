// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

type CleanPathAndroidTest struct {
	SrcDir     string
	Delimiters []string
	// Each test case is a triple of {path, epath, ename}, where path is passed to cleanPathAndroid(),
	// and (epath, ename) is its expected return value.
	Files    [][3]string
	FnExists func(string) bool
}

func TestCleanPathAndroid(t *testing.T) {
	tests := []CleanPathAndroidTest{
		// Test that paths with "/aosp/" and "/private/" in them are normalized.
		{
			SrcDir:     "/src/kernel",
			Delimiters: []string{"/aosp/", "/private/"},
			Files: [][3]string{
				{"/src/kernel/aosp/mm/mmap.c", "mm/mmap.c", "/src/kernel/aosp/mm/mmap.c"},
				{"/src/kernel/out/cache/feedface/aosp/mm/mmap.c", "mm/mmap.c", "/src/kernel/aosp/mm/mmap.c"},
				{"/src/kernel/out/cache/cafebabe/private/google_modules/module/mod.c", "google_modules/module/mod.c",
					"/src/kernel/private/google_modules/module/mod.c"},
				{"/some/other/path/aosp/mm/mmap.c", "mm/mmap.c", "/src/kernel/aosp/mm/mmap.c"},
			},
			FnExists: func(string) bool { return true },
		},
		// Test that for empty delimiters empty results are returned.
		{
			SrcDir:     "/src/kernel/",
			Delimiters: []string{},
			Files: [][3]string{
				{"/src/kernel/mm/mmap.c", "", ""},
			},
			FnExists: func(string) bool { return true },
		},
		// Test that for path that does not contain a delimiter the result is constructed based on FnExists().
		{
			SrcDir:     "/src/kernel/",
			Delimiters: []string{"/aosp/", "/private/"},
			Files: [][3]string{
				{"mm/mmap.c", "mm/mmap.c", "/src/kernel/aosp/mm/mmap.c"},
			},
			FnExists: func(s string) bool { return s == "/src/kernel/aosp/mm/mmap.c" },
		},
		// Test that for path that does not contain a delimiter the result is constructed based on FnExists().
		{
			SrcDir:     "/src/kernel/",
			Delimiters: []string{"/aosp/", "/private/"},
			Files: [][3]string{
				{"mm/mmap.c", "mm/mmap.c", "/src/kernel/private/mm/mmap.c"},
			},
			FnExists: func(s string) bool { return s != "/src/kernel/aosp/mm/mmap.c" },
		},
	}
	for _, test := range tests {
		for _, files := range test.Files {
			path, epath, ename := files[0], files[1], files[2]
			rpath, rname := cleanPathAndroid(path, test.SrcDir, test.Delimiters, test.FnExists)
			if (rpath != epath) || (rname != ename) {
				t.Fatalf("cleanPathAndroid(`%s`, `%s`, %v, ...) unexpectedly returned (`%s`, `%s`) instead of (`%s`, `%s`)",
					path, test.SrcDir, test.Delimiters, rpath, rname, epath, ename)
			}
		}
	}
}

func TestPathCleanerEmptyObj(t *testing.T) {
	// Test that empty Obj and Src do not accidentally match all absolute paths.
	// In the old implementation, strings.HasPrefix(abs, "") evaluated to true.
	kernelDirs := &mgrconfig.KernelDirs{
		Src: "",
		Obj: "",
	}
	rel, abs := CleanPath("/random/absolute/path", kernelDirs, nil)
	if rel != "random/absolute/path" || abs != "/random/absolute/path" {
		t.Errorf("expected rel=random/absolute/path, abs=/random/absolute/path, got %q, %q", rel, abs)
	}
}

func TestPathCleanerAbsolutePath(t *testing.T) {
	// Test that an absolute path in the default case isn't erroneously joined with Src.
	// In the old implementation, filepath.Join("/some_src_dir", "/random/absolute/path")
	// would incorrectly yield "/some_src_dir/random/absolute/path".
	kernelDirs := &mgrconfig.KernelDirs{
		Src: "/some_src_dir",
		Obj: "/some_obj_dir",
	}
	rel, abs := CleanPath("/random/absolute/path", kernelDirs, nil)
	if rel != "random/absolute/path" || abs != "/random/absolute/path" {
		t.Errorf("expected rel=random/absolute/path, abs=/random/absolute/path, got %q, %q", rel, abs)
	}
}

func TestPathCleanerRelativePath(t *testing.T) {
	// Test that a standard relative path in the default case is correctly joined with Src.
	kernelDirs := &mgrconfig.KernelDirs{
		Src: "/some_src_dir",
		Obj: "/some_obj_dir",
	}
	rel, abs := CleanPath("relative/path", kernelDirs, nil)
	if rel != "relative/path" || abs != "/some_src_dir/relative/path" {
		t.Errorf("expected rel=relative/path, abs=/some_src_dir/relative/path, got %q, %q", rel, abs)
	}
}

func TestPathCleanerKernelSrcPath(t *testing.T) {
	// Test that an absolute path pointing to Src is properly normalized.
	kernelDirs := &mgrconfig.KernelDirs{
		Src: "/some_src_dir",
		Obj: "/some_obj_dir",
	}
	rel, abs := CleanPath("/some_src_dir/relative/path", kernelDirs, nil)
	if rel != "relative/path" || abs != "/some_src_dir/relative/path" {
		t.Errorf("expected rel=relative/path, abs=/some_src_dir/relative/path, got %q, %q", rel, abs)
	}
}
