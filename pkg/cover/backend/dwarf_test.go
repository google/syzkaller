// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"testing"
)

// kcov is known to be broken in GCC versions < 14.
// If the version cannot be parsed, assume it is broken.
func TestIsKcovBrokenInCompiler(t *testing.T) {
	inputDataTrue := []string{
		"gcc (Debian 12.2.0-14) 12.2.0",
		"gcc (Debian 13.2.0-5) 13.2.0",
		"arm-unknown-linux-gnueabihf-g++ (GCC) 13.2.0",
		"aarch64-unknown-linux-gnu-g++ (GCC) 11.1.0",
		"g++ (Compiler-Explorer-Build-gcc-d3f1cf4e50356e44f745c5bc67ffd529cc4e2358-binutils-2.36.1) 12.0.0 20210426 (experimental)", // nolint:lll
		"g++ (Compiler-Explorer-Build-gcc--binutils-2.40) 13.2.0",
		"gcc (Compiler-Explorer-Build) 9.2.0",
		"GCC something something",
	}
	inputDataFalse := []string{
		"Debian clang version 16.0.6 (16)",
		"arm-unknown-linux-gnueabihf-g++ (GCC) 14.0.1 20240124 (experimental)",
		"g++ (Compiler-Explorer-Build-gcc-2a9637b229f64775d82fb5917f83f71e8ad1911d-binutils-2.40) 14.0.1 20240125 (experimental)", // nolint:lll
	}
	for _, ver := range inputDataTrue {
		result := IsKcovBrokenInCompiler(ver)
		if !result {
			t.Fatalf("IsKcovBrokenInCompiler(`%s`) unexpectedly returned %v\n", ver, result)
		}
	}
	for _, ver := range inputDataFalse {
		result := IsKcovBrokenInCompiler(ver)
		if result {
			t.Fatalf("IsKcovBrokenInCompiler(`%s`) unexpectedly returned %v\n", ver, result)
		}
	}
}

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
				t.Fatalf("cleanPathAndroid(`%s`, `%s`, %v, ...) unexpectedly returned (`%s`, `%s`) instead of (`%s`, `%s`)\n",
					path, test.SrcDir, test.Delimiters, rpath, rname, epath, ename)
			}
		}
	}
}
