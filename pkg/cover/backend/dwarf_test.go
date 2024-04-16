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
		if !isKcovBrokenInCompiler(ver) {
			t.Fatalf("isKcovBrokenInCompiler(%q) unexpectedly returned false", ver)
		}
	}
	for _, ver := range inputDataFalse {
		if isKcovBrokenInCompiler(ver) {
			t.Fatalf("isKcovBrokenInCompiler(%q) unexpectedly returned true", ver)
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
				t.Fatalf("cleanPathAndroid(`%s`, `%s`, %v, ...) unexpectedly returned (`%s`, `%s`) instead of (`%s`, `%s`)",
					path, test.SrcDir, test.Delimiters, rpath, rname, epath, ename)
			}
		}
	}
}

type NextCallTargetTest struct {
	Arch      *Arch
	Text      uint64
	Data      []byte
	ExpTarget uint64
	ExpPC     uint64
}

func runNextCallTarget(t *testing.T, arg NextCallTargetTest) {
	i := 0
	target, pc := nextCallTarget(arg.Arch, arg.Text, arg.Data, &i)
	if target != arg.ExpTarget || pc != arg.ExpPC {
		t.Fatalf("nextCallTarget(`%v`, %x, %v) unexpectedly returned (%x, %x) instead of (%x, %x)",
			arg.Arch, arg.Text, arg.Data, target, pc, arg.ExpTarget, arg.ExpPC)
	}
}

func TestNextCallTargetARM64(t *testing.T) {
	tests := []NextCallTargetTest{
		// ffff800080020010:       9414234f        bl      ffff800080528d4c <__sanitizer_cov_trace_pc>
		{
			Data:      []byte{0x4f, 0x23, 0x14, 0x94},
			ExpTarget: 0xffff800080528d4c,
			ExpPC:     0xffff800080020010,
		},
		// ffff800080020088:       95fbe498        bl      ffff800087f192e8 <__debug_smp_processor_id_veneer>
		{
			Data:      []byte{0x98, 0xe4, 0xfb, 0x95},
			ExpTarget: 0xffff800087f192e8,
			ExpPC:     0xffff800080020088,
		},
		// ffff80008477626c:       96f6cab8        bl      ffff800080528d4c <__sanitizer_cov_trace_pc>
		{
			Data:      []byte{0xb8, 0xca, 0xf6, 0x96},
			ExpTarget: 0xffff800080528d4c,
			ExpPC:     0xffff80008477626c,
		},
		// ffff80008052aa18:       97fff8cd        bl      ffff800080528d4c <__sanitizer_cov_trace_pc>
		{
			Data:      []byte{0xcd, 0xf8, 0xff, 0x97},
			ExpTarget: 0xffff800080528d4c,
			ExpPC:     0xffff80008052aa18,
		},
	}
	for _, test := range tests {
		arch := arches["arm64"]
		test.Arch = &arch
		test.Text = test.ExpPC
		runNextCallTarget(t, test)
	}
}

func TestNextCallTargetAMD64(t *testing.T) {
	tests := []NextCallTargetTest{
		// ffffffff811744c6:	e8 85 fb 7b 00       	call   ffffffff81934050 <__sanitizer_cov_trace_pc>
		{
			Data:      []byte{0xe8, 0x85, 0xfb, 0x7b, 0x00},
			Text:      0xffffffff811744c6,
			ExpTarget: 0xffffffff81934050,
			ExpPC:     0xffffffff811744c6,
		},
		// Same, but the search window starts two bytes earlier.
		{
			Data:      []byte{0x90, 0x90, 0xe8, 0x85, 0xfb, 0x7b, 0x00},
			Text:      0xffffffff811744c4,
			ExpTarget: 0xffffffff81934050,
			ExpPC:     0xffffffff811744c6,
		},
	}
	for _, test := range tests {
		arch := arches["amd64"]
		test.Arch = &arch
		runNextCallTarget(t, test)
	}
}
