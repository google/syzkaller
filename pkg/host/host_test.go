// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestDetectSupportedSyscalls(t *testing.T) {
	// Note: this test is not parallel because it modifies global testFallback var.
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%v", fallback), func(t *testing.T) {
			oldFallback := testFallback
			testFallback = fallback
			defer func() { testFallback = oldFallback }()
			target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
			if err != nil {
				t.Fatal(err)
			}
			// Dump for manual inspection.
			supp, disabled, err := DetectSupportedSyscalls(target, "none")
			if err != nil {
				t.Fatal(err)
			}
			for c, ok := range supp {
				if !ok {
					t.Fatalf("map contains false value for %v", c.Name)
				}
			}
			t.Logf("unsupported:")
			for c, reason := range disabled {
				t.Logf("%v: %v", c.Name, reason)
			}
			_, disabled = target.TransitivelyEnabledCalls(supp)
			t.Logf("\n\ntransitively unsupported:")
			for c, reason := range disabled {
				t.Logf("%v: %v", c.Name, reason)
			}
		})
	}
}

func TestKallsymsParse(t *testing.T) {
	tests := []struct {
		Arch     string
		Kallsyms []byte
		Syscalls []string
	}{
		{
			"amd64",
			[]byte(`
ffffffff817cdcc0 T __sys_bind
ffffffff817cdda0 T __x64_sys_bind
ffffffff817cddc0 T __ia32_sys_bind
ffffffff817cdde0 T __sys_listen
ffffffff817cde80 T __x64_sys_listen
ffffffff817cde90 T __ia32_sys_listen
ffffffff817cdea0 T __sys_accept4
ffffffff817ce080 T __x64_sys_accept4
ffffffff817ce0a0 T __ia32_sys_accept4
			`),
			[]string{"bind", "listen", "accept4"},
		},
		{
			"arm64",
			[]byte(`
ffff000010a3ddf8 T __sys_bind
ffff000010a3def8 T __arm64_sys_bind
ffff000010a3df20 T __sys_listen
ffff000010a3dfd8 T __arm64_sys_listen
ffff000010a3e000 T __sys_accept4
ffff000010a3e1f0 T __arm64_sys_accept4
			`),
			[]string{"bind", "listen", "accept4"},
		},
		{
			"ppc64le",
			[]byte(`
c0000000011ec810 T __sys_bind
c0000000011eca10 T sys_bind
c0000000011eca10 T __se_sys_bind
c0000000011eca70 T __sys_listen
c0000000011ecc10 T sys_listen
c0000000011ecc10 T __se_sys_listen
c0000000011ecc70 T __sys_accept4
c0000000011ed050 T sys_accept4
c0000000011ed050 T __se_sys_accept4
			`),
			[]string{"bind", "listen", "accept4"},
		},
	}

	for _, test := range tests {
		syscallSet := parseKallsyms(test.Kallsyms, test.Arch)
		if len(syscallSet) != len(test.Syscalls) {
			t.Fatalf("wrong number of parse syscalls, expected: %v, got: %v",
				len(test.Syscalls), len(syscallSet))
		}
		for _, syscall := range test.Syscalls {
			if _, ok := syscallSet[syscall]; !ok {
				t.Fatalf("syscall %v not found in parsed syscall list", syscall)
			}
		}
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	features, err := Check(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, feat := range features {
		t.Logf("%-24v: %v", feat.Name, feat.Reason)
	}
}
