// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux
// +build linux

package host

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestSupportedSyscalls(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(targets.Linux, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	supp, _, err := DetectSupportedSyscalls(target, "none")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	// These are safe to execute with invalid arguments.
	safe := []string{
		"memfd_create",
		"sendfile",
		"bpf$MAP_CREATE",
		"open",
		"openat",
		"read",
		"write",
		"stat",
	}
	for _, name := range safe {
		c := target.SyscallMap[name]
		if c == nil {
			t.Fatalf("can't find syscall '%v'", name)
		}
		a := ^uintptr(0) - 4097 // hopefully invalid
		_, _, err := syscall.Syscall6(uintptr(c.NR), a, a, a, a, a, a)
		if err == 0 {
			t.Fatalf("%v did not fail", name)
		}
		if ok := err != syscall.ENOSYS; ok != supp[c] {
			t.Fatalf("syscall %v: perse=%v kallsyms=%v", name, ok, supp[c])
		}
	}
}

func TestKallsymsParse(t *testing.T) {
	tests := []struct {
		Arch              string
		Kallsyms          []byte
		ParsedSyscalls    []string
		SupportedSyscalls []string
	}{
		{
			targets.AMD64,
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
			[]string{"bind", "listen", "accept4"},
		},
		{
			targets.ARM64,
			[]byte(`
ffff000010a3ddf8 T __sys_bind
ffff000010a3def8 T __arm64_sys_bind
ffff000010a3df20 T __sys_listen
ffff000010a3dfd8 T __arm64_sys_listen
ffff000010a3e000 T __sys_accept4
ffff000010a3e1f0 T __arm64_sys_accept4
			`),
			[]string{"bind", "listen", "accept4"},
			[]string{"bind", "listen", "accept4"},
		},
		{
			targets.PPC64LE,
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
			[]string{"bind", "listen", "accept4"},
		},
		{
			targets.ARM,
			[]byte(`
c037c67c T __se_sys_setfsuid
c037c694 T __sys_setfsgid
c037c790 T sys_setfsgid
c037c790 T __se_sys_setfsgid
c037c7a8 T sys_getpid
c037c7d0 T sys_gettid
c037c7f8 T sys_getppid
			`),
			[]string{"setfsgid", "getpid", "gettid", "getppid"},
			[]string{"setfsgid", "getpid", "gettid", "getppid"},
		},
		// Test kallsymsRenameMap.
		{
			targets.PPC64LE,
			[]byte(`
c00000000037eb00 T sys_newstat
			`),
			[]string{"newstat"},
			[]string{"stat"},
		},
		{
			targets.S390x,
			[]byte(`
0000000000e4f760 T __sys_bind
0000000000e4f8e8 T __s390_sys_bind
0000000000e4f938 T __s390x_sys_bind
0000000000e4f938 T __se_sys_bind
0000000000e4f988 T __sys_listen
0000000000e4fab0 T __s390_sys_listen
0000000000e4faf8 T __s390x_sys_listen
0000000000e4faf8 T __se_sys_listen
0000000000e4fb40 T __sys_accept4
0000000000e4fe58 T __s390_sys_accept4
0000000000e4feb0 T __s390x_sys_accept4
0000000000e4feb0 T __se_sys_accept4
			`),
			[]string{"bind", "listen", "accept4"},
			[]string{"bind", "listen", "accept4"},
		},
		{
			targets.RiscV64,
			[]byte(`
ffffffe0005c9b02 T __sys_bind
ffffffe0005c9ba0 T sys_bind
ffffffe0005c9ba0 T __se_sys_bind
ffffffe0005c9e72 T __sys_accept4
ffffffe0005c9f00 T sys_accept4
ffffffe0005c9f00 T __se_sys_accept4
ffffffe0005c9bd8 T __sys_listen
ffffffe0005c9c76 T sys_listen
ffffffe0005c9c76 T __se_sys_listen
			`),
			[]string{"bind", "listen", "accept4"},
			[]string{"bind", "listen", "accept4"},
		},
	}

	for _, test := range tests {
		syscallSet := parseKallsyms(test.Kallsyms, test.Arch)
		if len(syscallSet) != len(test.ParsedSyscalls) {
			t.Fatalf("wrong number of parse syscalls, expected: %v, got: %v",
				len(test.ParsedSyscalls), len(syscallSet))
		}
		for _, syscall := range test.ParsedSyscalls {
			if _, ok := syscallSet[syscall]; !ok {
				t.Fatalf("syscall %v not found in parsed syscall list", syscall)
			}
		}
		for _, syscall := range test.SupportedSyscalls {
			if newname := kallsymsRenameMap[syscall]; newname != "" {
				syscall = newname
			}

			if _, ok := syscallSet[syscall]; !ok {
				t.Fatalf("syscall %v not found in supported syscall list", syscall)
			}
		}
	}
}

func TestMatchKernelVersion(t *testing.T) {
	tests := []struct {
		version string
		major   int
		minor   int
		res     bool
		bad     bool
	}{
		{
			version: "5.9.0-rc5-next-20200918",
			major:   5,
			minor:   8,
			res:     true,
		},
		{
			version: "5.9.0-rc5-next-20200918",
			major:   4,
			minor:   10,
			res:     true,
		},
		{
			version: "5.9.0-rc5-next-20200918",
			major:   5,
			minor:   9,
			res:     true,
		},
		{
			version: "5.9.0-rc5-next-20200918",
			major:   5,
			minor:   10,
			res:     false,
		},
		{
			version: "5.9.0-rc5-next-20200918",
			major:   6,
			minor:   0,
			res:     false,
		},
		{
			version: "4.4.246-19567-g2c01e3dada31",
			major:   4,
			minor:   3,
			res:     true,
		},
		{
			version: "4.4.246-19567-g2c01e3dada31",
			major:   4,
			minor:   4,
			res:     true,
		},
		{
			version: "5.17.17-1debian-amd64",
			major:   5,
			minor:   16,
			res:     true,
		},
		{
			version: "5.17.17-1debian-amd64",
			major:   5,
			minor:   17,
			res:     true,
		},
		{
			version: "3.5",
			major:   3,
			minor:   4,
			res:     true,
		},
		{
			version: "3.5",
			major:   3,
			minor:   5,
			res:     true,
		},
		{
			version: "3.5",
			major:   3,
			minor:   6,
			res:     false,
		},
		{
			version: "",
			bad:     true,
		},
		{
			version: "something unparsable",
			bad:     true,
		},
		{
			version: "mykernel 4.17-5",
			bad:     true,
		},
		{
			version: "999999.999999",
			bad:     true,
		},
		{
			version: "4.abc.def",
			bad:     true,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ok, bad := matchKernelVersion(test.version, test.major, test.minor)
			if test.bad && !bad {
				t.Fatal("want error, but got no error")
			}
			if !test.bad && bad {
				t.Fatalf("want no error, but got error")
			}
			if test.res != ok {
				t.Fatalf("want match %v, but got %v", test.res, ok)
			}
		})
	}
}
