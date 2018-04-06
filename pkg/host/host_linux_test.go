// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build linux

package host

import (
	"runtime"
	"syscall"
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestSupportedSyscalls(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget("linux", runtime.GOARCH)
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
