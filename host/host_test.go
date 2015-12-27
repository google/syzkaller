// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"syscall"
	"testing"

	"github.com/google/syzkaller/sys"
)

func TestLog(t *testing.T) {
	// Dump for manual inspection.
	supp, err := DetectSupportedSyscalls()
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	t.Logf("unsupported:")
	for _, c := range sys.Calls {
		s, ok := supp[c]
		if ok && !s {
			t.Fatalf("map contains false value")
		}
		if !s {
			t.Logf("\t%v", c.Name)
		}
	}
	trans := sys.TransitivelyEnabledCalls(supp)
	t.Logf("transitively unsupported:")
	for _, c := range sys.Calls {
		s, ok := trans[c]
		if ok && !s {
			t.Fatalf("map contains false value")
		}
		if !s && supp[c] {
			t.Logf("\t%v", c.Name)
		}
	}
}

func TestSupportedSyscalls(t *testing.T) {
	supp, err := DetectSupportedSyscalls()
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
		c := sys.CallMap[name]
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
