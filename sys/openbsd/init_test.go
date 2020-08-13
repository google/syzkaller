// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package openbsd_test

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/openbsd/gen"
)

func TestNeutralize(t *testing.T) {
	prog.TestDeserializeHelper(t, "openbsd", "amd64", nil, []prog.DeserializeTest{
		{
			In:  `chflagsat(0x0, 0x0, 0x60004, 0x0)`,
			Out: `chflagsat(0x0, 0x0, 0x0, 0x0)`,
		},
		{
			In:  `fchflags(0x0, 0x60004)`,
			Out: `fchflags(0x0, 0x0)`,
		},
		// Note, a random ioctl description used since only the command
		// is of importance.
		{
			In:  `ioctl$BIOCSDIRFILT(0x0, 0xc0e04429, 0x0)`,
			Out: `ioctl$BIOCSDIRFILT(0x0, 0x0, 0x0)`,
		},
		{
			In:  `ioctl$BIOCSDIRFILT(0x0, 0xc0e04412, 0x0)`,
			Out: `ioctl$BIOCSDIRFILT(0x0, 0x0, 0x0)`,
		},
		{
			// major=22, minor=232
			In:  `mknodat(0x0, 0x0, 0x0, 0x16e8)`,
			Out: `mknodat(0x0, 0x0, 0x0, 0x202)`,
		},
		{
			// major=22, minor=232
			In:  `mknod(0x0, 0x0, 0x16e8)`,
			Out: `mknod(0x0, 0x0, 0x202)`,
		},
		{
			// major=22, minor=0
			In: `mknod(0x0, 0x0, 0x1600)`,
		},
		{
			// major=4, minor=0
			In: `mknod(0x0, 0x0, 0x400)`,
		},
		{
			// major=4, minor=1
			In:  `mknod(0x0, 0x0, 0x401)`,
			Out: `mknod(0x0, 0x0, 0x202)`,
		},
		{
			// major=4, minor=2
			In:  `mknod(0x0, 0x0, 0x402)`,
			Out: `mknod(0x0, 0x0, 0x202)`,
		},
		{
			// MCL_CURRENT | MCL_FUTURE
			In:  `mlockall(0x3)`,
			Out: `mlockall(0x1)`,
		},
		{
			// RLIMIT_DATA
			In:  `setrlimit(0x2, &(0x7f0000cc0ff0)={0x0, 0x80000000})`,
			Out: `setrlimit(0x2, &(0x7f0000cc0ff0)={0x60000000, 0x80000000})`,
		},
		{
			// RLIMIT_DATA
			In:  `setrlimit(0x10000000000002, &(0x7f0000cc0ff0)={0x0, 0x80000000})`,
			Out: `setrlimit(0x10000000000002, &(0x7f0000cc0ff0)={0x60000000, 0x80000000})`,
		},
		{
			// RLIMIT_STACK
			In:  `setrlimit(0x3, &(0x7f0000cc0ff0)={0x1000000000, 0x1000000000})`,
			Out: `setrlimit(0x3, &(0x7f0000cc0ff0)={0x100000, 0x100000})`,
		},
		{
			// RLIMIT_CPU
			In: `setrlimit(0x0, &(0x7f0000cc0ff0)={0x1, 0x1})`,
		},
		{
			// Test for sysctl kern.maxclusters.
			In:  `sysctl$kern(&(0x7f0000cc0ff0)={0x1, 0x43}, 0x2, 0x0, 0x0, &(0x7f0000000180), 0x0)`,
			Out: `sysctl$kern(&(0x7f0000cc0ff0)={0x0}, 0x0, 0x0, 0x0, &(0x7f0000000180), 0x0)`,
		},
		{
			// Test for sysctl kern.maxthread.
			In:  `sysctl$kern(&(0x7f0000000300)={0x1, 0x19}, 0x2, 0x0, 0x0, &(0x7f0000000300)="ff0380c5", 0x4)`,
			Out: `sysctl$kern(&(0x7f0000000300)={0x0}, 0x0, 0x0, 0x0, &(0x7f0000000300)="ff0380c5", 0x4)`,
		},
		{
			In:  `clock_settime(0x0, &(0x7f0000cc0ff0)={0x0, 0x0})`,
			Out: `clock_settime(0xffffffffffffffff, &(0x7f0000cc0ff0))`,
		},
	})
}
