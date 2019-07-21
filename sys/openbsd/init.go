// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package openbsd

import (
	"fmt"
	"math"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		unix:    targets.MakeUnixSanitizer(target),
		S_IFMT:  target.GetConst("S_IFMT"),
		S_IFCHR: target.GetConst("S_IFCHR"),
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.SanitizeCall
	target.AnnotateCall = arch.annotateCall
}

type arch struct {
	unix    *targets.UnixSanitizer
	S_IFMT  uint64
	S_IFCHR uint64
}

const (
	mknodMode = 0
	mknodDev  = 1

	// openbsd:src/etc/etc.amd64/MAKEDEV
	devFdMajor  = 22
	devNullDevT = 0x0202

	// kCoverFd in executor/executor.cc
	kcovFdMinorMin = 232
	// kOutPipeFd in executor/executor.cc
	kcovFdMinorMax = 248

	// MCL_FUTURE from openbsd:src/sys/sys/mman.h
	mclFuture uint64 = 0x2

	// RLIMIT_DATA from openbsd:src/sys/sys/resource.h
	rlimitData = 2
	// RLIMIT_STACK from openbsd:src/sys/sys/resource.h
	rlimitStack = 3
	// Mask covering all valid rlimit resources.
	rlimitMask = 0xf
)

// openbsd:src/sys/sys/types.h
func devmajor(dev uint64) uint64 {
	return (dev >> 8) & 0xff
}

// openbsd:src/sys/sys/types.h
func devminor(dev uint64) uint64 {
	return (dev & 0xff) | ((dev & 0xffff0000) >> 8)
}

func isKcovFd(dev uint64) bool {
	major := devmajor(dev)
	minor := devminor(dev)

	return major == devFdMajor && minor >= kcovFdMinorMin && minor < kcovFdMinorMax
}

func (arch *arch) SanitizeCall(c *prog.Call) {
	argStart := 1
	switch c.Meta.CallName {
	case "chflagsat":
		argStart = 2
		fallthrough
	case "chflags", "fchflags":
		// Prevent changing mutability flags on files. This is
		// especially problematic for file descriptors referring to
		// tty/pty devices since it can cause the SSH connection to the
		// VM to die.
		flags := c.Args[argStart].(*prog.ConstArg)
		badflags := [...]uint64{
			0x00000002, // UF_IMMUTABLE
			0x00000004, // UF_APPEND
			0x00020000, // SF_IMMUTABLE
			0x00040000, // SF_APPEND
		}
		for _, f := range badflags {
			flags.Val &= ^f
		}
	case "mknodat":
		argStart = 2
		fallthrough
	case "mknod":
		// Prevent vnodes of type VBAD from being created. Such vnodes will
		// likely trigger assertion errors by the kernel.
		mode := c.Args[argStart+mknodMode].(*prog.ConstArg)
		if mode.Val&arch.S_IFMT == arch.S_IFMT {
			mode.Val &^= arch.S_IFMT
			mode.Val |= arch.S_IFCHR
		}

		// Prevent /dev/fd/X devices from getting created where X maps
		// to an open kcov fd. They interfere with kcov data collection
		// and cause corpus explosion.
		// https://groups.google.com/d/msg/syzkaller/_IRWeAjVoy4/Akl2XMZTDAAJ
		dev := c.Args[argStart+mknodDev].(*prog.ConstArg)
		if isKcovFd(dev.Val) {
			dev.Val = devNullDevT
		}

		// Prevent /dev/sd0b (swap partition) and /dev/sd0c (raw disk)
		// nodes from being created. Writing to such devices can corrupt
		// the file system.
		if devmajor(dev.Val) == 4 && (devminor(dev.Val) == 1 || devminor(dev.Val) == 2) {
			dev.Val = devNullDevT
		}
	case "mlockall":
		flags := c.Args[0].(*prog.ConstArg)
		flags.Val &= ^mclFuture
	case "setrlimit":
		var rlimitMin uint64
		var rlimitMax uint64 = math.MaxUint64
		resource := c.Args[0].(*prog.ConstArg).Val & rlimitMask
		if resource == rlimitData {
			// OpenBSD performs a strict validation of the
			// RLIMIT_DATA soft limit during memory allocation.
			// Lowering the same limit could cause syz-executor to
			// run out of memory quickly. Therefore make sure to not
			// go lower than the default soft limit for the staff
			// group.
			rlimitMin = 1536 * 1024 * 1024
		} else if resource == rlimitStack {
			// Do not allow the stack to grow beyond the initial
			// soft limit chosen by syz-executor. Otherwise,
			// syz-executor will most likely not be able to perform
			// any more heap allocations since they majority of
			// memory is reserved for the stack.
			rlimitMax = 1 * 1024 * 1024
		} else {
			break
		}
		ptr := c.Args[1].(*prog.PointerArg)
		if ptr.Res != nil {
			args := ptr.Res.(*prog.GroupArg).Inner
			for _, arg := range args {
				switch v := arg.(type) {
				case *prog.ConstArg:
					if v.Val < rlimitMin {
						v.Val = rlimitMin
					}
					if v.Val > rlimitMax {
						v.Val = rlimitMax
					}
				}
			}
		}
	default:
		arch.unix.SanitizeCall(c)
	}
}

func (arch *arch) annotateCall(c prog.ExecCall) string {
	devArg := 2
	switch c.Meta.Name {
	case "mknodat":
		devArg = 3
		fallthrough
	case "mknod":
		dev := c.Args[devArg].(prog.ExecArgConst).Value
		return fmt.Sprintf("major = %v, minor = %v", devmajor(dev), devminor(dev))
	}
	return ""
}
