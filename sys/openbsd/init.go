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
		unix:             targets.MakeUnixNeutralizer(target),
		CLOCK_REALTIME:   target.GetConst("CLOCK_REALTIME"),
		CTL_KERN:         target.GetConst("CTL_KERN"),
		DIOCCLRSTATES:    target.GetConst("DIOCCLRSTATES"),
		DIOCKILLSTATES:   target.GetConst("DIOCKILLSTATES"),
		KERN_MAXCLUSTERS: target.GetConst("KERN_MAXCLUSTERS"),
		KERN_MAXTHREAD:   target.GetConst("KERN_MAXTHREAD"),
		S_IFCHR:          target.GetConst("S_IFCHR"),
		S_IFMT:           target.GetConst("S_IFMT"),
		MCL_FUTURE:       target.GetConst("MCL_FUTURE"),
		RLIMIT_DATA:      target.GetConst("RLIMIT_DATA"),
		RLIMIT_STACK:     target.GetConst("RLIMIT_STACK"),
	}

	target.MakeDataMmap = targets.MakePosixMmap(target, false, false)
	target.Neutralize = arch.neutralize
	target.AnnotateCall = arch.annotateCall
}

type arch struct {
	unix             *targets.UnixNeutralizer
	CLOCK_REALTIME   uint64
	CTL_KERN         uint64
	DIOCCLRSTATES    uint64
	DIOCKILLSTATES   uint64
	KERN_MAXCLUSTERS uint64
	KERN_MAXTHREAD   uint64
	S_IFCHR          uint64
	S_IFMT           uint64
	MCL_FUTURE       uint64
	RLIMIT_DATA      uint64
	RLIMIT_STACK     uint64
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

func (arch *arch) neutralize(c *prog.Call) {
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
	case "clock_settime":
		arch.neutralizeClockSettime(c)
	case "ioctl":
		// Performing the following ioctl commands on a /dev/pf file
		// descriptor causes the ssh VM connection to die. For now, just
		// rewire them to an invalid command.
		request := c.Args[1].(*prog.ConstArg)
		if request.Val == arch.DIOCCLRSTATES || request.Val == arch.DIOCKILLSTATES {
			request.Val = 0
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
		flags.Val &= ^arch.MCL_FUTURE
	case "setrlimit":
		arch.neutralizeRlimit(c)
	case "sysctl":
		arch.neutralizeSysctl(c)
	default:
		arch.unix.Neutralize(c)
	}
}

func (arch *arch) neutralizeClockSettime(c *prog.Call) {
	switch v := c.Args[0].(type) {
	case *prog.ConstArg:
		// Do not fiddle with the wall clock, one of the causes of "no
		// output from test machine" reports.
		if v.Val == arch.CLOCK_REALTIME {
			v.Val = ^uint64(0)
		}
	}
}

func (arch *arch) neutralizeRlimit(c *prog.Call) {
	rlimitMin := uint64(0)
	rlimitMax := uint64(math.MaxUint64)
	resource := c.Args[0].(*prog.ConstArg).Val & rlimitMask
	if resource == arch.RLIMIT_DATA {
		// OpenBSD performs a strict validation of the RLIMIT_DATA soft
		// limit during memory allocation. Lowering the same limit could
		// cause syz-executor to run out of memory quickly. Therefore
		// make sure to not go lower than the default soft limit for the
		// staff group.
		rlimitMin = 1536 * 1024 * 1024
	} else if resource == arch.RLIMIT_STACK {
		// Do not allow the stack to grow beyond the initial soft limit
		// chosen by syz-executor. Otherwise, syz-executor will most
		// likely not be able to perform any more heap allocations since
		// they majority of memory is reserved for the stack.
		rlimitMax = 1 * 1024 * 1024
	} else {
		return
	}

	ptr := c.Args[1].(*prog.PointerArg)
	if ptr.Res == nil {
		return
	}

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

func (arch *arch) neutralizeSysctl(c *prog.Call) {
	ptr := c.Args[0].(*prog.PointerArg)
	if ptr.Res == nil {
		return
	}

	var mib []*prog.ConstArg
	for _, arg := range ptr.Res.(*prog.GroupArg).Inner {
		switch v := arg.(type) {
		case *prog.ConstArg:
			mib = append(mib, v)
		}
	}

	if !arch.neutralizeSysctlKern(mib) {
		return
	}

	for _, m := range mib {
		m.Val = 0
	}
	// Reflect changes in the namelen argument.
	if len(c.Args) >= 1 {
		switch v := c.Args[1].(type) {
		case *prog.ConstArg:
			v.Val = 0
		}
	}
}

func (arch *arch) neutralizeSysctlKern(mib []*prog.ConstArg) bool {
	// Do not fiddle with root only knob kern.maxclusters, one of the causes
	// of "no output from test machine" reports.
	if len(mib) >= 2 &&
		mib[0].Val == arch.CTL_KERN && mib[1].Val == arch.KERN_MAXCLUSTERS {
		return true
	}

	// Do not fiddle with root only knob kern.maxthread, can cause the
	// syz-execprog process to panic.
	if len(mib) >= 2 &&
		mib[0].Val == arch.CTL_KERN && mib[1].Val == arch.KERN_MAXTHREAD {
		return true
	}

	return false
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
