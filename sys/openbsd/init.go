// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package openbsd

import (
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
)

func isKcovFd(dev uint64) bool {
	// openbsd:src/sys/sys/types.h
	major := (dev >> 8) & 0xff
	minor := (dev & 0xff) | ((dev & 0xffff0000) >> 8)

	return major == devFdMajor && minor >= kcovFdMinorMin && minor < kcovFdMinorMax
}

func (arch *arch) SanitizeCall(c *prog.Call) {
	argStart := 1
	switch c.Meta.CallName {
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
	default:
		arch.unix.SanitizeCall(c)
	}
}
