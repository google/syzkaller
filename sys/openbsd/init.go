// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package openbsd

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type arch struct {
	MAP_ANONYMOUS uint64
	MAP_PRIVATE   uint64
	MAP_FIXED     uint64
	PROT_READ     uint64
	PROT_WRITE    uint64
	S_IFMT        uint64
	S_IFCHR       uint64
	S_IFBLK       uint64
	S_IFIFO       uint64
}

func InitTarget(target *prog.Target) {
	arch := &arch{
		MAP_ANONYMOUS: target.ConstMap["MAP_ANON"],
		MAP_FIXED:     target.ConstMap["MAP_FIXED"],
		MAP_PRIVATE:   target.ConstMap["MAP_PRIVATE"],
		PROT_READ:     target.ConstMap["PROT_READ"],
		PROT_WRITE:    target.ConstMap["PROT_WRITE"],
		S_IFBLK:       target.ConstMap["S_IFBLK"],
		S_IFCHR:       target.ConstMap["S_IFCHR"],
		S_IFIFO:       target.ConstMap["S_IFIFO"],
		S_IFMT:        target.ConstMap["S_IFMT"],
	}

	target.MakeMmap = targets.MakePosixMmap(target)
	target.SanitizeCall = arch.sanitizeCall
}

func (arch *arch) sanitizeCall(c *prog.Call) {
	mknodModeIdx := -1
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "mknod", "mknod$loop":
		mknodModeIdx = 1
	case "mknodat":
		mknodModeIdx = 2
	case "exit":
		code := c.Args[0].(*prog.ConstArg)
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
	if mknodModeIdx != -1 {
		val := c.Args[mknodModeIdx].(*prog.ConstArg).Val
		c.Args[mknodModeIdx].(*prog.ConstArg).Val = arch.sanitizeMknodMode(val)
	}
}

// Sanitize the mode argument passed to mknod in order to prevent vnodes of type
// VBAD from being created. Such vnodes will likely trigger assertion errors by
// the kernel.
func (arch *arch) sanitizeMknodMode(mode uint64) uint64 {
	saneMode := mode & ^arch.S_IFMT
	switch {
	case (mode & arch.S_IFMT) != arch.S_IFMT:
		return mode
	case (mode & arch.S_IFCHR) == arch.S_IFCHR:
		return saneMode | arch.S_IFCHR
	case (mode & arch.S_IFBLK) == arch.S_IFBLK:
		return saneMode | arch.S_IFBLK
	case (mode & arch.S_IFIFO) == arch.S_IFIFO:
		return saneMode | arch.S_IFIFO
	default:
		return saneMode
	}
}
