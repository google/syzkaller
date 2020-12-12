// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"fmt"

	"github.com/google/syzkaller/sys/targets"
)

func RestorePC(pc, base uint32) uint64 {
	return uint64(base)<<32 + uint64(pc)
}

func PreviousInstructionPC(target *targets.Target, pc uint64) uint64 {
	offset := instructionLen(target.Arch)
	pc -= offset
	// THUMB instructions are 2 or 4 bytes with low bit set.
	// ARM instructions are always 4 bytes.
	if target.Arch == targets.ARM {
		return pc & ^uint64(1)
	}
	return pc
}

func NextInstructionPC(target *targets.Target, pc uint64) uint64 {
	offset := instructionLen(target.Arch)
	pc += offset
	// THUMB instructions are 2 or 4 bytes with low bit set.
	// ARM instructions are always 4 bytes.
	if target.Arch == targets.ARM {
		return pc & ^uint64(1)
	}
	return pc
}

func instructionLen(arch string) uint64 {
	switch arch {
	case targets.AMD64:
		return 5
	case targets.I386:
		return 5
	case targets.ARM64:
		return 4
	case targets.ARM:
		return 3
	case targets.PPC64LE:
		return 4
	case targets.MIPS64LE:
		return 8
	case targets.S390x:
		return 6
	case targets.RiscV64:
		return 4
	default:
		panic(fmt.Sprintf("unknown arch %q", arch))
	}
}
