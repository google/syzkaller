
package backend

import (
	"fmt"

	"github.com/google/syzkaller/sys/targets"
)

func PreviousInstructionPC(target *targets.Target, vm string, pc uint64) uint64 {
	// AMD64 call instruction is 5 bytes
	return pc - 5
}

func NextInstructionPC(target *targets.Target, vm string, pc uint64) uint64 {
	// AMD64 call instruction is 5 bytes
	return pc + 5
}
