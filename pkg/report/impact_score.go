// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"github.com/google/syzkaller/pkg/report/crash"
)

// impactOrder represent an ordering of bug impact severity. The earlier
// entries are considered more severe.
var impactOrder = []crash.Type{
	// Highest Priority (Direct Memory Corruption - Write)
	crash.KASANUseAfterFreeWrite,
	crash.KASANWrite,
	// High Priority (Memory Corruption)
	crash.KASANInvalidFree,
	crash.KASANUseAfterFreeRead,
	crash.KMSANUseAfterFreeRead,
	crash.KFENCE, // TODO: split crash.KFENCE
	crash.KASANRead,
	crash.MemorySafetyUBSAN, // array-index-out-of-bounds, at least Read.
	crash.KCSANAssert,
	crash.RefcountWARNING, // we had a few UAFs in the past
	// Medium Priority (Infoleaks, Uninitialized Memory, Corruptions)
	crash.KMSANInfoLeak,
	crash.MemorySafetyBUG,
	crash.KMSANUninitValue,
	// Medium Priority (Concurrency and Severe Instability)
	crash.KCSANDataRace,
	crash.AtomicSleep, // high potential for system-wide deadlocks
	crash.LockdepBug,  // indicates potential deadlocks and hangs
	// Lower-Medium Priority (Denial of Service and General Bugs)
	crash.MemoryLeak, // a form of DoS
	crash.DoS,
	crash.Hang,
	// Unknown types shouldn't be mentioned here. If bug goes to Unknown it means we need better parsing/processing.
	// You can find them at the end of the scored list on the bug enumeration pages.
	// crash.KMSANUnknown
	// crash.KASANUnknown
	// crash.KCSANUnknown
}

// TitleToImpact converts a bug title to an impact score.
// A higher score indicates a more severe impact.
// -1 means unknown.
func TitleToImpact(title string) int {
	typ := TitleToCrashType(title)
	for i, t := range impactOrder {
		if typ == t {
			return len(impactOrder) - i
		}
	}
	return -1
}
