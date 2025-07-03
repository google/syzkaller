// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import "slices"

type Type string

const (
	UnknownType = Type("")
	// keep-sorted start
	AtomicSleep            = Type("ATOMIC_SLEEP")
	Bug                    = Type("BUG")
	DoS                    = Type("DoS")
	Hang                   = Type("HANG")
	KASANInvalidFree       = Type("KASAN-INVALID-FREE")
	KASANOther             = Type("KASAN-OTHER")
	KASANRead              = Type("KASAN-READ")
	KASANUseAfterFreeRead  = Type("KASAN-USE-AFTER-FREE-READ")
	KASANUseAfterFreeWrite = Type("KASAN-USE-AFTER-FREE-WRITE")
	KASANWrite             = Type("KASAN-WRITE")
	KCSAN                  = Type("KCSAN")
	KCSANDataRace          = Type("DATARACE")
	KFENCE                 = Type("KFENCE")
	KMSANInfoLeak          = Type("KMSAN-INFO-LEAK")
	KMSANUninitValue       = Type("KMSAN-UNINIT-VALUE")
	KMSANUnknown           = Type("KMSAN-UNKNOWN")
	KMSANUseAfterFreeRead  = Type("KMSAN-USE-AFTER-FREE-READ")
	LockdepBug             = Type("LOCKDEP")
	MemoryLeak             = Type("LEAK")
	MemorySafetyBUG        = Type("MEMORY_SAFETY_BUG")
	MemorySafetyUBSAN      = Type("MEMORY_SAFETY_UBSAN")
	MemorySafetyWARNING    = Type("MEMORY_SAFETY_WARNING")
	UBSAN                  = Type("UBSAN")
	Warning                = Type("WARNING")
	// keep-sorted end
	LostConnection   = Type("LOST_CONNECTION")
	SyzFailure       = Type("SYZ_FAILURE")
	UnexpectedReboot = Type("REBOOT")
)

func (t Type) String() string {
	if t == UnknownType {
		return "UNKNOWN"
	}
	return string(t)
}

type TypeGroupPred func(Type) bool

func (t Type) IsKASAN() bool {
	return slices.Contains([]Type{
		KASANRead, KASANWrite, KASANUseAfterFreeRead, KASANUseAfterFreeWrite, KASANInvalidFree, KASANOther}, t)
}

func (t Type) IsKMSAN() bool {
	return slices.Contains([]Type{
		KMSANUninitValue, KMSANInfoLeak, KMSANUseAfterFreeRead, KMSANUnknown}, t)
}

func (t Type) IsKCSAN() bool {
	return t == KCSANDataRace || t == KCSAN
}

func (t Type) IsUBSAN() bool {
	return t == UBSAN || t == MemorySafetyUBSAN
}

func (t Type) IsBUG() bool {
	return t == Bug || t == MemorySafetyBUG
}

func (t Type) IsWarning() bool {
	return t == Warning || t == MemorySafetyWARNING
}

func (t Type) IsBugOrWarning() bool {
	return t.IsBUG() || t.IsWarning()
}

func (t Type) IsMemSafety() bool {
	return t == MemorySafetyBUG || t == MemorySafetyWARNING || t == MemorySafetyUBSAN
}

func (t Type) IsMemoryLeak() bool {
	return t == MemoryLeak
}

func (t Type) IsLockingBug() bool {
	return t.IsLockdep() || t.IsAtomicSleep()
}

func (t Type) IsDoS() bool {
	return t == Bug || t == DoS
}

func (t Type) IsHang() bool {
	return t == Hang
}

func (t Type) IsLockdep() bool {
	return t == LockdepBug
}

func (t Type) IsAtomicSleep() bool {
	return t == AtomicSleep
}
