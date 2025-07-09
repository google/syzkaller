// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import "slices"

type Type string

const (
	UnknownType = Type("")
	// keep-sorted start
	AtomicSleep             = Type("ATOMIC_SLEEP")
	Bug                     = Type("BUG")
	DoS                     = Type("DoS")
	Hang                    = Type("HANG")
	KASANInvalidFree        = Type("KASAN-INVALID-FREE")
	KASANNullPtrDerefRead   = Type("KASAN-NULL-POINTER-DEREFERENCE-READ")
	KASANNullPtrDerefWrite  = Type("KASAN-NULL-POINTER-DEREFERENCE-WRITE")
	KASANRead               = Type("KASAN-READ")
	KASANUnknown            = Type("KASAN-UNKNOWN")
	KASANUseAfterFreeRead   = Type("KASAN-USE-AFTER-FREE-READ")
	KASANUseAfterFreeWrite  = Type("KASAN-USE-AFTER-FREE-WRITE")
	KASANWrite              = Type("KASAN-WRITE")
	KCSANAssert             = Type("KCSAN-ASSERT")
	KCSANDataRace           = Type("KCSAN-DATARACE")
	KCSANUnknown            = Type("KCSAN-UNKNOWN")
	KFENCEInvalidFree       = Type("KFENCE-INVALID-FREE")
	KFENCEMemoryCorruption  = Type("KFENCE-MEMORY-CORRUPTION")
	KFENCERead              = Type("KFENCE-READ")
	KFENCEUnknown           = Type("KFENCE-UNKNOWN")
	KFENCEUseAfterFreeRead  = Type("KFENCE-USE-AFTER-FREE-READ")
	KFENCEUseAfterFreeWrite = Type("KFENCE-USE-AFTER-FREE-WRITE")
	KFENCEWrite             = Type("KFENCE-WRITE")
	KMSANInfoLeak           = Type("KMSAN-INFO-LEAK")
	KMSANUninitValue        = Type("KMSAN-UNINIT-VALUE")
	KMSANUnknown            = Type("KMSAN-UNKNOWN")
	KMSANUseAfterFreeRead   = Type("KMSAN-USE-AFTER-FREE-READ")
	LockdepBug              = Type("LOCKDEP")
	MemoryLeak              = Type("LEAK")
	MemorySafetyBUG         = Type("MEMORY_SAFETY_BUG")
	MemorySafetyUBSAN       = Type("MEMORY_SAFETY_UBSAN")
	NullPtrDerefBUG         = Type("NULL-POINTER-DEREFERENCE")
	RefcountWARNING         = Type("REFCOUNT_WARNING")
	UBSAN                   = Type("UBSAN")
	Warning                 = Type("WARNING")
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
		KASANNullPtrDerefRead, KASANNullPtrDerefWrite, KASANRead, KASANWrite,
		KASANUseAfterFreeRead, KASANUseAfterFreeWrite, KASANInvalidFree, KASANUnknown}, t)
}

func (t Type) IsKMSAN() bool {
	return slices.Contains([]Type{
		KMSANUninitValue, KMSANInfoLeak, KMSANUseAfterFreeRead, KMSANUnknown}, t)
}

func (t Type) IsKCSAN() bool {
	return t == KCSANDataRace || t == KCSANAssert || t == KCSANUnknown
}

func (t Type) IsUBSAN() bool {
	return t == UBSAN || t == MemorySafetyUBSAN
}

func (t Type) IsBUG() bool {
	return slices.Contains([]Type{Bug, MemorySafetyBUG, NullPtrDerefBUG}, t)
}

func (t Type) IsWarning() bool {
	return t == Warning || t == RefcountWARNING
}

func (t Type) IsBugOrWarning() bool {
	return t.IsBUG() || t.IsWarning()
}

func (t Type) IsMemSafety() bool {
	return t == MemorySafetyBUG || t == RefcountWARNING || t == MemorySafetyUBSAN
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
