// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

type Type string

const (
	UnknownType      = Type("")
	Hang             = Type("HANG")
	MemoryLeak       = Type("LEAK")
	DataRace         = Type("DATARACE")
	UnexpectedReboot = Type("REBOOT")
	UBSAN            = Type("UBSAN")
	Bug              = Type("BUG")
	Warning          = Type("WARNING")
	KASAN            = Type("KASAN")
	LockdepBug       = Type("LOCKDEP")
	AtomicSleep      = Type("ATOMIC_SLEEP")
	KMSAN            = Type("KMSAN")
	SyzFailure       = Type("SYZ_FAILURE")
)

func (t Type) String() string {
	if t == UnknownType {
		return "UNKNOWN"
	}
	return string(t)
}
