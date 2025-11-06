// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kcov

// This file defines values required for KCOV ioctl calls. More information on
// the values and their semantics can be found in the kernel documentation under
// Documentation/dev-tools/kcov.rst, or at docs.kernel.org/dev-tools/kcov.html.

import "unsafe"

const (
	sizeofUintPtr = int(unsafe.Sizeof((*int)(nil)))

	iocNrBits   = 8
	iocTypeBits = 8
	iocSizeBits = 14
	iocDirBits  = 2

	iocNrShift   = 0
	iocTypeshift = iocNrShift + iocNrBits
	iocSizeShift = iocTypeshift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits

	iocNone  = 0
	iocWrite = 1
	iocRead  = 2

	// kcovInitTrace initializes KCOV tracing.
	// #define kcovInitTrace _IOR('c', 1, unsigned long)
	kcovInitTrace uintptr = (iocRead << iocDirShift) |
		(unsafe.Sizeof(uint64(0)) << iocSizeShift) | ('c' << iocTypeshift) | (1 << iocNrShift) // 0x80086301.

	// kcovEnable enables kcov for the current thread.
	// #define kcovEnable _IO('c', 100)
	kcovEnable uintptr = (iocNone << iocDirShift) |
		(0 << iocSizeShift) | ('c' << iocTypeshift) | (100 << iocNrShift) // 0x6364.

	// kcovDisable disables kcov for the current thread.
	// #define kcovDisable _IO('c', 101)
	kcovDisable uintptr = (iocNone << iocDirShift) |
		(0 << iocSizeShift) | ('c' << iocTypeshift) | (101 << iocNrShift) // 0x6365.

	kcovTracePC  = 0
	kcovTraceCMP = 1
)
