package kcov

import "unsafe"

const (
	// sizeof(uintptr)
	sizeofUintPtr = 8
)

const (
	_IOC_NRBITS   = 8
	_IOC_TYPEBITS = 8
	_IOC_SIZEBITS = 14
	_IOC_DIRBITS  = 2

	_IOC_NRSHIFT   = 0
	_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
	_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
	_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS

	_IOC_NONE  = 0
	_IOC_WRITE = 1
	_IOC_READ  = 2
)

// KCOV ioctl commands for Linux.
const (
	// KCOV_INIT_TRACE initializes kcov tracing.
	// #define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
	// On amd64, unsigned long is 8 bytes.
	KCOV_INIT_TRACE uintptr = (_IOC_READ << _IOC_DIRSHIFT) | (uintptr(unsafe.Sizeof(uint64(0))) << _IOC_SIZESHIFT) | ('c' << _IOC_TYPESHIFT) | (1 << _IOC_NRSHIFT) // 0x80086301

	// KCOV_ENABLE enables kcov for the current thread.
	// #define KCOV_ENABLE _IO('c', 100)
	KCOV_ENABLE uintptr = (_IOC_NONE << _IOC_DIRSHIFT) | (0 << _IOC_SIZESHIFT) | ('c' << _IOC_TYPESHIFT) | (100 << _IOC_NRSHIFT) // 0x6364

	// KCOV_DISABLE disables kcov for the current thread.
	// #define KCOV_DISABLE _IO('c', 101)
	KCOV_DISABLE uintptr = (_IOC_NONE << _IOC_DIRSHIFT) | (0 << _IOC_SIZESHIFT) | ('c' << _IOC_TYPESHIFT) | (101 << _IOC_NRSHIFT) // 0x6365

	KCOV_TRACE_PC  = 0
	KCOV_TRACE_CMP = 1
)
