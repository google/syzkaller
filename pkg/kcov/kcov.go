// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

// Package kcov provides Go native code for collecting kernel coverage (KCOV)
// information.
package kcov

import (
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	kcovPath = "/sys/kernel/debug/kcov"
	// This is the same value used by the linux executor, see executor_linux.h.
	kcovCoverSize = 512 << 10
)

// Holds resources for a single traced thread.
type KCOVState struct {
	file  *os.File
	cover []byte
}

type KCOVTraceResult struct {
	Result   error     // Result of the call.
	Coverage []uintptr // Collected program counters.
}

// Trace invokes `f` and returns a KCOVTraceResult.
func (st *KCOVState) Trace(f func() error) KCOVTraceResult {
	// First 8 bytes holds the number of collected PCs since last poll.
	countPtr := (*uintptr)(unsafe.Pointer(&st.cover[0]))
	// Reset coverage for this run.
	atomic.StoreUintptr(countPtr, 0)
	// Trigger call.
	err := f()
	// Load the number of PCs that were hit during trigger.
	n := atomic.LoadUintptr(countPtr)

	pcDataPtr := (*uintptr)(unsafe.Pointer(&st.cover[sizeofUintPtr]))
	pcs := unsafe.Slice(pcDataPtr, n)
	pcsCopy := make([]uintptr, n)
	copy(pcsCopy, pcs)
	return KCOVTraceResult{Result: err, Coverage: pcsCopy}
}

// EnableTracingForCurrentGoroutine prepares the current goroutine for kcov tracing.
// It must be paired with a call to DisableTracing.
func EnableTracingForCurrentGoroutine() (st *KCOVState, err error) {
	st = &KCOVState{}
	defer func() {
		if err != nil {
			// The original error is more important, so we ignore any potential
			// errors that result from cleaning up.
			_ = st.DisableTracing()
		}
	}()

	// KCOV is per-thread, so lock goroutine to its current OS thread.
	runtime.LockOSThread()

	file, err := os.OpenFile(kcovPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	st.file = file

	// Setup trace mode and size.
	if err := unix.IoctlSetInt(int(st.file.Fd()), uint(kcovInitTrace), kcovCoverSize); err != nil {
		return nil, err
	}

	// Mmap buffer shared between kernel- and user-space. For more information,
	// see the Linux KCOV documentation: https://docs.kernel.org/dev-tools/kcov.html.
	st.cover, err = unix.Mmap(
		int(st.file.Fd()),
		0, // Offset.
		kcovCoverSize*sizeofUintPtr,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		return nil, err
	}

	// Enable coverage collection on the current thread.
	if err := unix.IoctlSetInt(int(st.file.Fd()), uint(kcovEnable), kcovTracePC); err != nil {
		return nil, err
	}
	return st, nil
}

// DisableTracing disables KCOV tracing for the current Go routine. On failure,
// it returns the first error that occurred during cleanup.
func (st *KCOVState) DisableTracing() error {
	var firstErr error
	if err := unix.IoctlSetInt(int(st.file.Fd()), uint(kcovDisable), kcovTracePC); err != nil {
		firstErr = err
	}
	if err := unix.Munmap(st.cover); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := st.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	runtime.UnlockOSThread()
	return firstErr
}
