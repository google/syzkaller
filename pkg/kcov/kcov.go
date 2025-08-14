// Package kcov provides Go native code for reading kernel coverage.
package kcov

import (
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const kcovPath string = "/sys/kernel/debug/kcov"

const (
	kcovCoverSize = 64 << 10
)

// Holds resources for a single traced thread.
type KCOVState struct {
	file  *os.File
	cover []byte
}

// Trace invokes `f` and returns its result, as well as collected kernel
// coverage during its invocation.
func (st *KCOVState) Trace(f func() error) ([]uintptr, error) {
	// First 8 bytes holds the number of collected PCs since last poll.
	countPtr := (*uint64)(unsafe.Pointer(&st.cover[0]))
	// Reset coverage for this run.
	atomic.StoreUint64(countPtr, 0)
	// Trigger call.
	err := f()
	// Load the number of PCs that were hit during trigger.
	n := atomic.LoadUint64(countPtr)
	if n == 0 {
		return nil, nil
	}

	pcDataPtr := (*uintptr)(unsafe.Pointer(&st.cover[sizeofUintPtr]))
	pcs := unsafe.Slice(pcDataPtr, n)
	pcsCopy := make([]uintptr, n)
	copy(pcsCopy, pcs)
	return pcsCopy, err
}

// EnableTracingForCurrentGoroutine prepares the current goroutine for kcov tracing.
// It must be paired with a call to DisableTracing.
func EnableTracingForCurrentGoroutine() (*KCOVState, error) {
	// KCOV is per-thread, so lock goroutine to its current OS thread.
	runtime.LockOSThread()

	file, err := os.OpenFile(kcovPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	cleanupOnError := func() {
		file.Close()
		runtime.UnlockOSThread()
	}

	fd := file.Fd()

	// Setup trace mode and size.
	if err := unix.IoctlSetInt(int(fd), uint(KCOV_INIT_TRACE), kcovCoverSize); err != nil {
		cleanupOnError()
		return nil, err
	}

	// Mmap buffer shared between kernel- and user-space.
	coverageBuffer, err := unix.Mmap(
		int(fd),
		0, // offset
		kcovCoverSize*sizeofUintPtr,
		unix.PROT_READ|unix.PROT_WRITE, // a read/write mapping
		unix.MAP_SHARED,                // changes are shared with the kernel
	)
	if err != nil {
		cleanupOnError()
		return nil, err
	}

	// Enable coverage collection on the current thread.
	if err := unix.IoctlSetInt(int(fd), uint(KCOV_ENABLE), KCOV_TRACE_PC); err != nil {
		cleanupOnError()
		unix.Munmap(coverageBuffer)
		return nil, err
	}

	return &KCOVState{
		file:  file,
		cover: coverageBuffer,
	}, nil
}

func (st *KCOVState) DisableTracing() {
	runtime.UnlockOSThread()
	st.file.Close()
}
