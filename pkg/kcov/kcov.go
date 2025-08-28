// Package kcov provides Go native code for reading kernel coverage.
package kcov

import (
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	kcovPath      = "/sys/kernel/debug/kcov"
	kcovCoverSize = 64 << 10
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
func EnableTracingForCurrentGoroutine() (*KCOVState, error) {
	// KCOV is per-thread, so lock goroutine to its current OS thread.
	runtime.LockOSThread()

	file, err := os.OpenFile(kcovPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	st := KCOVState{
		file: file,
	}
	fd := file.Fd()

	// Setup trace mode and size.
	if err := unix.IoctlSetInt(int(fd), uint(KCOV_INIT_TRACE), kcovCoverSize); err != nil {
		st.DisableTracing()
		return nil, err
	}

	// Mmap buffer shared between kernel- and user-space. For more information,
	// see the Linux KCOV documentation: https://docs.kernel.org/dev-tools/kcov.html.
	st.cover, err = unix.Mmap(
		int(fd),
		0, // Offset.
		kcovCoverSize*sizeofUintPtr,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		st.DisableTracing()
		return nil, err
	}

	// Enable coverage collection on the current thread.
	if err := unix.IoctlSetInt(int(fd), uint(KCOV_ENABLE), KCOV_TRACE_PC); err != nil {
		st.DisableTracing()
		return nil, err
	}

	return &st, nil
}

func (st *KCOVState) DisableTracing() {
	runtime.UnlockOSThread()
	st.file.Close()
	unix.Munmap(st.cover)
}
