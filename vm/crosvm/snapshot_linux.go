// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package crosvm

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
	"golang.org/x/sys/unix"
)

// snapshotAddr is the guest physical address the host/guest shared memory region is mapped at.
// crosvm allocates high MMIO for devices starting right after guest RAM (4 GB + PCIe VCFG),
// growing upwards, so a fixed address far above that will not collide in practice.
// crosvm reserves the range in its address allocator, so a collision fails the boot
// rather than silently corrupting memory.
const snapshotAddr = 1 << 36 // 64 GB

type snapshot struct {
	shmemFD  int
	shmem    []byte
	input    []byte
	header   *flatrpc.SnapshotHeaderT
	snapDir  string
	restored bool
}

func (inst *instance) snapshotClose() {
	if inst.shmem != nil {
		syscall.Munmap(inst.shmem)
		inst.shmem = nil
	}
	// > 0 rather than != 0: fd 0 is stdin, and closing that would be worse
	// than leaking a descriptor.
	if inst.shmemFD > 0 {
		syscall.Close(inst.shmemFD)
		inst.shmemFD = 0
	}
	if inst.snapDir != "" {
		os.RemoveAll(inst.snapDir)
		inst.snapDir = ""
	}
}

// snapshotEnable sets up the memory shared between the host and the guest and returns
// the crosvm arguments that map it into the guest.
//
// Unlike QEMU, crosvm has no ivshmem device, so we use a file-backed MMIO mapping instead:
// crosvm maps our memfd into the guest physical address space at a fixed address, and the
// executor finds it by mmap'ing /dev/mem at the same address (see executor/snapshot.h).
//
// The mapping is MMIO rather than RAM, which is what makes this work at all: crosvm
// snapshots only guest RAM (vm_control::do_snapshot serializes vm.get_memory()), so the
// shared region is not saved and not restored. That is the equivalent of QEMU's
// "migrate_set_capability x-ignore-shared on" and is what lets us write a new input into
// the region before each restore.
//
// The other ivshmem feature we lose is the doorbell interrupt, so both sides poll the
// state word in the header instead of being woken up.
func (inst *instance) snapshotEnable() ([]string, error) {
	shmemFD, err := unix.MemfdCreate("syz-crosvm-shmem", 0)
	if err != nil {
		return nil, fmt.Errorf("crosvm: memfd_create failed: %w", err)
	}
	inst.shmemFD = shmemFD
	if err := syscall.Ftruncate(shmemFD, int64(flatrpc.ConstSnapshotShmemSize)); err != nil {
		return nil, fmt.Errorf("crosvm: ftruncate failed: %w", err)
	}
	shmem, err := syscall.Mmap(shmemFD, 0, int(flatrpc.ConstSnapshotShmemSize),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("crosvm: shmem mmap failed: %w", err)
	}
	inst.shmem = shmem
	inst.input = shmem[:flatrpc.ConstMaxInputSize:flatrpc.ConstMaxInputSize]
	inst.header = (*flatrpc.SnapshotHeaderT)(unsafe.Pointer(&shmem[flatrpc.ConstMaxInputSize]))
	// crosvm opens the backing file by name, and every restored crosvm process opens it
	// again, so the fd must stay open in the manager for as long as the VM lives.
	shmemFile := fmt.Sprintf("/proc/%v/fd/%v", syscall.Getpid(), shmemFD)
	inst.snapDir = filepath.Join(inst.workdir, "snapshot")

	// The guest RAM top must stay below the shared region, otherwise crosvm cannot place it.
	if uint64(inst.cfg.Mem)<<20 >= snapshotAddr {
		return nil, fmt.Errorf("crosvm: mem %v MB is too large for snapshot mode", inst.cfg.Mem)
	}
	return []string{
		"--file-backed-mapping", fmt.Sprintf("addr=%v,size=%v,path=%v,rw",
			uint64(snapshotAddr), uint64(flatrpc.ConstSnapshotShmemSize), shmemFile),
	}, nil
}

const minErrOutputWait = time.Second

func (inst *instance) SetupSnapshot(input []byte) error {
	if inst.debug {
		log.Logf(0, "crosvm: starting snapshot handshake")
	}
	copy(inst.input, input)
	// Tell executor that we are ready to snapshot and wait for an ack.
	inst.header.UpdateState(flatrpc.SnapshotStateHandshake)
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateHandshake, 10*time.Minute) {
		return fmt.Errorf("executor does not start snapshot handshake\n%s", inst.readOutput(minErrOutputWait))
	}
	// crosvm refuses to write into an existing snapshot directory.
	os.RemoveAll(inst.snapDir)
	if _, err := inst.controlRetry(time.Minute*inst.timeouts.Scale, "snapshot", "take", inst.snapDir); err != nil {
		return fmt.Errorf("%w\n%s", err, inst.readOutput(minErrOutputWait))
	}
	if inst.debug {
		log.Logf(0, "crosvm: snapshot size %v MB", dirSize(inst.snapDir)>>20)
	}
	inst.header.UpdateState(flatrpc.SnapshotStateSnapshotted)
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateSnapshotted, time.Minute) {
		return fmt.Errorf("executor has not confirmed snapshot handshake\n%s", inst.readOutput(minErrOutputWait))
	}
	return nil
}

func (inst *instance) RunSnapshot(timeout time.Duration, input []byte) (result, output []byte, err error) {
	copy(inst.input, input)
	inst.header.OutputOffset = 0
	inst.header.OutputSize = 0
	inst.header.UpdateState(flatrpc.SnapshotStateExecute)
	if err := inst.restoreSnapshot(); err != nil {
		return nil, nil, fmt.Errorf("%w\n%s", err, inst.readOutput(minErrOutputWait))
	}
	inst.waitSnapshotStateChange(flatrpc.SnapshotStateExecute, timeout)
	resStart := int(flatrpc.ConstMaxInputSize) + int(atomic.LoadUint32(&inst.header.OutputOffset))
	resEnd := resStart + int(atomic.LoadUint32(&inst.header.OutputSize))
	var res []byte
	if resEnd <= len(inst.shmem) {
		res = inst.shmem[resStart:resEnd:resEnd]
	}
	output = inst.readOutput(0)
	return res, output, nil
}

// restoreSnapshot rewinds the VM to the state saved by SetupSnapshot.
//
// crosvm cannot restore a snapshot into a running VM: the control socket only implements
// "snapshot take", and restoring is a startup-only operation ("crosvm run --restore").
// So a restore means killing the VM and starting a new crosvm process from the snapshot.
// This is considerably more expensive than QEMU's loadvm, which restores in-process.
func (inst *instance) restoreSnapshot() error {
	if inst.crosvm != nil {
		inst.crosvm.Process.Kill()
		inst.crosvm.Wait()
		inst.crosvm = nil
	}
	// The killed process does not get to clean up after itself, and crosvm refuses to
	// start when its control socket already exists.
	os.Remove(inst.sock)
	// --suspended keeps the vCPUs stopped until we have the control socket, so that the
	// restored guest cannot run ahead of us and read a half-written input.
	// inst.args[0] is "run", which must stay first, and the kernel image must stay last.
	args := append([]string{"run", "--restore", inst.snapDir, "--suspended"}, inst.args[1:]...)
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return err
	}
	crosvm := osutil.Command(inst.cfg.Crosvm, args...)
	crosvm.Stdout = wpipe
	crosvm.Stderr = wpipe
	if err := crosvm.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return fmt.Errorf("failed to restore snapshot: %w", err)
	}
	wpipe.Close()
	inst.crosvm = crosvm
	// Re-registering the reader under the same name replaces the previous one, whose
	// goroutine has exited (or is about to) as the killed process closed the pipe.
	inst.merger.Add("crosvm", vmimpl.OutputConsole, rpipe)
	// "resume" both waits for the restore to complete and starts the vCPUs.
	if _, err := inst.controlRetry(time.Minute*inst.timeouts.Scale, "resume"); err != nil {
		return err
	}
	inst.restored = true
	return nil
}

func dirSize(dir string) int64 {
	var size int64
	filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, err := entry.Info(); err == nil {
			size += info.Size()
		}
		return nil
	})
	return size
}

func (inst *instance) waitSnapshotStateChange(state flatrpc.SnapshotState, timeout time.Duration) bool {
	// crosvm has no doorbell interrupt, so the guest cannot notify us of the state change
	// and we have to poll. Spin first (the common case is that the program finishes fast),
	// then back off so that a hung program does not burn a core.
	deadline := time.Now().Add(timeout)
	for i := 0; ; i++ {
		if inst.header.LoadState() != state {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		if i > 1000 {
			time.Sleep(time.Millisecond)
		}
	}
}

func (inst *instance) readOutput(minTotalWait time.Duration) []byte {
	var output []byte
	// If output channel has overflown, then wait for more output from the merger goroutine.
	wait := cap(inst.merger.Output)
	start := time.Now()
	for {
		select {
		case out := <-inst.merger.Output:
			output = append(output, out.Data...)
			wait--
		default:
			if wait > 0 {
				if time.Since(start) < minTotalWait {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				return output
			}
			// After the first overflow we wait after every read because the goroutine
			// may be running and sending more output to the channel concurrently.
			wait = 1
			time.Sleep(10 * time.Millisecond)
		}
	}
}
