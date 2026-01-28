// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/flatrpc"
	"golang.org/x/sys/unix"
)

type snapshot struct {
	ivsListener *net.UnixListener
	ivsConn     *net.UnixConn
	doorbellFD  int
	eventFD     int
	shmemFD     int
	shmem       []byte
	input       []byte
	header      *flatrpc.SnapshotHeaderT
}

func (inst *instance) snapshotClose() {
	if inst.ivsListener != nil {
		inst.ivsListener.Close()
	}
	if inst.ivsConn != nil {
		inst.ivsConn.Close()
	}
	if inst.doorbellFD != 0 {
		syscall.Close(inst.doorbellFD)
	}
	if inst.eventFD != 0 {
		syscall.Close(inst.eventFD)
	}
	if inst.shmemFD != 0 {
		syscall.Close(inst.shmemFD)
	}
	if inst.shmem != nil {
		syscall.Munmap(inst.shmem)
	}
}

func (inst *instance) snapshotEnable() ([]string, error) {
	// We use ivshmem device (Inter-VM Shared Memory) for communication with the VM,
	// it allows to have a shared memory region directly accessible by both host and target:
	// https://www.qemu.org/docs/master/system/devices/ivshmem.html
	//
	// The shared memory region is not restored as part of snapshot restore since we set:
	//	migrate_set_capability x-ignore-shared on
	// This allows to write a new input into ivshmem before each restore.
	//
	// We also use doorbell (interrupt) capability of ivshmem to notify host about
	// program execution completion. Doorbell also allows to send interrupts in the other direction
	// (from host to target), but we don't need/use this since we arrange things such that
	// snapshot restore serves as a signal to execute new input.
	//
	// Ideally we use a single ivshmem device for both purposes (shmem+doorbell).
	// But unfortunately it seems that the doorbell device is always restored on snapshot restore
	// (at least I did not find a way to make it not restored, maybe can be solved with qemu change).
	// So we use 2 separate devices for these purposes.
	shmemFD, err := unix.MemfdCreate("syz-qemu-shmem", 0)
	if err != nil {
		return nil, fmt.Errorf("qemu: memfd_create failed: %w", err)
	}
	inst.shmemFD = shmemFD
	if err := syscall.Ftruncate(shmemFD, int64(flatrpc.ConstSnapshotShmemSize)); err != nil {
		return nil, fmt.Errorf("qemu: ftruncate failed: %w", err)
	}
	shmem, err := syscall.Mmap(shmemFD, 0, int(flatrpc.ConstSnapshotShmemSize),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("qemu: shmem mmap failed: %w", err)
	}
	inst.shmem = shmem
	inst.input = shmem[:flatrpc.ConstMaxInputSize:flatrpc.ConstMaxInputSize]
	inst.header = (*flatrpc.SnapshotHeaderT)(unsafe.Pointer(&shmem[flatrpc.ConstMaxInputSize]))
	shmemFile := fmt.Sprintf("/proc/%v/fd/%v", syscall.Getpid(), shmemFD)

	doorbellFD, err := unix.MemfdCreate("syz-qemu-doorbell", 0)
	if err != nil {
		return nil, fmt.Errorf("qemu: memfd_create failed: %w", err)
	}
	if err := syscall.Ftruncate(doorbellFD, int64(flatrpc.ConstSnapshotDoorbellSize)); err != nil {
		return nil, fmt.Errorf("qemu: ftruncate failed: %w", err)
	}
	inst.doorbellFD = doorbellFD

	eventFD, err := unix.Eventfd(0, unix.EFD_SEMAPHORE)
	if err != nil {
		return nil, fmt.Errorf("qemu: eventfd failed: %w", err)
	}
	inst.eventFD = eventFD

	sockPath := filepath.Join(inst.workdir, "ivs.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("qemu: unix listen on %v failed: %w", sockPath, err)
	}
	inst.ivsListener = ln

	return []string{
		// migratable=on is required to take snapshots.
		// tsc=off disables RDTSC timestamp counter, it's not virtualized/restored as part of snapshots,
		// so the target kernel sees a large jump in time and always declares TSC as unstable after restore.
		"-cpu", "host,migratable=on,tsc=off",
		"-chardev", fmt.Sprintf("socket,path=%v,id=snapshot-doorbell", sockPath),
		"-device", "ivshmem-doorbell,master=on,vectors=1,chardev=snapshot-doorbell",
		"-device", "ivshmem-plain,master=on,memdev=snapshot-shmem",
		"-object", fmt.Sprintf("memory-backend-file,size=%v,share=on,discard-data=on,id=snapshot-shmem,mem-path=%v",
			uint64(flatrpc.ConstSnapshotShmemSize), shmemFile),
	}, nil
}

func (inst *instance) snapshotHandshake() error {
	// ivshmem-doorbell expects an external server that communicates via a unix socket.
	// The protocol is not documented, for details see:
	// https://github.com/qemu/qemu/blob/master/hw/misc/ivshmem.c
	// https://github.com/qemu/qemu/blob/master/contrib/ivshmem-server/ivshmem-server.c
	conn, err := inst.ivsListener.AcceptUnix()
	if err != nil {
		return fmt.Errorf("qemu: unix accept failed: %w", err)
	}
	inst.ivsListener.Close()
	inst.ivsListener = nil
	inst.ivsConn = conn

	msg := make([]byte, 8)
	// Send protocol version 0.
	binary.LittleEndian.PutUint64(msg, 0)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("qemu: ivs conn write failed: %w", err)
	}
	// Send VM id 0.
	binary.LittleEndian.PutUint64(msg, 0)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("qemu: ivs conn write failed: %w", err)
	}
	// Send shared memory file FD.
	binary.LittleEndian.PutUint64(msg, ^uint64(0))
	rights := syscall.UnixRights(inst.doorbellFD)
	if _, _, err := conn.WriteMsgUnix(msg, rights, nil); err != nil {
		return fmt.Errorf("qemu: ivs conn sendmsg failed: %w", err)
	}
	// Send event FD for VM 1 interrupt vector 0.
	binary.LittleEndian.PutUint64(msg, 1)
	rights = syscall.UnixRights(inst.eventFD)
	if _, _, err := conn.WriteMsgUnix(msg, rights, nil); err != nil {
		return fmt.Errorf("qemu: ivs conn sendmsg failed: %w", err)
	}
	return nil
}

func (inst *instance) SetupSnapshot(input []byte) error {
	copy(inst.input, input)
	// Tell executor that we are ready to snapshot and wait for an ack.
	inst.header.UpdateState(flatrpc.SnapshotStateHandshake)
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateHandshake, 10*time.Minute) {
		return fmt.Errorf("executor does not start snapshot handshake\n%s", inst.readOutput())
	}
	if _, err := inst.hmp("migrate_set_capability x-ignore-shared on", 0); err != nil {
		return err
	}
	if _, err := inst.hmp("savevm syz", 0); err != nil {
		return err
	}
	if inst.debug {
		inst.hmp("info snapshots", 0) // this prints size of the snapshot
	}
	inst.header.UpdateState(flatrpc.SnapshotStateSnapshotted)
	if !inst.waitSnapshotStateChange(flatrpc.SnapshotStateSnapshotted, time.Minute) {
		return fmt.Errorf("executor has not confirmed snapshot handshake\n%s", inst.readOutput())
	}
	return nil
}

func (inst *instance) RunSnapshot(timeout time.Duration, input []byte) (result, output []byte, err error) {
	copy(inst.input, input)
	inst.header.OutputOffset = 0
	inst.header.OutputSize = 0
	inst.header.UpdateState(flatrpc.SnapshotStateExecute)
	if _, err := inst.hmp("loadvm syz", 0); err != nil {
		return nil, nil, fmt.Errorf("%w\n%s", err, inst.readOutput())
	}
	inst.waitSnapshotStateChange(flatrpc.SnapshotStateExecute, timeout)
	resStart := int(flatrpc.ConstMaxInputSize) + int(atomic.LoadUint32(&inst.header.OutputOffset))
	resEnd := resStart + int(atomic.LoadUint32(&inst.header.OutputSize))
	var res []byte
	if resEnd <= len(inst.shmem) {
		res = inst.shmem[resStart:resEnd:resEnd]
	}
	output = inst.readOutput()
	return res, output, nil
}

func (inst *instance) waitSnapshotStateChange(state flatrpc.SnapshotState, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	timeoutMs := int(timeout / time.Millisecond)
	fds := []unix.PollFd{{
		Fd:     int32(inst.eventFD),
		Events: unix.POLLIN,
	}}
	for {
		if n, _ := unix.Poll(fds, timeoutMs); n == 1 {
			var buf [8]byte
			syscall.Read(inst.eventFD, buf[:])
		}
		if inst.header.LoadState() != state {
			return true
		}
		remain := time.Until(deadline)
		if remain < time.Millisecond {
			return false
		}
		timeoutMs = int(remain / time.Millisecond)
	}
}

func (inst *instance) readOutput() []byte {
	var output []byte
	// If output channel has overflown, then wait for more output from the merger goroutine.
	wait := cap(inst.merger.Output)
	for {
		select {
		case out := <-inst.merger.Output:
			output = append(output, out.Data...)
			wait--
		default:
			if wait > 0 {
				return output
			}
			// After the first overflow we wait after every read because the goroutine
			// may be running and sending more output to the channel concurrently.
			wait = 1
			time.Sleep(10 * time.Millisecond)
		}
	}
}
