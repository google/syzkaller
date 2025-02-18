// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <utility>

#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif

// Size of qemu snapshots and time required to restore a snapshot depend on the amount of memory
// the VM touches after boot. For example, a 132 MB snapshot takes around 150ms to restore,
// while a 260 MB snapshot takes around 275 ms to restore.
//
// To reduce size of the snapshot it's recommended to use smaller kernel and setup fewer devices.
// For example the following cmdline arguments:
// "loop.max_loop=1 dummy_hcd.num=1 vivid.n_devs=2 vivid.multiplanar=1,2 netrom.nr_ndevs=1 rose.rose_ndevs=1"
// and CONFIG_USBIP_VHCI_NR_HCS=1 help to reduce snapshot by about 20 MB. Note: we have only 1 proc
// in snapshot mode, so we don't need lots of devices. However, our descriptions rely on vivid.n_devs=16
// since they hardcode names like /dev/video36 which follow after these 16 pre-created devices.
//
// Additionally we could try to use executor as init process, this should remove dhcpd/sshd/udevd/klogd/etc.
// We don't need even networking in snapshot mode since we communicate via shared memory.

static struct {
	// Ivshmem interrupt doorbell register.
	volatile uint32* doorbell;
	volatile rpc::SnapshotHeaderT* hdr;
	void* input;
} ivs;

// Finds qemu ivshmem device, see:
// https://www.qemu.org/docs/master/specs/ivshmem-spec.html
static void FindIvshmemDevices()
{
	std::string result;
	DIR* devices = opendir("/sys/bus/pci/devices");
	if (!devices)
		fail("opendir(/sys/bus/pci/devices) failed");
	void* regs = nullptr;
	void* input = nullptr;
	void* output = nullptr;
	while (auto* dev = readdir(devices)) {
		if (dev->d_name[0] == '.')
			continue;
		const std::string& vendor = ReadTextFile("/sys/bus/pci/devices/%s/vendor", dev->d_name);
		const std::string& device = ReadTextFile("/sys/bus/pci/devices/%s/device", dev->d_name);
		debug("PCI device %s: vendor=%s device=%s\n", dev->d_name, vendor.c_str(), device.c_str());
		if (vendor != "0x1af4" || device != "0x1110")
			continue;
		char filename[1024];
		snprintf(filename, sizeof(filename), "/sys/bus/pci/devices/%s/resource2", dev->d_name);
		int res2 = open(filename, O_RDWR);
		if (res2 == -1)
			fail("failed to open ivshmem resource2");
		struct stat statbuf;
		if (fstat(res2, &statbuf))
			fail("failed to fstat ivshmem resource2");
		debug("ivshmem resource2 size %zu\n", static_cast<size_t>(statbuf.st_size));
		// The only way to distinguish the 2 ivshmem regions is by size.
		if (statbuf.st_size == static_cast<uint64>(rpc::Const::SnapshotDoorbellSize)) {
			snprintf(filename, sizeof(filename), "/sys/bus/pci/devices/%s/resource0", dev->d_name);
			int res0 = open(filename, O_RDWR);
			if (res0 == -1)
				fail("failed to open ivshmem resource0");
			regs = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, res0, 0);
			close(res0);
			if (regs == MAP_FAILED)
				fail("failed to mmap ivshmem resource0");
			debug("mapped doorbell registers at %p\n", regs);
		} else if (statbuf.st_size == static_cast<uint64>(rpc::Const::SnapshotShmemSize)) {
			input = mmap(nullptr, static_cast<uint64>(rpc::Const::MaxInputSize),
				     PROT_READ, MAP_SHARED, res2, 0);
			output = mmap(nullptr, static_cast<uint64>(rpc::Const::MaxOutputSize),
				      PROT_READ | PROT_WRITE, MAP_SHARED, res2,
				      static_cast<uint64>(rpc::Const::MaxInputSize));
			if (input == MAP_FAILED || output == MAP_FAILED)
				fail("failed to mmap ivshmem resource2");
			debug("mapped shmem input at at %p/%llu\n",
			      input, static_cast<uint64>(rpc::Const::MaxInputSize));
			debug("mapped shmem output at at %p/%llu\n",
			      output, static_cast<uint64>(rpc::Const::MaxOutputSize));
#if GOOS_linux
			if (pkeys_enabled && pkey_mprotect(output, static_cast<uint64>(rpc::Const::MaxOutputSize),
							   PROT_READ | PROT_WRITE, RESERVED_PKEY))
				exitf("failed to pkey_mprotect output buffer");
#endif
		}
		close(res2);
	}
	closedir(devices);
	if (regs == nullptr || input == nullptr)
		fail("cannot find ivshmem PCI devices");
	ivs.doorbell = static_cast<uint32*>(regs) + 3;
	ivs.hdr = static_cast<rpc::SnapshotHeaderT*>(output);
	ivs.input = input;
	output_data = reinterpret_cast<OutputData*>(static_cast<char*>(output) + sizeof(rpc::SnapshotHeaderT));
	output_size = static_cast<uint64>(rpc::Const::MaxOutputSize) - sizeof(rpc::SnapshotHeaderT);
}

static void SnapshotSetup(char** argv, int argc)
{
	flag_snapshot = true;
	// This allows to see debug output during early setup.
	// If debug is not actually enabled, it will be turned off in parse_handshake.
	flag_debug = true;
#if GOOS_linux
	// In snapshot mode executor output is redirected to /dev/kmsg.
	// This is required to turn off rate limiting of writes.
	write_file("/proc/sys/kernel/printk_devkmsg", "on\n");
#endif
	FindIvshmemDevices();
	// Wait for the host to write handshake_req into input memory.
	while (ivs.hdr->state != rpc::SnapshotState::Handshake)
		sleep_ms(10);
	auto msg = flatbuffers::GetRoot<rpc::SnapshotHandshake>(ivs.input);
	handshake_req req = {
	    .magic = kInMagic,
	    .use_cover_edges = msg->cover_edges(),
	    .is_kernel_64_bit = msg->kernel_64_bit(),
	    .flags = msg->env_flags(),
	    .pid = 0,
	    .sandbox_arg = static_cast<uint64>(msg->sandbox_arg()),
	    .syscall_timeout_ms = static_cast<uint64>(msg->syscall_timeout_ms()),
	    .program_timeout_ms = static_cast<uint64>(msg->program_timeout_ms()),
	    .slowdown_scale = static_cast<uint64>(msg->slowdown()),
	};
	parse_handshake(req);
#if SYZ_HAVE_FEATURES
	setup_sysctl();
	setup_cgroups();
#endif
#if SYZ_HAVE_SETUP_EXT
	// This can be defined in common_ext.h.
	setup_ext();
#endif
	for (const auto& feat : features) {
		if (!(msg->features() & feat.id))
			continue;
		debug("setting up feature %s\n", rpc::EnumNameFeature(feat.id));
		const char* reason = feat.setup();
		if (reason)
			failmsg("feature setup failed", "reason: %s", reason);
	}
}

constexpr size_t kOutputPopulate = 256 << 10;
constexpr size_t kInputPopulate = 64 << 10;
constexpr size_t kGlobalsPopulate = 4 << 10;
constexpr size_t kDataPopulate = 8 << 10;
constexpr size_t kCoveragePopulate = 64 << 10;
constexpr size_t kThreadsPopulate = 2;

static void SnapshotSetState(rpc::SnapshotState state)
{
	debug("changing stapshot state %s -> %s\n",
	      rpc::EnumNameSnapshotState(ivs.hdr->state), rpc::EnumNameSnapshotState(state));
	std::atomic_signal_fence(std::memory_order_seq_cst);
	ivs.hdr->state = state;
	// The register contains VM index shifted by 16 (the host part is VM index 1)
	// + interrup vector index (0 in our case).
	*ivs.doorbell = 1 << 16;
}

// PopulateMemory prefaults anon memory (we want to avoid minor page faults as well).
static void PopulateMemory(void* ptr, size_t size)
{
	ptr = (void*)(uintptr_t(ptr) & ~(getpagesize() - 1));
	if (madvise(ptr, size, MADV_POPULATE_WRITE))
		failmsg("populate madvise failed", "ptr=%p size=%zu", ptr, size);
}

// TouchMemory prefaults non-anon shared memory.
static void TouchMemory(void* ptr, size_t size)
{
	size_t const kPageSize = getpagesize();
	for (size_t i = 0; i < size; i += kPageSize)
		(void)((volatile char*)ptr)[i];
}

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void SnapshotPrepareParent()
{
	// This allows access to the output region.
	CoverAccessScope scope(nullptr);
	TouchMemory((char*)output_data + output_size - kOutputPopulate, kOutputPopulate);
	// Notify SnapshotStart that we finished prefaulting memory in the parent.
	output_data->completed = 1;
	// Wait for the request to come, so that we give it full time slice to execute.
	// This process will start waiting for the child as soon as we return.
	while (ivs.hdr->state != rpc::SnapshotState::Execute)
		;
}
#endif

static void SnapshotStart()
{
	debug("SnapshotStart\n");
	CoverAccessScope scope(nullptr);
	// Prefault as much memory as we can before the snapshot is taken.
	// Also pre-create some threads and let them block.
	// This is intended to make execution after each snapshot restore faster,
	// as we won't need to do that duplicate work again and again.
	flag_threaded = true;
	for (size_t i = 0; i < kThreadsPopulate; i++) {
		thread_t* th = &threads[i];
		thread_create(th, i, flag_coverage);
		if (flag_coverage)
			PopulateMemory(th->cov.alloc, kCoveragePopulate);
	}
	TouchMemory((char*)output_data + output_size - kOutputPopulate, kOutputPopulate);
	TouchMemory(ivs.input, kInputPopulate);
	PopulateMemory(&flag_coverage, kGlobalsPopulate);
	PopulateMemory((void*)SYZ_DATA_OFFSET, kDataPopulate);
	sleep_ms(100); // let threads start and block
	// Wait for the parent process to prefault as well.
	while (!output_data->completed)
		sleep_ms(1);
	// Notify host that we are ready to be snapshotted.
	SnapshotSetState(rpc::SnapshotState::Ready);
	// Snapshot is restored here.
	// First time we may loop here while the snapshot is taken,
	// but afterwards we should be restored when the state is already Execute.
	// Note: we don't use sleep in the loop because we may be snapshotted while in the sleep syscall.
	// As the result each execution after snapshot restore will be slower as it will need to finish
	// the sleep and return from the syscall.
	while (ivs.hdr->state == rpc::SnapshotState::Ready)
		;
	if (ivs.hdr->state == rpc::SnapshotState::Snapshotted) {
		// First time around, just acknowledge and wait for snapshot restart.
		SnapshotSetState(rpc::SnapshotState::Executed);
		for (;;)
			sleep(1000);
	}
	// Resumed for program execution.
	output_data->Reset();
	auto msg = flatbuffers::GetRoot<rpc::SnapshotRequest>(ivs.input);
	execute_req req = {
	    .magic = kInMagic,
	    .id = 0,
	    .type = rpc::RequestType::Program,
	    .exec_flags = static_cast<uint64>(msg->exec_flags()),
	    .all_call_signal = msg->all_call_signal(),
	    .all_extra_signal = msg->all_extra_signal(),
	};
	parse_execute(req);
	output_data->num_calls.store(msg->num_calls(), std::memory_order_relaxed);
	input_data = const_cast<uint8*>(msg->prog_data()->Data());
}

NORETURN static void SnapshotDone(bool failed)
{
	debug("SnapshotDone\n");
	CoverAccessScope scope(nullptr);
	uint32 num_calls = output_data->num_calls.load(std::memory_order_relaxed);
	auto data = finish_output(output_data, 0, 0, num_calls, 0, 0, failed ? kFailStatus : 0, false, nullptr);
	ivs.hdr->output_offset = data.data() - reinterpret_cast<volatile uint8_t*>(ivs.hdr);
	ivs.hdr->output_size = data.size();
	SnapshotSetState(failed ? rpc::SnapshotState::Failed : rpc::SnapshotState::Executed);
	// Wait to be restarted from the snapshot.
	for (;;)
		sleep(1000);
}
