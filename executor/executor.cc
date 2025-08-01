// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <algorithm>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <optional>

#if !GOOS_windows
#include <unistd.h>
#endif

#include "defs.h"

#include "pkg/flatrpc/flatrpc.h"

#if defined(__GNUC__)
#define SYSCALLAPI
#define NORETURN __attribute__((noreturn))
#define PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
// Assuming windows/cl.
#define SYSCALLAPI WINAPI
#define NORETURN __declspec(noreturn)
#define PRINTF(fmt, args)
#define __thread __declspec(thread)
#endif

#ifndef GIT_REVISION
#define GIT_REVISION "unknown"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
constexpr bool kAddressSanitizer = true;
#else
constexpr bool kAddressSanitizer = false;
#endif

// uint64 is impossible to printf without using the clumsy and verbose "%" PRId64.
// So we define and use uint64. Note: pkg/csource does s/uint64/uint64/.
// Also define uint32/16/8 for consistency.
typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

// Note: zircon max fd is 256.
// Some common_OS.h files know about this constant for RLIMIT_NOFILE.
const int kMaxFd = 250;
const int kFdLimit = 256;
const int kMaxThreads = 32;
const int kInPipeFd = kMaxFd - 1; // remapped from stdin
const int kOutPipeFd = kMaxFd - 2; // remapped from stdout
const int kCoverFd = kOutPipeFd - kMaxThreads;
const int kExtraCoverFd = kCoverFd - 1;
const int kMaxArgs = 9;
const int kCoverSize = 512 << 10;
const int kFailStatus = 67;

// Two approaches of dealing with kcov memory.
const int kCoverOptimizedCount = 8; // the max number of kcov instances
const int kCoverOptimizedPreMmap = 3; // this many will be mmapped inside main(), others - when needed.
const int kCoverDefaultCount = 6; // the max number of kcov instances when delayed kcov mmap is not available

// Logical error (e.g. invalid input program), use as an assert() alternative.
// If such error happens 10+ times in a row, it will be detected as a bug by the runner process.
// The runner will fail and syz-manager will create a bug for this.
// Note: err is used for bug deduplication, thus distinction between err (constant message)
// and msg (varying part).
static NORETURN void fail(const char* err);
static NORETURN PRINTF(2, 3) void failmsg(const char* err, const char* msg, ...);
// Just exit (e.g. due to temporal ENOMEM error).
static NORETURN PRINTF(1, 2) void exitf(const char* msg, ...);
static NORETURN void doexit(int status);
#if !GOOS_fuchsia
static NORETURN void doexit_thread(int status);
#endif

// Print debug output that is visible when running syz-manager/execprog with -debug flag.
// Debug output is supposed to be relatively high-level (syscalls executed, return values, timing, etc)
// and is intended mostly for end users. If you need to debug lower-level details, use debug_verbose
// function and temporary enable it in your build by changing #if 0 below.
// This function does not add \n at the end of msg as opposed to the previous functions.
static PRINTF(1, 2) void debug(const char* msg, ...);
void debug_dump_data(const char* data, int length);

#if 0
#define debug_verbose(...) debug(__VA_ARGS__)
#else
#define debug_verbose(...) (void)0
#endif

static void receive_execute();
static void reply_execute(uint32 status);
static void receive_handshake();

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void SnapshotPrepareParent();

// Allocating (and forking) virtual memory for each executed process is expensive, so we only mmap
// the amount we might possibly need for the specific received prog.
const int kMaxOutputComparisons = 14 << 20; // executions with comparsions enabled are usually < 1% of all executions
const int kMaxOutputCoverage = 6 << 20; // coverage is needed in ~ up to 1/3 of all executions (depending on corpus rotation)
const int kMaxOutputSignal = 4 << 20;
const int kMinOutput = 256 << 10; // if we don't need to send signal, the output is rather short.
const int kInitialOutput = kMinOutput; // the minimal size to be allocated in the parent process
const int kMaxOutput = kMaxOutputComparisons;
#else
// We don't fork and allocate the memory only once, so prepare for the worst case.
const int kInitialOutput = 14 << 20;
const int kMaxOutput = kInitialOutput;
#endif

// For use with flatrpc bit flags.
template <typename T>
bool IsSet(T flags, T f)
{
	return (flags & f) != T::NONE;
}

// TODO: allocate a smaller amount of memory in the parent once we merge the patches that enable
// prog execution with neither signal nor coverage. Likely 64kb will be enough in that case.

const uint32 kMaxCalls = 64;

struct alignas(8) OutputData {
	std::atomic<uint32> size;
	std::atomic<uint32> consumed;
	std::atomic<uint32> completed;
	std::atomic<uint32> num_calls;
	std::atomic<flatbuffers::Offset<flatbuffers::Vector<uint8_t>>> result_offset;
	struct {
		// Call index in the test program (they may be out-of-order is some syscalls block).
		int index;
		// Offset of the CallInfo object in the output region.
		flatbuffers::Offset<rpc::CallInfoRaw> offset;
	} calls[kMaxCalls];

	void Reset()
	{
		size.store(0, std::memory_order_relaxed);
		consumed.store(0, std::memory_order_relaxed);
		completed.store(0, std::memory_order_relaxed);
		num_calls.store(0, std::memory_order_relaxed);
		result_offset.store(0, std::memory_order_relaxed);
	}
};

// ShmemAllocator/ShmemBuilder help to construct flatbuffers ExecResult reply message in shared memory.
//
// To avoid copying the reply (in particular coverage/signal/comparisons which may be large), the child
// process starts forming CallInfo objects as it handles completion of syscalls, then the top-most runner
// process uses these CallInfo to form an array of them, and adds ProgInfo object with a reference to the array.
// In order to make this possible, OutputData object is placed at the beginning of the shared memory region,
// and it records metadata required to start serialization in one process and continue later in another process.
//
// OutputData::size is the size of the whole shmem region that the child uses (it different size when coverage/
// comparisons are requested). Note that flatbuffers serialization happens from the end of the buffer backwards.
// OutputData::consumed records currently consumed amount memory in the shmem region so that the parent process
// can continue from that point.
// OutputData::completed records number of completed calls (entries in OutputData::calls arrays).
// Flatbuffers identifies everything using offsets in the buffer, OutputData::calls::offset records this offset
// for the call object so that we can use it in the parent process to construct the array of calls.
//
// FlatBufferBuilder generally grows the underlying buffer incrementally as necessary and copying data
// (std::vector style). We cannot do this in the shared memory since we have only a single region.
// To allow serialization into the shared memory region, ShmemBuilder passes initial buffer size which is equal
// to the overall shmem region size (minus OutputData header size) to FlatBufferBuilder, and the custom
// ShmemAllocator allocator. As the result, FlatBufferBuilder does exactly one allocation request
// to ShmemAllocator and never reallocates (if we overflow the buffer and FlatBufferBuilder does another request,
// ShmemAllocator will fail).
class ShmemAllocator : public flatbuffers::Allocator
{
public:
	ShmemAllocator(void* buf, size_t size)
	    : buf_(buf),
	      size_(size)
	{
	}

private:
	void* buf_;
	size_t size_;
	bool allocated_ = false;

	uint8_t* allocate(size_t size) override
	{
		if (allocated_ || size != size_)
			failmsg("bad allocate request", "allocated=%d size=%zu/%zu", allocated_, size_, size);
		allocated_ = true;
		return static_cast<uint8_t*>(buf_);
	}

	void deallocate(uint8_t* p, size_t size) override
	{
		if (!allocated_ || buf_ != p || size_ != size)
			failmsg("bad deallocate request", "allocated=%d buf=%p/%p size=%zu/%zu",
				allocated_, buf_, p, size_, size);
		allocated_ = false;
	}

	uint8_t* reallocate_downward(uint8_t* old_p, size_t old_size,
				     size_t new_size, size_t in_use_back,
				     size_t in_use_front) override
	{
		fail("can't reallocate");
	}
};

class ShmemBuilder : ShmemAllocator, public flatbuffers::FlatBufferBuilder
{
public:
	ShmemBuilder(OutputData* data, size_t size, bool store_size)
	    : ShmemAllocator(data + 1, size - sizeof(*data)),
	      FlatBufferBuilder(size - sizeof(*data), this)
	{
		if (store_size)
			data->size.store(size, std::memory_order_relaxed);
		size_t consumed = data->consumed.load(std::memory_order_relaxed);
		if (consumed >= size - sizeof(*data))
			failmsg("ShmemBuilder: too large output offset", "size=%zd consumed=%zd", size, consumed);
		if (consumed)
			FlatBufferBuilder::buf_.make_space(consumed);
	}
};

const int kInFd = 3;
const int kOutFd = 4;
const int kMaxSignalFd = 5;
const int kCoverFilterFd = 6;
static OutputData* output_data;
static std::optional<ShmemBuilder> output_builder;
static uint32 output_size;
static void mmap_output(uint32 size);
static uint32 hash(uint32 a);
static bool dedup(uint8 index, uint64 sig);

static uint64 start_time_ms = 0;
static bool flag_debug;
static bool flag_snapshot;
static bool flag_coverage;
static bool flag_read_only_coverage;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_sandbox_namespace;
static bool flag_sandbox_android;
static bool flag_extra_coverage;
static bool flag_net_injection;
static bool flag_net_devices;
static bool flag_net_reset;
static bool flag_cgroups;
static bool flag_close_fds;
static bool flag_devlink_pci;
static bool flag_nic_vf;
static bool flag_vhci_injection;
static bool flag_wifi;
static bool flag_delay_kcov_mmap;

static bool flag_collect_cover;
static bool flag_collect_signal;
static bool flag_dedup_cover;
static bool flag_threaded;

// If true, then executor should write the comparisons data to fuzzer.
static bool flag_comparisons;

static uint64 request_id;
static rpc::RequestType request_type;
static uint64 all_call_signal;
static bool all_extra_signal;

// Tunable timeouts, received with execute_req.
static uint64 syscall_timeout_ms;
static uint64 program_timeout_ms;
static uint64 slowdown_scale;

// Can be used to disginguish whether we're at the initialization stage
// or we already execute programs.
static bool in_execute_one = false;

#define SYZ_EXECUTOR 1
#include "common.h"

const size_t kMaxInput = 4 << 20; // keep in sync with prog.ExecBufferSize
const size_t kMaxCommands = 1000; // prog package knows about this constant (prog.execMaxCommands)

const uint64 instr_eof = -1;
const uint64 instr_copyin = -2;
const uint64 instr_copyout = -3;
const uint64 instr_setprops = -4;

const uint64 arg_const = 0;
const uint64 arg_addr32 = 1;
const uint64 arg_addr64 = 2;
const uint64 arg_result = 3;
const uint64 arg_data = 4;
const uint64 arg_csum = 5;

const uint64 binary_format_native = 0;
const uint64 binary_format_bigendian = 1;
const uint64 binary_format_strdec = 2;
const uint64 binary_format_strhex = 3;
const uint64 binary_format_stroct = 4;

const uint64 no_copyout = -1;

static int running;
static uint32 completed;
static bool is_kernel_64_bit;
static bool use_cover_edges;

static uint8* input_data;

// Checksum kinds.
static const uint64 arg_csum_inet = 0;

// Checksum chunk kinds.
static const uint64 arg_csum_chunk_data = 0;
static const uint64 arg_csum_chunk_const = 1;

typedef intptr_t(SYSCALLAPI* syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

struct call_t {
	const char* name;
	int sys_nr;
	call_attrs_t attrs;
	syscall_t call;
};

struct cover_t {
	int fd;
	uint32 size;
	// mmap_alloc_ptr is the internal pointer to KCOV mapping, possibly with guard pages.
	// It is only used to allocate/deallocate the buffer of mmap_alloc_size.
	char* mmap_alloc_ptr;
	uint32 mmap_alloc_size;
	// data is the pointer to the kcov buffer containing the recorded PCs.
	// data may differ from mmap_alloc_ptr.
	char* data;
	// data_size is set by cover_open(). This is the requested kcov buffer size.
	uint32 data_size;
	// data_end is simply data + data_size.
	char* data_end;
	// Currently collecting comparisons.
	bool collect_comps;
	// Note: On everything but darwin the first value in data is the count of
	// recorded PCs, followed by the PCs. We therefore set data_offset to the
	// size of one PC.
	// On darwin data points to an instance of the ksancov_trace struct. Here we
	// set data_offset to the offset between data and the structs 'pcs' member,
	// which contains the PCs.
	intptr_t data_offset;
	// Note: On everything but darwin this is 0, as the PCs contained in data
	// are already correct. XNUs KSANCOV API, however, chose to always squeeze
	// PCs into 32 bit. To make the recorded PC fit, KSANCOV substracts a fixed
	// offset (VM_MIN_KERNEL_ADDRESS for AMD64) and then truncates the result to
	// uint32_t. We get this from the 'offset' member in ksancov_trace.
	intptr_t pc_offset;
	// The coverage buffer has overflowed and we have truncated coverage.
	bool overflow;
	// True if cover_enable() was called for this object.
	bool enabled;
};

struct thread_t {
	int id;
	bool created;
	event_t ready;
	event_t done;
	uint8* copyout_pos;
	uint64 copyout_index;
	bool executing;
	int call_index;
	int call_num;
	int num_args;
	intptr_t args[kMaxArgs];
	call_props_t call_props;
	intptr_t res;
	uint32 reserrno;
	bool fault_injected;
	cover_t cov;
	bool soft_fail_state;
};

static thread_t threads[kMaxThreads];
static thread_t* last_scheduled;
// Threads use this variable to access information about themselves.
static __thread struct thread_t* current_thread;

static cover_t extra_cov;

struct res_t {
	bool executed;
	uint64 val;
};

static res_t results[kMaxCommands];

const uint64 kInMagic = 0xbadc0ffeebadface;

struct handshake_req {
	uint64 magic;
	bool use_cover_edges;
	bool is_kernel_64_bit;
	rpc::ExecEnv flags;
	uint64 pid;
	uint64 sandbox_arg;
	uint64 syscall_timeout_ms;
	uint64 program_timeout_ms;
	uint64 slowdown_scale;
};

struct execute_req {
	uint64 magic;
	uint64 id;
	rpc::RequestType type;
	uint64 exec_flags;
	uint64 all_call_signal;
	bool all_extra_signal;
};

struct execute_reply {
	uint32 magic;
	uint32 done;
	uint32 status;
};

enum {
	KCOV_CMP_CONST = 1,
	KCOV_CMP_SIZE1 = 0,
	KCOV_CMP_SIZE2 = 2,
	KCOV_CMP_SIZE4 = 4,
	KCOV_CMP_SIZE8 = 6,
	KCOV_CMP_SIZE_MASK = 6,
};

struct kcov_comparison_t {
	// Note: comparisons are always 64-bits regardless of kernel bitness.
	uint64 type;
	uint64 arg1;
	uint64 arg2;
	uint64 pc;
};

typedef char kcov_comparison_size[sizeof(kcov_comparison_t) == 4 * sizeof(uint64) ? 1 : -1];

struct feature_t {
	rpc::Feature id;
	const char* (*setup)();
};

static thread_t* schedule_call(int call_index, int call_num, uint64 copyout_index, uint64 num_args, uint64* args, uint8* pos, call_props_t call_props);
static void handle_completion(thread_t* th);
static void copyout_call_results(thread_t* th);
static void write_call_output(thread_t* th, bool finished);
static void write_extra_output();
static void execute_call(thread_t* th);
static void thread_create(thread_t* th, int id, bool need_coverage);
static void thread_mmap_cover(thread_t* th);
static void* worker_thread(void* arg);
static uint64 read_input(uint8** input_posp, bool peek = false);
static uint64 read_arg(uint8** input_posp);
static uint64 read_const_arg(uint8** input_posp, uint64* size_p, uint64* bf, uint64* bf_off_p, uint64* bf_len_p);
static uint64 read_result(uint8** input_posp);
static uint64 swap(uint64 v, uint64 size, uint64 bf);
static void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len);
static bool copyout(char* addr, uint64 size, uint64* res);
static void setup_control_pipes();
static bool coverage_filter(uint64 pc);
static rpc::ComparisonRaw convert(const kcov_comparison_t& cmp);
static flatbuffers::span<uint8_t> finish_output(OutputData* output, int proc_id, uint64 req_id, uint32 num_calls,
						uint64 elapsed, uint64 freshness, uint32 status, bool hanged,
						const std::vector<uint8_t>* process_output);
static void parse_execute(const execute_req& req);
static void parse_handshake(const handshake_req& req);

#include "syscalls.h"

#if GOOS_linux
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#define MAP_FIXED_EXCLUSIVE MAP_FIXED_NOREPLACE
#elif GOOS_freebsd
#define MAP_FIXED_EXCLUSIVE (MAP_FIXED | MAP_EXCL)
#else
#define MAP_FIXED_EXCLUSIVE MAP_FIXED // The check is not supported.
#endif

#if GOOS_linux
#include "executor_linux.h"
#elif GOOS_fuchsia
#include "executor_fuchsia.h"
#elif GOOS_freebsd || GOOS_netbsd || GOOS_openbsd
#include "executor_bsd.h"
#elif GOOS_darwin
#include "executor_darwin.h"
#elif GOOS_windows
#include "executor_windows.h"
#elif GOOS_test
#include "executor_test.h"
#else
#error "unknown OS"
#endif

class CoverAccessScope final
{
public:
	CoverAccessScope(cover_t* cov)
	    : cov_(cov)
	{
		// CoverAccessScope must not be used recursively b/c on Linux pkeys protection is global,
		// so cover_protect for one cov overrides previous cover_unprotect for another cov.
		if (used_)
			fail("recursion in CoverAccessScope");
		used_ = true;
		if (flag_coverage)
			cover_unprotect(cov_);
	}
	~CoverAccessScope()
	{
		if (flag_coverage)
			cover_protect(cov_);
		used_ = false;
	}

private:
	cover_t* const cov_;
	static bool used_;

	CoverAccessScope(const CoverAccessScope&) = delete;
	CoverAccessScope& operator=(const CoverAccessScope&) = delete;
};

bool CoverAccessScope::used_;

#if !SYZ_HAVE_FEATURES
static feature_t features[] = {};
#endif

#include "shmem.h"

#include "conn.h"
#include "cover_filter.h"
#include "files.h"
#include "subprocess.h"

#include "snapshot.h"

#include "executor_runner.h"

#include "test.h"

static std::optional<CoverFilter> max_signal;
static std::optional<CoverFilter> cover_filter;

#if SYZ_HAVE_SANDBOX_ANDROID
static uint64 sandbox_arg = 0;
#endif

int main(int argc, char** argv)
{
	if (argc == 1) {
		fprintf(stderr, "no command");
		return 1;
	}
	if (strcmp(argv[1], "runner") == 0) {
		runner(argv, argc);
		fail("runner returned");
	}
	if (strcmp(argv[1], "leak") == 0) {
#if SYZ_HAVE_LEAK_CHECK
		check_leaks(argv + 2, argc - 2);
#else
		fail("leak checking is not implemented");
#endif
		return 0;
	}
	if (strcmp(argv[1], "test") == 0)
		return run_tests(argc == 3 ? argv[2] : nullptr);

	if (strcmp(argv[1], "exec") != 0) {
		fprintf(stderr, "unknown command");
		return 1;
	}

	start_time_ms = current_time_ms();

	os_init(argc, argv, (char*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);
	use_temporary_dir();
	install_segv_handler();
	current_thread = &threads[0];

	if (argc > 2 && strcmp(argv[2], "snapshot") == 0) {
		SnapshotSetup(argv, argc);
	} else {
		void* mmap_out = mmap(NULL, kMaxInput, PROT_READ, MAP_SHARED, kInFd, 0);
		if (mmap_out == MAP_FAILED)
			fail("mmap of input file failed");
		input_data = static_cast<uint8*>(mmap_out);

		mmap_output(kInitialOutput);

		// Prevent test programs to mess with these fds.
		// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
		// which will cause fuzzer to crash.
		close(kInFd);
#if !SYZ_EXECUTOR_USES_FORK_SERVER
		// For SYZ_EXECUTOR_USES_FORK_SERVER, close(kOutFd) is invoked in the forked child,
		// after the program has been received.
		close(kOutFd);
#endif

		if (fcntl(kMaxSignalFd, F_GETFD) != -1) {
			// Use random addresses for coverage filters to not collide with output_data.
			max_signal.emplace(kMaxSignalFd, reinterpret_cast<void*>(0x110c230000ull));
			close(kMaxSignalFd);
		}
		if (fcntl(kCoverFilterFd, F_GETFD) != -1) {
			cover_filter.emplace(kCoverFilterFd, reinterpret_cast<void*>(0x110f230000ull));
			close(kCoverFilterFd);
		}

		setup_control_pipes();
		receive_handshake();
#if !SYZ_EXECUTOR_USES_FORK_SERVER
		// We receive/reply handshake when fork server is disabled just to simplify runner logic.
		// It's a bit suboptimal, but no fork server is much slower anyway.
		reply_execute(0);
		receive_execute();
#endif
	}

	if (flag_coverage) {
		int create_count = kCoverDefaultCount, mmap_count = create_count;
		if (flag_delay_kcov_mmap) {
			create_count = kCoverOptimizedCount;
			mmap_count = kCoverOptimizedPreMmap;
		}
		if (create_count > kMaxThreads)
			create_count = kMaxThreads;
		for (int i = 0; i < create_count; i++) {
			threads[i].cov.fd = kCoverFd + i;
			cover_open(&threads[i].cov, false);
			if (i < mmap_count) {
				// Pre-mmap coverage collection for some threads. This should be enough for almost
				// all programs, for the remaning few ones coverage will be set up when it's needed.
				thread_mmap_cover(&threads[i]);
			}
		}
		extra_cov.fd = kExtraCoverFd;
		cover_open(&extra_cov, true);
		cover_mmap(&extra_cov);
		cover_protect(&extra_cov);
		if (flag_extra_coverage) {
			// Don't enable comps because we don't use them in the fuzzer yet.
			cover_enable(&extra_cov, false, true);
		}
	}

	int status = 0;
	if (flag_sandbox_none)
		status = do_sandbox_none();
#if SYZ_HAVE_SANDBOX_SETUID
	else if (flag_sandbox_setuid)
		status = do_sandbox_setuid();
#endif
#if SYZ_HAVE_SANDBOX_NAMESPACE
	else if (flag_sandbox_namespace)
		status = do_sandbox_namespace();
#endif
#if SYZ_HAVE_SANDBOX_ANDROID
	else if (flag_sandbox_android)
		status = do_sandbox_android(sandbox_arg);
#endif
	else
		fail("unknown sandbox type");

#if SYZ_EXECUTOR_USES_FORK_SERVER
	fprintf(stderr, "loop exited with status %d\n", status);
	// If an external sandbox process wraps executor, the out pipe will be closed
	// before the sandbox process exits this will make ipc package kill the sandbox.
	// As the result sandbox process will exit with exit status 9 instead of the executor
	// exit status (notably kFailStatus). So we duplicate the exit status on the pipe.
	reply_execute(status);
	doexit(status);
	// Unreachable.
	return 1;
#else
	reply_execute(status);
	return status;
#endif
}

// This method can be invoked as many times as one likes - MMAP_FIXED can overwrite the previous
// mapping without any problems. The only precondition - kOutFd must not be closed.
static void mmap_output(uint32 size)
{
	if (size <= output_size)
		return;
	if (size % SYZ_PAGE_SIZE != 0)
		failmsg("trying to mmap output area that is not divisible by page size", "page=%d,area=%d", SYZ_PAGE_SIZE, size);
	uint32* mmap_at = NULL;
	if (output_data == NULL) {
		if (kAddressSanitizer) {
			// ASan allows user mappings only at some specific address ranges,
			// so we don't randomize. But we also assume 64-bits and that we are running tests.
			mmap_at = (uint32*)0x7f0000000000ull;
		} else {
			// It's the first time we map output region - generate its location.
			// The output region is the only thing in executor process for which consistency matters.
			// If it is corrupted ipc package will fail to parse its contents and panic.
			// But fuzzer constantly invents new ways of how to corrupt the region,
			// so we map the region at a (hopefully) hard to guess address with random offset,
			// surrounded by unmapped pages.
			// The address chosen must also work on 32-bit kernels with 1GB user address space.
			const uint64 kOutputBase = 0x1b2bc20000ull;
			mmap_at = (uint32*)(kOutputBase + (1 << 20) * (getpid() % 128));
		}
	} else {
		// We are expanding the mmapped region. Adjust the parameters to avoid mmapping already
		// mmapped area as much as possible.
		// There exists a mremap call that could have helped, but it's purely Linux-specific.
		mmap_at = (uint32*)((char*)(output_data) + output_size);
	}
	void* result = mmap(mmap_at, size - output_size,
			    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, output_size);
	if (result == MAP_FAILED || (mmap_at && result != mmap_at))
		failmsg("mmap of output file failed", "want %p, got %p", mmap_at, result);
	if (output_data == NULL)
		output_data = static_cast<OutputData*>(result);
	output_size = size;
}

void setup_control_pipes()
{
	if (dup2(0, kInPipeFd) < 0)
		fail("dup2(0, kInPipeFd) failed");
	if (dup2(1, kOutPipeFd) < 0)
		fail("dup2(1, kOutPipeFd) failed");
	if (dup2(2, 1) < 0)
		fail("dup2(2, 1) failed");
	// We used to close(0), but now we dup stderr to stdin to keep fd numbers
	// stable across executor and C programs generated by pkg/csource.
	if (dup2(2, 0) < 0)
		fail("dup2(2, 0) failed");
}

void receive_handshake()
{
	handshake_req req = {};
	ssize_t n = read(kInPipeFd, &req, sizeof(req));
	if (n != sizeof(req))
		failmsg("handshake read failed", "read=%zu", n);
	parse_handshake(req);
}

void parse_handshake(const handshake_req& req)
{
	if (req.magic != kInMagic)
		failmsg("bad handshake magic", "magic=0x%llx", req.magic);
#if SYZ_HAVE_SANDBOX_ANDROID
	sandbox_arg = req.sandbox_arg;
#endif
	is_kernel_64_bit = req.is_kernel_64_bit;
	use_cover_edges = req.use_cover_edges;
	procid = req.pid;
	syscall_timeout_ms = req.syscall_timeout_ms;
	program_timeout_ms = req.program_timeout_ms;
	slowdown_scale = req.slowdown_scale;
	flag_debug = (bool)(req.flags & rpc::ExecEnv::Debug);
	flag_coverage = (bool)(req.flags & rpc::ExecEnv::Signal);
	flag_read_only_coverage = (bool)(req.flags & rpc::ExecEnv::ReadOnlyCoverage);
	flag_sandbox_none = (bool)(req.flags & rpc::ExecEnv::SandboxNone);
	flag_sandbox_setuid = (bool)(req.flags & rpc::ExecEnv::SandboxSetuid);
	flag_sandbox_namespace = (bool)(req.flags & rpc::ExecEnv::SandboxNamespace);
	flag_sandbox_android = (bool)(req.flags & rpc::ExecEnv::SandboxAndroid);
	flag_extra_coverage = (bool)(req.flags & rpc::ExecEnv::ExtraCover);
	flag_net_injection = (bool)(req.flags & rpc::ExecEnv::EnableTun);
	flag_net_devices = (bool)(req.flags & rpc::ExecEnv::EnableNetDev);
	flag_net_reset = (bool)(req.flags & rpc::ExecEnv::EnableNetReset);
	flag_cgroups = (bool)(req.flags & rpc::ExecEnv::EnableCgroups);
	flag_close_fds = (bool)(req.flags & rpc::ExecEnv::EnableCloseFds);
	flag_devlink_pci = (bool)(req.flags & rpc::ExecEnv::EnableDevlinkPCI);
	flag_vhci_injection = (bool)(req.flags & rpc::ExecEnv::EnableVhciInjection);
	flag_wifi = (bool)(req.flags & rpc::ExecEnv::EnableWifi);
	flag_delay_kcov_mmap = (bool)(req.flags & rpc::ExecEnv::DelayKcovMmap);
	flag_nic_vf = (bool)(req.flags & rpc::ExecEnv::EnableNicVF);
}

void receive_execute()
{
	execute_req req = {};
	ssize_t n = 0;
	while ((n = read(kInPipeFd, &req, sizeof(req))) == -1 && errno == EINTR)
		;
	if (n != (ssize_t)sizeof(req))
		failmsg("control pipe read failed", "read=%zd want=%zd", n, sizeof(req));
	parse_execute(req);
}

void parse_execute(const execute_req& req)
{
	request_id = req.id;
	request_type = req.type;
	flag_collect_signal = req.exec_flags & (1 << 0);
	flag_collect_cover = req.exec_flags & (1 << 1);
	flag_dedup_cover = req.exec_flags & (1 << 2);
	flag_comparisons = req.exec_flags & (1 << 3);
	flag_threaded = req.exec_flags & (1 << 4);
	all_call_signal = req.all_call_signal;
	all_extra_signal = req.all_extra_signal;

	debug("[%llums] exec opts: reqid=%llu type=%llu procid=%llu threaded=%d cover=%d comps=%d dedup=%d signal=%d "
	      " sandbox=%d/%d/%d/%d timeouts=%llu/%llu/%llu kernel_64_bit=%d\n",
	      current_time_ms() - start_time_ms, request_id, (uint64)request_type, procid, flag_threaded, flag_collect_cover,
	      flag_comparisons, flag_dedup_cover, flag_collect_signal, flag_sandbox_none, flag_sandbox_setuid,
	      flag_sandbox_namespace, flag_sandbox_android, syscall_timeout_ms, program_timeout_ms, slowdown_scale,
	      is_kernel_64_bit);
	if (syscall_timeout_ms == 0 || program_timeout_ms <= syscall_timeout_ms || slowdown_scale == 0)
		failmsg("bad timeouts", "syscall=%llu, program=%llu, scale=%llu",
			syscall_timeout_ms, program_timeout_ms, slowdown_scale);
}

bool cover_collection_required()
{
	return flag_coverage && (flag_collect_signal || flag_collect_cover || flag_comparisons);
}

void reply_execute(uint32 status)
{
	if (flag_snapshot)
		SnapshotDone(status == kFailStatus);
	if (write(kOutPipeFd, &status, sizeof(status)) != sizeof(status))
		fail("control pipe write failed");
}

void realloc_output_data()
{
#if SYZ_EXECUTOR_USES_FORK_SERVER
	if (flag_comparisons)
		mmap_output(kMaxOutputComparisons);
	else if (flag_collect_cover)
		mmap_output(kMaxOutputCoverage);
	else if (flag_collect_signal)
		mmap_output(kMaxOutputSignal);
	if (close(kOutFd) < 0)
		fail("failed to close kOutFd");
#endif
}

void execute_glob()
{
	const char* pattern = (const char*)input_data;
	const auto& files = Glob(pattern);
	size_t size = 0;
	for (const auto& file : files)
		size += file.size() + 1;
	mmap_output(kMaxOutput);
	ShmemBuilder fbb(output_data, kMaxOutput, true);
	uint8_t* pos = nullptr;
	auto off = fbb.CreateUninitializedVector(size, &pos);
	for (const auto& file : files) {
		memcpy(pos, file.c_str(), file.size() + 1);
		pos += file.size() + 1;
	}
	output_data->consumed.store(fbb.GetSize(), std::memory_order_release);
	output_data->result_offset.store(off, std::memory_order_release);
}

// execute_one executes program stored in input_data.
void execute_one()
{
	if (request_type == rpc::RequestType::Glob) {
		execute_glob();
		return;
	}
	if (request_type != rpc::RequestType::Program)
		failmsg("bad request type", "type=%llu", (uint64)request_type);

	in_execute_one = true;
#if GOOS_linux
	char buf[64];
	// Linux TASK_COMM_LEN is only 16, so the name needs to be compact.
	snprintf(buf, sizeof(buf), "syz.%llu.%llu", procid, request_id);
	prctl(PR_SET_NAME, buf);
#endif
	if (flag_snapshot)
		SnapshotStart();
	else
		realloc_output_data();
	// Output buffer may be pkey-protected in snapshot mode, so don't write the output size
	// (it's fixed and known anyway).
	output_builder.emplace(output_data, output_size, !flag_snapshot);
	uint64 start = current_time_ms();
	uint8* input_pos = input_data;

	if (cover_collection_required()) {
		if (!flag_threaded)
			cover_enable(&threads[0].cov, flag_comparisons, false);
		if (flag_extra_coverage)
			cover_reset(&extra_cov);
	}

	int call_index = 0;
	uint64 prog_extra_timeout = 0;
	uint64 prog_extra_cover_timeout = 0;
	call_props_t call_props;
	memset(&call_props, 0, sizeof(call_props));

	read_input(&input_pos); // total number of calls
	for (;;) {
		uint64 call_num = read_input(&input_pos);
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)(read_input(&input_pos) + SYZ_DATA_OFFSET);
			uint64 typ = read_input(&input_pos);
			switch (typ) {
			case arg_const: {
				uint64 size, bf, bf_off, bf_len;
				uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
				copyin(addr, arg, size, bf, bf_off, bf_len);
				break;
			}
			case arg_addr32:
			case arg_addr64: {
				uint64 val = read_input(&input_pos) + SYZ_DATA_OFFSET;
				if (typ == arg_addr32)
					NONFAILING(*(uint32*)addr = val);
				else
					NONFAILING(*(uint64*)addr = val);
				break;
			}
			case arg_result: {
				uint64 meta = read_input(&input_pos);
				uint64 size = meta & 0xff;
				uint64 bf = meta >> 8;
				uint64 val = read_result(&input_pos);
				copyin(addr, val, size, bf, 0, 0);
				break;
			}
			case arg_data: {
				uint64 size = read_input(&input_pos);
				size &= ~(1ull << 63); // readable flag
				if (input_pos + size > input_data + kMaxInput)
					fail("data arg overflow");
				NONFAILING(memcpy(addr, input_pos, size));
				input_pos += size;
				break;
			}
			case arg_csum: {
				debug_verbose("checksum found at %p\n", addr);
				uint64 size = read_input(&input_pos);
				char* csum_addr = addr;
				uint64 csum_kind = read_input(&input_pos);
				switch (csum_kind) {
				case arg_csum_inet: {
					if (size != 2)
						failmsg("bag inet checksum size", "size=%llu", size);
					debug_verbose("calculating checksum for %p\n", csum_addr);
					struct csum_inet csum;
					csum_inet_init(&csum);
					uint64 chunks_num = read_input(&input_pos);
					uint64 chunk;
					for (chunk = 0; chunk < chunks_num; chunk++) {
						uint64 chunk_kind = read_input(&input_pos);
						uint64 chunk_value = read_input(&input_pos);
						uint64 chunk_size = read_input(&input_pos);
						switch (chunk_kind) {
						case arg_csum_chunk_data:
							chunk_value += SYZ_DATA_OFFSET;
							debug_verbose("#%lld: data chunk, addr: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							NONFAILING(csum_inet_update(&csum, (const uint8*)chunk_value, chunk_size));
							break;
						case arg_csum_chunk_const:
							if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8)
								failmsg("bad checksum const chunk size", "size=%lld", chunk_size);
							// Here we assume that const values come to us big endian.
							debug_verbose("#%lld: const chunk, value: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							csum_inet_update(&csum, (const uint8*)&chunk_value, chunk_size);
							break;
						default:
							failmsg("bad checksum chunk kind", "kind=%llu", chunk_kind);
						}
					}
					uint16 csum_value = csum_inet_digest(&csum);
					debug_verbose("writing inet checksum %hx to %p\n", csum_value, csum_addr);
					copyin(csum_addr, csum_value, 2, binary_format_native, 0, 0);
					break;
				}
				default:
					failmsg("bad checksum kind", "kind=%llu", csum_kind);
				}
				break;
			}
			default:
				failmsg("bad argument type", "type=%llu", typ);
			}
			continue;
		}
		if (call_num == instr_copyout) {
			read_input(&input_pos); // index
			read_input(&input_pos); // addr
			read_input(&input_pos); // size
			// The copyout will happen when/if the call completes.
			continue;
		}
		if (call_num == instr_setprops) {
			read_call_props_t(call_props, read_input(&input_pos, false));
			continue;
		}

		// Normal syscall.
		if (call_num >= ARRAY_SIZE(syscalls))
			failmsg("invalid syscall number", "call_num=%llu", call_num);
		const call_t* call = &syscalls[call_num];
		if (prog_extra_timeout < call->attrs.prog_timeout)
			prog_extra_timeout = call->attrs.prog_timeout * slowdown_scale;
		if (call->attrs.remote_cover)
			prog_extra_cover_timeout = 500 * slowdown_scale; // 500 ms
		uint64 copyout_index = read_input(&input_pos);
		uint64 num_args = read_input(&input_pos);
		if (num_args > kMaxArgs)
			failmsg("command has bad number of arguments", "args=%llu", num_args);
		uint64 args[kMaxArgs] = {};
		for (uint64 i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
		for (uint64 i = num_args; i < kMaxArgs; i++)
			args[i] = 0;
		thread_t* th = schedule_call(call_index++, call_num, copyout_index,
					     num_args, args, input_pos, call_props);

		if (call_props.async && flag_threaded) {
			// Don't wait for an async call to finish. We'll wait at the end.
			// If we're not in the threaded mode, just ignore the async flag - during repro simplification syzkaller
			// will anyway try to make it non-threaded.
		} else if (flag_threaded) {
			// Wait for call completion.
			uint64 timeout_ms = syscall_timeout_ms + call->attrs.timeout * slowdown_scale;
			// This is because of printing pre/post call. Ideally we print everything in the main thread
			// and then remove this (would also avoid intermixed output).
			if (flag_debug && timeout_ms < 1000)
				timeout_ms = 1000;
			if (event_timedwait(&th->done, timeout_ms))
				handle_completion(th);

			// Check if any of previous calls have completed.
			for (int i = 0; i < kMaxThreads; i++) {
				th = &threads[i];
				if (th->executing && event_isset(&th->done))
					handle_completion(th);
			}
		} else {
			// Execute directly.
			if (th != &threads[0])
				fail("using non-main thread in non-thread mode");
			event_reset(&th->ready);
			execute_call(th);
			event_set(&th->done);
			handle_completion(th);
		}
		memset(&call_props, 0, sizeof(call_props));
	}

	if (running > 0) {
		// Give unfinished syscalls some additional time.
		last_scheduled = 0;
		uint64 wait_start = current_time_ms();
		uint64 wait_end = wait_start + 2 * syscall_timeout_ms;
		wait_end = std::max(wait_end, start + program_timeout_ms / 6);
		wait_end = std::max(wait_end, wait_start + prog_extra_timeout);
		while (running > 0 && current_time_ms() <= wait_end) {
			sleep_ms(1 * slowdown_scale);
			for (int i = 0; i < kMaxThreads; i++) {
				thread_t* th = &threads[i];
				if (th->executing && event_isset(&th->done))
					handle_completion(th);
			}
		}
		// Write output coverage for unfinished calls.
		if (running > 0) {
			for (int i = 0; i < kMaxThreads; i++) {
				thread_t* th = &threads[i];
				if (th->executing) {
					if (cover_collection_required())
						cover_collect(&th->cov);
					write_call_output(th, false);
				}
			}
		}
	}

#if SYZ_HAVE_CLOSE_FDS
	close_fds();
#endif

	write_extra_output();
	if (flag_extra_coverage) {
		// Check for new extra coverage in small intervals to avoid situation
		// that we were killed on timeout before we write any.
		// Check for extra coverage is very cheap, effectively a memory load.
		const uint64 kSleepMs = 100;
		for (uint64 i = 0; i < prog_extra_cover_timeout / kSleepMs &&
				   output_data->completed.load(std::memory_order_relaxed) < kMaxCalls;
		     i++) {
			sleep_ms(kSleepMs);
			write_extra_output();
		}
	}
}

thread_t* schedule_call(int call_index, int call_num, uint64 copyout_index, uint64 num_args, uint64* args, uint8* pos, call_props_t call_props)
{
	// Find a spare thread to execute the call.
	int i = 0;
	for (; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		if (!th->created)
			thread_create(th, i, cover_collection_required());
		if (event_isset(&th->done)) {
			if (th->executing)
				handle_completion(th);
			break;
		}
	}
	if (i == kMaxThreads)
		exitf("out of threads");
	thread_t* th = &threads[i];
	if (event_isset(&th->ready) || !event_isset(&th->done) || th->executing)
		exitf("bad thread state in schedule: ready=%d done=%d executing=%d",
		      event_isset(&th->ready), event_isset(&th->done), th->executing);
	last_scheduled = th;
	th->copyout_pos = pos;
	th->copyout_index = copyout_index;
	event_reset(&th->done);
	// We do this both right before execute_syscall in the thread and here because:
	// the former is useful to reset all unrelated coverage from our syscalls (e.g. futex in event_wait),
	// while the reset here is useful to avoid the following scenario that the fuzzer was able to trigger.
	// If the test program contains seccomp syscall that kills the worker thread on the next syscall,
	// then it won't receive this next syscall and won't do cover_reset. If we are collecting comparions
	// then we've already transformed comparison data from the previous syscall into rpc::ComparisonRaw
	// in write_comparisons. That data is still in the buffer. The first word of rpc::ComparisonRaw is PC
	// which overlaps with comparison type in kernel exposed records. As the result write_comparisons
	// that will try to write out data from unfinished syscalls will see these rpc::ComparisonRaw records,
	// mis-interpret PC as type, and fail as: SYZFAIL: invalid kcov comp type (type=ffffffff8100b4e0).
	if (flag_coverage)
		cover_reset(&th->cov);
	th->executing = true;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	th->call_props = call_props;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	event_set(&th->ready);
	running++;
	return th;
}

template <typename cover_data_t>
uint32 write_signal(flatbuffers::FlatBufferBuilder& fbb, int index, cover_t* cov, bool all)
{
	// Write out feedback signals.
	// Currently it is code edges computed as xor of two subsequent basic block PCs.
	fbb.StartVector(0, sizeof(uint64));
	cover_data_t* cover_data = (cover_data_t*)(cov->data + cov->data_offset);
	if ((char*)(cover_data + cov->size) > cov->data_end)
		failmsg("too much cover", "cov=%u", cov->size);
	uint32 nsig = 0;
	cover_data_t prev_pc = 0;
	bool prev_filter = true;
	for (uint32 i = 0; i < cov->size; i++) {
		cover_data_t pc = cover_data[i] + cov->pc_offset;
		uint64 sig = pc;
		if (use_cover_edges) {
			// Only hash the lower 12 bits so the hash is independent of any module offsets.
			const uint64 mask = (1 << 12) - 1;
			sig ^= hash(prev_pc & mask) & mask;
		}
		bool filter = coverage_filter(pc);
		// Ignore the edge only if both current and previous PCs are filtered out
		// to capture all incoming and outcoming edges into the interesting code.
		bool ignore = !filter && !prev_filter;
		prev_pc = pc;
		prev_filter = filter;
		if (ignore || dedup(index, sig))
			continue;
		if (!all && max_signal && max_signal->Contains(sig))
			continue;
		fbb.PushElement(uint64(sig));
		nsig++;
	}
	return fbb.EndVector(nsig);
}

template <typename cover_data_t>
uint32 write_cover(flatbuffers::FlatBufferBuilder& fbb, cover_t* cov)
{
	uint32 cover_size = cov->size;
	cover_data_t* cover_data = (cover_data_t*)(cov->data + cov->data_offset);
	if (flag_dedup_cover) {
		cover_data_t* end = cover_data + cover_size;
		std::sort(cover_data, end);
		cover_size = std::unique(cover_data, end) - cover_data;
	}
	fbb.StartVector(cover_size, sizeof(uint64));
	// Flatbuffer arrays are written backwards, so reverse the order on our side as well.
	for (uint32 i = 0; i < cover_size; i++)
		fbb.PushElement(uint64(cover_data[cover_size - i - 1] + cov->pc_offset));
	return fbb.EndVector(cover_size);
}

uint32 write_comparisons(flatbuffers::FlatBufferBuilder& fbb, cover_t* cov)
{
	// Collect only the comparisons
	uint64 ncomps = *(uint64_t*)cov->data;
	kcov_comparison_t* cov_start = (kcov_comparison_t*)(cov->data + sizeof(uint64));
	if ((char*)(cov_start + ncomps) > cov->data_end)
		failmsg("too many comparisons", "ncomps=%llu", ncomps);
	cov->overflow = ((char*)(cov_start + ncomps + 1) > cov->data_end);
	rpc::ComparisonRaw* start = (rpc::ComparisonRaw*)cov_start;
	rpc::ComparisonRaw* end = start;
	// We will convert kcov_comparison_t to ComparisonRaw inplace.
	static_assert(sizeof(kcov_comparison_t) >= sizeof(rpc::ComparisonRaw));
	for (uint32 i = 0; i < ncomps; i++) {
		auto raw = convert(cov_start[i]);
		if (!raw.pc())
			continue;
		*end++ = raw;
	}
	std::sort(start, end, [](rpc::ComparisonRaw a, rpc::ComparisonRaw b) -> bool {
		if (a.pc() != b.pc())
			return a.pc() < b.pc();
		if (a.op1() != b.op1())
			return a.op1() < b.op1();
		return a.op2() < b.op2();
	});
	ncomps = std::unique(start, end, [](rpc::ComparisonRaw a, rpc::ComparisonRaw b) -> bool {
			 return a.pc() == b.pc() && a.op1() == b.op1() && a.op2() == b.op2();
		 }) -
		 start;
	return fbb.CreateVectorOfStructs(start, ncomps).o;
}

bool coverage_filter(uint64 pc)
{
	if (!cover_filter)
		return true;
	return cover_filter->Contains(pc);
}

void handle_completion(thread_t* th)
{
	if (event_isset(&th->ready) || !event_isset(&th->done) || !th->executing)
		exitf("bad thread state in completion: ready=%d done=%d executing=%d",
		      event_isset(&th->ready), event_isset(&th->done), th->executing);
	if (th->res != (intptr_t)-1)
		copyout_call_results(th);

	write_call_output(th, true);
	write_extra_output();
	th->executing = false;
	running--;
	if (running < 0) {
		// This fires periodically for the past 2 years (see issue #502).
		fprintf(stderr, "running=%d completed=%d flag_threaded=%d current=%d\n",
			running, completed, flag_threaded, th->id);
		for (int i = 0; i < kMaxThreads; i++) {
			thread_t* th1 = &threads[i];
			fprintf(stderr, "th #%2d: created=%d executing=%d"
					" ready=%d done=%d call_index=%d res=%lld reserrno=%d\n",
				i, th1->created, th1->executing,
				event_isset(&th1->ready), event_isset(&th1->done),
				th1->call_index, (uint64)th1->res, th1->reserrno);
		}
		exitf("negative running");
	}
}

void copyout_call_results(thread_t* th)
{
	if (th->copyout_index != no_copyout) {
		if (th->copyout_index >= kMaxCommands)
			failmsg("result overflows kMaxCommands", "index=%lld", th->copyout_index);
		results[th->copyout_index].executed = true;
		results[th->copyout_index].val = th->res;
	}
	for (bool done = false; !done;) {
		uint64 instr = read_input(&th->copyout_pos);
		switch (instr) {
		case instr_copyout: {
			uint64 index = read_input(&th->copyout_pos);
			if (index >= kMaxCommands)
				failmsg("result overflows kMaxCommands", "index=%lld", index);
			char* addr = (char*)(read_input(&th->copyout_pos) + SYZ_DATA_OFFSET);
			uint64 size = read_input(&th->copyout_pos);
			uint64 val = 0;
			if (copyout(addr, size, &val)) {
				results[index].executed = true;
				results[index].val = val;
			}
			debug_verbose("copyout 0x%llx from %p\n", val, addr);
			break;
		}
		default:
			done = true;
			break;
		}
	}
}

void write_output(int index, cover_t* cov, rpc::CallFlag flags, uint32 error, bool all_signal)
{
	CoverAccessScope scope(cov);
	auto& fbb = *output_builder;
	const uint32 start_size = output_builder->GetSize();
	(void)start_size;
	uint32 signal_off = 0;
	uint32 cover_off = 0;
	uint32 comps_off = 0;
	if (flag_comparisons) {
		comps_off = write_comparisons(fbb, cov);
	} else {
		if (flag_collect_signal) {
			if (is_kernel_64_bit)
				signal_off = write_signal<uint64>(fbb, index, cov, all_signal);
			else
				signal_off = write_signal<uint32>(fbb, index, cov, all_signal);
		}
		if (flag_collect_cover) {
			if (is_kernel_64_bit)
				cover_off = write_cover<uint64>(fbb, cov);
			else
				cover_off = write_cover<uint32>(fbb, cov);
		}
	}

	rpc::CallInfoRawBuilder builder(*output_builder);
	if (cov->overflow)
		flags |= rpc::CallFlag::CoverageOverflow;
	builder.add_flags(flags);
	builder.add_error(error);
	if (signal_off)
		builder.add_signal(signal_off);
	if (cover_off)
		builder.add_cover(cover_off);
	if (comps_off)
		builder.add_comps(comps_off);
	auto off = builder.Finish();
	uint32 slot = output_data->completed.load(std::memory_order_relaxed);
	if (slot >= kMaxCalls)
		failmsg("too many calls in output", "slot=%d", slot);
	auto& call = output_data->calls[slot];
	call.index = index;
	call.offset = off;
	output_data->consumed.store(output_builder->GetSize(), std::memory_order_release);
	output_data->completed.store(slot + 1, std::memory_order_release);
	debug_verbose("out #%u: index=%u errno=%d flags=0x%x total_size=%u\n",
		      slot + 1, index, error, static_cast<unsigned>(flags), call.data_size - start_size);
}

void write_call_output(thread_t* th, bool finished)
{
	uint32 reserrno = ENOSYS;
	rpc::CallFlag flags = rpc::CallFlag::Executed;
	if (finished && th != last_scheduled)
		flags |= rpc::CallFlag::Blocked;
	if (finished) {
		reserrno = th->res != -1 ? 0 : th->reserrno;
		flags |= rpc::CallFlag::Finished;
		if (th->fault_injected)
			flags |= rpc::CallFlag::FaultInjected;
	}
	bool all_signal = th->call_index < 64 ? (all_call_signal & (1ull << th->call_index)) : false;
	write_output(th->call_index, &th->cov, flags, reserrno, all_signal);
}

void write_extra_output()
{
	if (!cover_collection_required() || !flag_extra_coverage || flag_comparisons)
		return;
	cover_collect(&extra_cov);
	if (!extra_cov.size)
		return;
	write_output(-1, &extra_cov, rpc::CallFlag::NONE, 997, all_extra_signal);
	cover_reset(&extra_cov);
}

flatbuffers::span<uint8_t> finish_output(OutputData* output, int proc_id, uint64 req_id, uint32 num_calls, uint64 elapsed,
					 uint64 freshness, uint32 status, bool hanged, const std::vector<uint8_t>* process_output)
{
	// In snapshot mode the output size is fixed and output_size is always initialized, so use it.
	int out_size = flag_snapshot ? output_size : output->size.load(std::memory_order_relaxed) ?
												  : kMaxOutput;
	uint32 completed = output->completed.load(std::memory_order_relaxed);
	completed = std::min(completed, kMaxCalls);
	debug("handle completion: completed=%u output_size=%u\n", completed, out_size);
	ShmemBuilder fbb(output, out_size, false);
	auto empty_call = rpc::CreateCallInfoRawDirect(fbb, rpc::CallFlag::NONE, 998);
	std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> calls(num_calls, empty_call);
	std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> extra;
	for (uint32_t i = 0; i < completed; i++) {
		const auto& call = output->calls[i];
		if (call.index == -1) {
			extra.push_back(call.offset);
			continue;
		}
		if (call.index < 0 || call.index >= static_cast<int>(num_calls) || call.offset.o > kMaxOutput) {
			debug("bad call index/offset: proc=%d req=%llu call=%d/%d completed=%d offset=%u",
			      proc_id, req_id, call.index, num_calls,
			      completed, call.offset.o);
			continue;
		}
		calls[call.index] = call.offset;
	}
	auto prog_info_off = rpc::CreateProgInfoRawDirect(fbb, &calls, &extra, 0, elapsed, freshness);
	flatbuffers::Offset<flatbuffers::String> error_off = 0;
	if (status == kFailStatus)
		error_off = fbb.CreateString("process failed");
	// If the request wrote binary result (currently glob requests do this), use it instead of the output.
	auto output_off = output->result_offset.load(std::memory_order_relaxed);
	if (output_off.IsNull() && process_output)
		output_off = fbb.CreateVector(*process_output);
	auto exec_off = rpc::CreateExecResultRaw(fbb, req_id, proc_id, output_off, hanged, error_off, prog_info_off);
	auto msg_off = rpc::CreateExecutorMessageRaw(fbb, rpc::ExecutorMessagesRaw::ExecResult,
						     flatbuffers::Offset<void>(exec_off.o));
	fbb.FinishSizePrefixed(msg_off);
	return fbb.GetBufferSpan();
}

void thread_create(thread_t* th, int id, bool need_coverage)
{
	th->created = true;
	th->id = id;
	th->executing = false;
	// Lazily set up coverage collection.
	// It is assumed that actually it's already initialized - with a few rare exceptions.
	if (need_coverage) {
		if (!th->cov.fd)
			exitf("out of opened kcov threads");
		thread_mmap_cover(th);
	}
	event_init(&th->ready);
	event_init(&th->done);
	event_set(&th->done);
	if (flag_threaded)
		thread_start(worker_thread, th);
}

void thread_mmap_cover(thread_t* th)
{
	if (th->cov.data != NULL)
		return;
	cover_mmap(&th->cov);
	cover_protect(&th->cov);
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;
	current_thread = th;
	for (bool first = true;; first = false) {
		event_wait(&th->ready);
		event_reset(&th->ready);
		// Setup coverage only after receiving the first ready event
		// because in snapshot mode we don't know coverage mode for precreated threads.
		if (first && cover_collection_required())
			cover_enable(&th->cov, flag_comparisons, false);
		execute_call(th);
		event_set(&th->done);
	}
	return 0;
}

void execute_call(thread_t* th)
{
	const call_t* call = &syscalls[th->call_num];
	debug("#%d [%llums] -> %s(",
	      th->id, current_time_ms() - start_time_ms, call->name);
	for (int i = 0; i < th->num_args; i++) {
		if (i != 0)
			debug(", ");
		debug("0x%llx", (uint64)th->args[i]);
	}
	debug(")\n");

	int fail_fd = -1;
	th->soft_fail_state = false;
	if (th->call_props.fail_nth > 0) {
		if (th->call_props.rerun > 0)
			fail("both fault injection and rerun are enabled for the same call");
		fail_fd = inject_fault(th->call_props.fail_nth);
		th->soft_fail_state = true;
	}

	if (flag_coverage)
		cover_reset(&th->cov);
	// For pseudo-syscalls and user-space functions NONFAILING can abort before assigning to th->res.
	// Arrange for res = -1 and errno = EFAULT result for such case.
	th->res = -1;
	errno = EFAULT;
	NONFAILING(th->res = execute_syscall(call, th->args));
	th->reserrno = errno;
	// Our pseudo-syscalls may misbehave.
	if ((th->res == -1 && th->reserrno == 0) || call->attrs.ignore_return)
		th->reserrno = EINVAL;
	// Reset the flag before the first possible fail().
	th->soft_fail_state = false;

	if (flag_coverage)
		cover_collect(&th->cov);
	th->fault_injected = false;

	if (th->call_props.fail_nth > 0)
		th->fault_injected = fault_injected(fail_fd);

	// If required, run the syscall some more times.
	// But let's still return res, errno and coverage from the first execution.
	for (int i = 0; i < th->call_props.rerun; i++)
		NONFAILING(execute_syscall(call, th->args));

	debug("#%d [%llums] <- %s=0x%llx",
	      th->id, current_time_ms() - start_time_ms, call->name, (uint64)th->res);
	if (th->res == (intptr_t)-1)
		debug(" errno=%d", th->reserrno);
	if (flag_coverage)
		debug(" cover=%u", th->cov.size);
	if (th->call_props.fail_nth > 0)
		debug(" fault=%d", th->fault_injected);
	if (th->call_props.rerun > 0)
		debug(" rerun=%d", th->call_props.rerun);
	debug("\n");
}

static uint32 hash(uint32 a)
{
	// For test OS we disable hashing for determinism and testability.
#if !GOOS_test
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
#endif
	return a;
}

const uint32 dedup_table_size = 8 << 10;
uint64 dedup_table_sig[dedup_table_size];
uint8 dedup_table_index[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
static bool dedup(uint8 index, uint64 sig)
{
	for (uint32 i = 0; i < 4; i++) {
		uint32 pos = (sig + i) % dedup_table_size;
		if (dedup_table_sig[pos] == sig && dedup_table_index[pos] == index)
			return true;
		if (dedup_table_sig[pos] == 0 || dedup_table_index[pos] != index) {
			dedup_table_index[pos] = index;
			dedup_table_sig[pos] = sig;
			return false;
		}
	}
	uint32 pos = sig % dedup_table_size;
	dedup_table_sig[pos] = sig;
	dedup_table_index[pos] = index;
	return false;
}

template <typename T>
void copyin_int(char* addr, uint64 val, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	if (bf_off == 0 && bf_len == 0) {
		*(T*)addr = swap(val, sizeof(T), bf);
		return;
	}
	T x = swap(*(T*)addr, sizeof(T), bf);
	debug_verbose("copyin_int<%zu>: old x=0x%llx\n", sizeof(T), (uint64)x);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	const uint64 shift = sizeof(T) * CHAR_BIT - bf_off - bf_len;
#else
	const uint64 shift = bf_off;
#endif
	x = (x & ~BITMASK(shift, bf_len)) | ((val << shift) & BITMASK(shift, bf_len));
	debug_verbose("copyin_int<%zu>: x=0x%llx\n", sizeof(T), (uint64)x);
	*(T*)addr = swap(x, sizeof(T), bf);
}

void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	debug_verbose("copyin: addr=%p val=0x%llx size=%llu bf=%llu bf_off=%llu bf_len=%llu\n",
		      addr, val, size, bf, bf_off, bf_len);
	if (bf != binary_format_native && bf != binary_format_bigendian && (bf_off != 0 || bf_len != 0))
		failmsg("bitmask for string format", "off=%llu, len=%llu", bf_off, bf_len);
	switch (bf) {
	case binary_format_native:
	case binary_format_bigendian:
		NONFAILING(switch (size) {
			case 1:
				copyin_int<uint8>(addr, val, bf, bf_off, bf_len);
				break;
			case 2:
				copyin_int<uint16>(addr, val, bf, bf_off, bf_len);
				break;
			case 4:
				copyin_int<uint32>(addr, val, bf, bf_off, bf_len);
				break;
			case 8:
				copyin_int<uint64>(addr, val, bf, bf_off, bf_len);
				break;
			default:
				failmsg("copyin: bad argument size", "size=%llu", size);
		});
		break;
	case binary_format_strdec:
		if (size != 20)
			failmsg("bad strdec size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "%020llu", val));
		break;
	case binary_format_strhex:
		if (size != 18)
			failmsg("bad strhex size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "0x%016llx", val));
		break;
	case binary_format_stroct:
		if (size != 23)
			failmsg("bad stroct size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "%023llo", val));
		break;
	default:
		failmsg("unknown binary format", "format=%llu", bf);
	}
}

bool copyout(char* addr, uint64 size, uint64* res)
{
	return NONFAILING(
	    switch (size) {
		    case 1:
			    *res = *(uint8*)addr;
			    break;
		    case 2:
			    *res = *(uint16*)addr;
			    break;
		    case 4:
			    *res = *(uint32*)addr;
			    break;
		    case 8:
			    *res = *(uint64*)addr;
			    break;
		    default:
			    failmsg("copyout: bad argument size", "size=%llu", size);
	    });
}

uint64 read_arg(uint8** input_posp)
{
	uint64 typ = read_input(input_posp);
	switch (typ) {
	case arg_const: {
		uint64 size, bf, bf_off, bf_len;
		uint64 val = read_const_arg(input_posp, &size, &bf, &bf_off, &bf_len);
		if (bf != binary_format_native && bf != binary_format_bigendian)
			failmsg("bad argument binary format", "format=%llu", bf);
		if (bf_off != 0 || bf_len != 0)
			failmsg("bad argument bitfield", "off=%llu, len=%llu", bf_off, bf_len);
		return swap(val, size, bf);
	}
	case arg_addr32:
	case arg_addr64: {
		return read_input(input_posp) + SYZ_DATA_OFFSET;
	}
	case arg_result: {
		uint64 meta = read_input(input_posp);
		uint64 bf = meta >> 8;
		if (bf != binary_format_native)
			failmsg("bad result argument format", "format=%llu", bf);
		return read_result(input_posp);
	}
	default:
		failmsg("bad argument type", "type=%llu", typ);
	}
}

uint64 swap(uint64 v, uint64 size, uint64 bf)
{
	if (bf == binary_format_native)
		return v;
	if (bf != binary_format_bigendian)
		failmsg("bad binary format in swap", "format=%llu", bf);
	switch (size) {
	case 2:
		return htobe16(v);
	case 4:
		return htobe32(v);
	case 8:
		return htobe64(v);
	default:
		failmsg("bad big-endian int size", "size=%llu", size);
	}
}

uint64 read_const_arg(uint8** input_posp, uint64* size_p, uint64* bf_p, uint64* bf_off_p, uint64* bf_len_p)
{
	uint64 meta = read_input(input_posp);
	uint64 val = read_input(input_posp);
	*size_p = meta & 0xff;
	uint64 bf = (meta >> 8) & 0xff;
	*bf_off_p = (meta >> 16) & 0xff;
	*bf_len_p = (meta >> 24) & 0xff;
	uint64 pid_stride = meta >> 32;
	val += pid_stride * procid;
	*bf_p = bf;
	return val;
}

uint64 read_result(uint8** input_posp)
{
	uint64 idx = read_input(input_posp);
	uint64 op_div = read_input(input_posp);
	uint64 op_add = read_input(input_posp);
	uint64 arg = read_input(input_posp);
	if (idx >= kMaxCommands)
		failmsg("command refers to bad result", "result=%lld", idx);
	if (results[idx].executed) {
		arg = results[idx].val;
		if (op_div != 0)
			arg = arg / op_div;
		arg += op_add;
	}
	return arg;
}

uint64 read_input(uint8** input_posp, bool peek)
{
	uint64 v = 0;
	unsigned shift = 0;
	uint8* input_pos = *input_posp;
	for (int i = 0;; i++, shift += 7) {
		const int maxLen = 10;
		if (i == maxLen)
			failmsg("varint overflow", "pos=%zu", (size_t)(*input_posp - input_data));
		if (input_pos >= input_data + kMaxInput)
			failmsg("input command overflows input", "pos=%p: [%p:%p)",
				input_pos, input_data, input_data + kMaxInput);
		uint8 b = *input_pos++;
		v |= uint64(b & 0x7f) << shift;
		if (b < 0x80) {
			if (i == maxLen - 1 && b > 1)
				failmsg("varint overflow", "pos=%zu", (size_t)(*input_posp - input_data));
			break;
		}
	}
	if (v & 1)
		v = ~(v >> 1);
	else
		v = v >> 1;
	if (!peek)
		*input_posp = input_pos;
	return v;
}

rpc::ComparisonRaw convert(const kcov_comparison_t& cmp)
{
	if (cmp.type > (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK))
		failmsg("invalid kcov comp type", "type=%llx", cmp.type);
	uint64 arg1 = cmp.arg1;
	uint64 arg2 = cmp.arg2;
	// Comparisons with 0 are not interesting, fuzzer should be able to guess 0's without help.
	if (arg1 == 0 && (arg2 == 0 || (cmp.type & KCOV_CMP_CONST)))
		return {};
	// Successful comparison is not interesting.
	if (arg1 == arg2)
		return {};

	// This can be a pointer (assuming 64-bit kernel).
	// First of all, we want avert fuzzer from our output region.
	// Without this fuzzer manages to discover and corrupt it.
	uint64 out_start = (uint64)output_data;
	uint64 out_end = out_start + output_size;
	if (arg1 >= out_start && arg1 <= out_end)
		return {};
	if (arg2 >= out_start && arg2 <= out_end)
		return {};
	if (!coverage_filter(cmp.pc))
		return {};

	// KCOV converts all arguments of size x first to uintx_t and then to uint64.
	// We want to properly extend signed values, e.g we want int8 c = 0xfe to be represented
	// as 0xfffffffffffffffe. Note that uint8 c = 0xfe will be represented the same way.
	// This is ok because during hints processing we will anyways try the value 0x00000000000000fe.
	switch (cmp.type & KCOV_CMP_SIZE_MASK) {
	case KCOV_CMP_SIZE1:
		arg1 = (uint64)(long long)(signed char)arg1;
		arg2 = (uint64)(long long)(signed char)arg2;
		break;
	case KCOV_CMP_SIZE2:
		arg1 = (uint64)(long long)(short)arg1;
		arg2 = (uint64)(long long)(short)arg2;
		break;
	case KCOV_CMP_SIZE4:
		arg1 = (uint64)(long long)(int)arg1;
		arg2 = (uint64)(long long)(int)arg2;
		break;
	}

	// Prog package expects operands in the opposite order (first operand may come from the input,
	// the second operand was computed in the kernel), so swap operands.
	return {cmp.pc, arg2, arg1, !!(cmp.type & KCOV_CMP_CONST)};
}

void failmsg(const char* err, const char* msg, ...)
{
	int e = errno;
	fprintf(stderr, "SYZFAIL: %s\n", err);
	if (msg) {
		va_list args;
		va_start(args, msg);
		vfprintf(stderr, msg, args);
		va_end(args);
	}
	fprintf(stderr, " (errno %d: %s)\n", e, strerror(e));

	// fail()'s are often used during the validation of kernel reactions to queries
	// that were issued by pseudo syscalls implementations. As fault injection may
	// cause the kernel not to succeed in handling these queries (e.g. socket writes
	// or reads may fail), this could ultimately lead to unwanted "lost connection to
	// test machine" crashes.
	// In order to avoid this and, on the other hand, to still have the ability to
	// signal a disastrous situation, the exit code of this function depends on the
	// current context.
	// All fail() invocations during system call execution with enabled fault injection
	// lead to termination with zero exit code. In all other cases, the exit code is
	// kFailStatus.
	if (current_thread && current_thread->soft_fail_state)
		doexit(0);
	doexit(kFailStatus);
}

void fail(const char* err)
{
	failmsg(err, 0);
}

void exitf(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(1);
}

void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	int err = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
	errno = err;
}

void debug_dump_data(const char* data, int length)
{
	if (!flag_debug)
		return;
	int i = 0;
	for (; i < length; i++) {
		debug("%02x ", data[i] & 0xff);
		if (i % 16 == 15)
			debug("\n");
	}
	if (i % 16 != 0)
		debug("\n");
}
