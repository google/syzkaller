// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

// Currently this is unused (included only to test building).
#include "pkg/flatrpc/flatrpc.h"

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

#if !GOOS_windows
#include <unistd.h>
#endif

#include "defs.h"

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

// uint64 is impossible to printf without using the clumsy and verbose "%" PRId64.
// So we define and use uint64. Note: pkg/csource does s/uint64/uint64/.
// Also define uint32/16/8 for consistency.
typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

// exit/_exit do not necessary work (e.g. if fuzzer sets seccomp filter that prohibits exit_group).
// Use doexit instead.  We must redefine exit to something that exists in stdlib,
// because some standard libraries contain "using ::exit;", but has different signature.
#define exit vsnprintf

// Dynamic memory allocation reduces test reproducibility across different libc versions and kernels.
// malloc will cause unspecified number of additional mmap's at unspecified locations.
// For small objects prefer stack allocations, for larger -- either global objects (this may have
// issues with concurrency), or controlled mmaps, or make the fuzzer allocate memory.
#define malloc do_not_use_malloc
#define calloc do_not_use_calloc

// Note: zircon max fd is 256.
// Some common_OS.h files know about this constant for RLIMIT_NOFILE.
const int kMaxFd = 250;
const int kMaxThreads = 32;
const int kInPipeFd = kMaxFd - 1; // remapped from stdin
const int kOutPipeFd = kMaxFd - 2; // remapped from stdout
const int kCoverFd = kOutPipeFd - kMaxThreads;
const int kExtraCoverFd = kCoverFd - 1;
const int kMaxArgs = 9;
const int kCoverSize = 256 << 10;
const int kFailStatus = 67;

// Two approaches of dealing with kcov memory.
const int kCoverOptimizedCount = 12; // the number of kcov instances to be opened inside main()
const int kCoverOptimizedPreMmap = 3; // this many will be mmapped inside main(), others - when needed.
const int kCoverDefaultCount = 6; // otherwise we only init kcov instances inside main()

// Logical error (e.g. invalid input program), use as an assert() alternative.
// If such error happens 10+ times in a row, it will be detected as a bug by syz-fuzzer.
// syz-fuzzer will fail and syz-manager will create a bug for this.
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
static void reply_execute(int status);

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void receive_handshake();
static void reply_handshake();
#endif

#if SYZ_EXECUTOR_USES_SHMEM
// The output region is the only thing in executor process for which consistency matters.
// If it is corrupted ipc package will fail to parse its contents and panic.
// But fuzzer constantly invents new ways of how to corrupt the region,
// so we map the region at a (hopefully) hard to guess address with random offset,
// surrounded by unmapped pages.
// The address chosen must also work on 32-bit kernels with 1GB user address space.
const uint64 kOutputBase = 0x1b2bc20000ull;

#if SYZ_EXECUTOR_USES_FORK_SERVER
// Allocating (and forking) virtual memory for each executed process is expensive, so we only mmap
// the amount we might possibly need for the specific received prog.
const int kMaxOutputComparisons = 14 << 20; // executions with comparsions enabled are usually < 1% of all executions
const int kMaxOutputCoverage = 6 << 20; // coverage is needed in ~ up to 1/3 of all executions (depending on corpus rotation)
const int kMaxOutputSignal = 4 << 20;
const int kMinOutput = 256 << 10; // if we don't need to send signal, the output is rather short.
const int kInitialOutput = kMinOutput; // the minimal size to be allocated in the parent process
#else
// We don't fork and allocate the memory only once, so prepare for the worst case.
const int kInitialOutput = 14 << 20;
#endif

// TODO: allocate a smaller amount of memory in the parent once we merge the patches that enable
// prog execution with neither signal nor coverage. Likely 64kb will be enough in that case.

const int kInFd = 3;
const int kOutFd = 4;
static uint32* output_data;
static uint32* output_pos;
static int output_size;
static void mmap_output(int size);
static uint32* write_output(uint32 v);
static uint32* write_output_64(uint64 v);
static void write_completed(uint32 completed);
static uint32 hash(uint32 a);
static bool dedup(uint32 sig);
#endif // if SYZ_EXECUTOR_USES_SHMEM

uint64 start_time_ms = 0;

static bool flag_debug;
static bool flag_coverage;
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
static bool flag_coverage_filter;

// If true, then executor should write the comparisons data to fuzzer.
static bool flag_comparisons;

// Tunable timeouts, received with execute_req.
static uint64 syscall_timeout_ms;
static uint64 program_timeout_ms;
static uint64 slowdown_scale;

// Can be used to disginguish whether we're at the initialization stage
// or we already execute programs.
static bool in_execute_one = false;

#define SYZ_EXECUTOR 1
#include "common.h"

const int kMaxInput = 4 << 20; // keep in sync with prog.ExecBufferSize
const int kMaxCommands = 1000; // prog package knows about this constant (prog.execMaxCommands)

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
uint32 completed;
bool is_kernel_64_bit = true;

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
	uint32 mmap_alloc_size;
	char* data;
	char* data_end;
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
const uint32 kOutMagic = 0xbadf00d;

struct handshake_req {
	uint64 magic;
	uint64 flags; // env flags
	uint64 pid;
	uint64 sandbox_arg;
};

struct handshake_reply {
	uint32 magic;
};

struct execute_req {
	uint64 magic;
	uint64 env_flags;
	uint64 exec_flags;
	uint64 pid;
	uint64 syscall_timeout_ms;
	uint64 program_timeout_ms;
	uint64 slowdown_scale;
	uint64 prog_size;
};

struct execute_reply {
	uint32 magic;
	uint32 done;
	uint32 status;
};

// call_reply.flags
const uint32 call_flag_executed = 1 << 0;
const uint32 call_flag_finished = 1 << 1;
const uint32 call_flag_blocked = 1 << 2;
const uint32 call_flag_fault_injected = 1 << 3;

struct call_reply {
	execute_reply header;
	uint32 magic;
	uint32 call_index;
	uint32 call_num;
	uint32 reserrno;
	uint32 flags;
	uint32 signal_size;
	uint32 cover_size;
	uint32 comps_size;
	// signal/cover/comps follow
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

	bool ignore() const;
	void write();
	bool operator==(const struct kcov_comparison_t& other) const;
	bool operator<(const struct kcov_comparison_t& other) const;
};

typedef char kcov_comparison_size[sizeof(kcov_comparison_t) == 4 * sizeof(uint64) ? 1 : -1];

struct feature_t {
	rpc::Feature id;
	void (*setup)();
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
static void setup_features(char** enable, int n);

#include "syscalls.h"

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

#include "cov_filter.h"

#include "test.h"

#if SYZ_HAVE_SANDBOX_ANDROID
static uint64 sandbox_arg = 0;
#endif

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "setup") == 0) {
		setup_features(argv + 2, argc - 2);
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "leak") == 0) {
#if SYZ_HAVE_LEAK_CHECK
		check_leaks(argv + 2, argc - 2);
#else
		fail("leak checking is not implemented");
#endif
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "setup_kcsan_filterlist") == 0) {
#if SYZ_HAVE_KCSAN
		setup_kcsan_filterlist(argv + 2, argc - 2, true);
#else
		fail("KCSAN is not implemented");
#endif
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "test") == 0)
		return run_tests();

	if (argc < 2 || strcmp(argv[1], "exec") != 0) {
		fprintf(stderr, "unknown command");
		return 1;
	}

	start_time_ms = current_time_ms();

	os_init(argc, argv, (char*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);
	current_thread = &threads[0];

#if SYZ_EXECUTOR_USES_SHMEM
	void* mmap_out = mmap(NULL, kMaxInput, PROT_READ, MAP_PRIVATE, kInFd, 0);
#else
	void* mmap_out = mmap(NULL, kMaxInput, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
#endif
	if (mmap_out == MAP_FAILED)
		fail("mmap of input file failed");
	input_data = static_cast<uint8*>(mmap_out);

#if SYZ_EXECUTOR_USES_SHMEM
	mmap_output(kInitialOutput);
	// Prevent test programs to mess with these fds.
	// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
	// which will cause fuzzer to crash.
	close(kInFd);
#if !SYZ_EXECUTOR_USES_FORK_SERVER
	close(kOutFd);
#endif
	// For SYZ_EXECUTOR_USES_FORK_SERVER, close(kOutFd) is invoked in the forked child,
	// after the program has been received.
#endif // if  SYZ_EXECUTOR_USES_SHMEM

	use_temporary_dir();
	install_segv_handler();
	setup_control_pipes();
#if SYZ_EXECUTOR_USES_FORK_SERVER
	receive_handshake();
#else
	receive_execute();
#endif
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
		char sep = '/';
#if GOOS_windows
		sep = '\\';
#endif
		char filename[1024] = {0};
		char* end = strrchr(argv[0], sep);
		size_t len = end - argv[0];
		strncpy(filename, argv[0], len + 1);
		strncat(filename, "syz-cover-bitmap", 17);
		filename[sizeof(filename) - 1] = '\0';
		init_coverage_filter(filename);
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
	// Other statuses happen when fuzzer processes manages to kill loop, e.g. with:
	// ptrace(PTRACE_SEIZE, 1, 0, 0x100040)
	if (status != kFailStatus)
		status = 0;
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

#if SYZ_EXECUTOR_USES_SHMEM
// This method can be invoked as many times as one likes - MMAP_FIXED can overwrite the previous
// mapping without any problems. The only precondition - kOutFd must not be closed.
static void mmap_output(int size)
{
	if (size <= output_size)
		return;
	if (size % SYZ_PAGE_SIZE != 0)
		failmsg("trying to mmap output area that is not divisible by page size", "page=%d,area=%d", SYZ_PAGE_SIZE, size);
	uint32* mmap_at = NULL;
	if (output_data == NULL) {
		// It's the first time we map output region - generate its location.
		output_data = mmap_at = (uint32*)(kOutputBase + (1 << 20) * (getpid() % 128));
	} else {
		// We are expanding the mmapped region. Adjust the parameters to avoid mmapping already
		// mmapped area as much as possible.
		// There exists a mremap call that could have helped, but it's purely Linux-specific.
		mmap_at = (uint32*)((char*)(output_data) + output_size);
	}
	void* result = mmap(mmap_at, size - output_size,
			    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, output_size);
	if (result != mmap_at)
		failmsg("mmap of output file failed", "want %p, got %p", mmap_at, result);
	output_size = size;
}
#endif

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

void parse_env_flags(uint64 flags)
{
	// Note: Values correspond to ordering in pkg/ipc/ipc.go, e.g. FlagSandboxNamespace
	flag_debug = flags & (1 << 0);
	flag_coverage = flags & (1 << 1);
	if (flags & (1 << 2))
		flag_sandbox_setuid = true;
	else if (flags & (1 << 3))
		flag_sandbox_namespace = true;
	else if (flags & (1 << 4))
		flag_sandbox_android = true;
	else
		flag_sandbox_none = true;
	flag_extra_coverage = flags & (1 << 5);
	flag_net_injection = flags & (1 << 6);
	flag_net_devices = flags & (1 << 7);
	flag_net_reset = flags & (1 << 8);
	flag_cgroups = flags & (1 << 9);
	flag_close_fds = flags & (1 << 10);
	flag_devlink_pci = flags & (1 << 11);
	flag_vhci_injection = flags & (1 << 12);
	flag_wifi = flags & (1 << 13);
	flag_delay_kcov_mmap = flags & (1 << 14);
	flag_nic_vf = flags & (1 << 15);
}

#if SYZ_EXECUTOR_USES_FORK_SERVER
void receive_handshake()
{
	handshake_req req = {};
	int n = read(kInPipeFd, &req, sizeof(req));
	if (n != sizeof(req))
		failmsg("handshake read failed", "read=%d", n);
	if (req.magic != kInMagic)
		failmsg("bad handshake magic", "magic=0x%llx", req.magic);
#if SYZ_HAVE_SANDBOX_ANDROID
	sandbox_arg = req.sandbox_arg;
#endif
	parse_env_flags(req.flags);
	procid = req.pid;
}

void reply_handshake()
{
	handshake_reply reply = {};
	reply.magic = kOutMagic;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}
#endif

static execute_req last_execute_req;

void receive_execute()
{
	execute_req& req = last_execute_req;
	if (read(kInPipeFd, &req, sizeof(req)) != (ssize_t)sizeof(req))
		fail("control pipe read failed");
	if (req.magic != kInMagic)
		failmsg("bad execute request magic", "magic=0x%llx", req.magic);
	if (req.prog_size > kMaxInput)
		failmsg("bad execute prog size", "size=0x%llx", req.prog_size);
	parse_env_flags(req.env_flags);
	procid = req.pid;
	syscall_timeout_ms = req.syscall_timeout_ms;
	program_timeout_ms = req.program_timeout_ms;
	slowdown_scale = req.slowdown_scale;
	flag_collect_signal = req.exec_flags & (1 << 0);
	flag_collect_cover = req.exec_flags & (1 << 1);
	flag_dedup_cover = req.exec_flags & (1 << 2);
	flag_comparisons = req.exec_flags & (1 << 3);
	flag_threaded = req.exec_flags & (1 << 4);
	flag_coverage_filter = req.exec_flags & (1 << 5);

	debug("[%llums] exec opts: procid=%llu threaded=%d cover=%d comps=%d dedup=%d signal=%d"
	      " timeouts=%llu/%llu/%llu prog=%llu filter=%d\n",
	      current_time_ms() - start_time_ms, procid, flag_threaded, flag_collect_cover,
	      flag_comparisons, flag_dedup_cover, flag_collect_signal, syscall_timeout_ms,
	      program_timeout_ms, slowdown_scale, req.prog_size, flag_coverage_filter);
	if (syscall_timeout_ms == 0 || program_timeout_ms <= syscall_timeout_ms || slowdown_scale == 0)
		failmsg("bad timeouts", "syscall=%llu, program=%llu, scale=%llu",
			syscall_timeout_ms, program_timeout_ms, slowdown_scale);
	if (SYZ_EXECUTOR_USES_SHMEM) {
		if (req.prog_size)
			fail("need_prog: no program");
		return;
	}
	if (req.prog_size == 0)
		fail("need_prog: no program");
	uint64 pos = 0;
	for (;;) {
		ssize_t rv = read(kInPipeFd, input_data + pos, kMaxInput - pos);
		if (rv < 0)
			fail("read failed");
		pos += rv;
		if (rv == 0 || pos >= req.prog_size)
			break;
	}
	if (pos != req.prog_size)
		failmsg("bad input size", "size=%lld, want=%lld", pos, req.prog_size);
}

bool cover_collection_required()
{
	return flag_coverage && (flag_collect_signal || flag_collect_cover || flag_comparisons);
}

void reply_execute(int status)
{
	execute_reply reply = {};
	reply.magic = kOutMagic;
	reply.done = true;
	reply.status = status;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}

#if SYZ_EXECUTOR_USES_SHMEM
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
#endif // if SYZ_EXECUTOR_USES_SHMEM

// execute_one executes program stored in input_data.
void execute_one()
{
	in_execute_one = true;
#if SYZ_EXECUTOR_USES_SHMEM
	realloc_output_data();
	output_pos = output_data;
	write_output(0); // Number of executed syscalls (updated later).
#endif // if SYZ_EXECUTOR_USES_SHMEM
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
	// Check for new extra coverage in small intervals to avoid situation
	// that we were killed on timeout before we write any.
	// Check for extra coverage is very cheap, effectively a memory load.
	const uint64 kSleepMs = 100;
	for (uint64 i = 0; i < prog_extra_cover_timeout / kSleepMs; i++) {
		sleep_ms(kSleepMs);
		write_extra_output();
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

#if SYZ_EXECUTOR_USES_SHMEM
template <typename cover_data_t>
void write_coverage_signal(cover_t* cov, uint32* signal_count_pos, uint32* cover_count_pos)
{
	// Write out feedback signals.
	// Currently it is code edges computed as xor of two subsequent basic block PCs.
	cover_data_t* cover_data = (cover_data_t*)(cov->data + cov->data_offset);
	if (flag_collect_signal) {
		uint32 nsig = 0;
		cover_data_t prev_pc = 0;
		bool prev_filter = true;
		for (uint32 i = 0; i < cov->size; i++) {
			cover_data_t pc = cover_data[i] + cov->pc_offset;
			uint64 sig = pc & 0xFFFFFFFFFFFFF000;
			if (use_cover_edges(pc)) {
				// Only hash the lower 12 bits so the hash is
				// independent of any module offsets.
				sig |= (pc & 0xFFF) ^ (hash(prev_pc & 0xFFF) & 0xFFF);
			}
			bool filter = coverage_filter(pc);
			// Ignore the edge only if both current and previous PCs are filtered out
			// to capture all incoming and outcoming edges into the interesting code.
			bool ignore = !filter && !prev_filter;
			prev_pc = pc;
			prev_filter = filter;
			if (ignore || dedup(sig))
				continue;
			write_output_64(sig);
			nsig++;
		}
		// Write out number of signals.
		*signal_count_pos = nsig;
	}

	if (flag_collect_cover) {
		// Write out real coverage (basic block PCs).
		uint32 cover_size = cov->size;
		if (flag_dedup_cover) {
			cover_data_t* end = cover_data + cover_size;
			cover_unprotect(cov);
			std::sort(cover_data, end);
			cover_size = std::unique(cover_data, end) - cover_data;
			cover_protect(cov);
		}
		// Always sent uint64 PCs.
		for (uint32 i = 0; i < cover_size; i++)
			write_output_64(cover_data[i] + cov->pc_offset);
		*cover_count_pos = cover_size;
	}
}
#endif // if SYZ_EXECUTOR_USES_SHMEM

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

void write_call_output(thread_t* th, bool finished)
{
	uint32 reserrno = ENOSYS;
	const bool blocked = finished && th != last_scheduled;
	uint32 call_flags = call_flag_executed | (blocked ? call_flag_blocked : 0);
	if (finished) {
		reserrno = th->res != -1 ? 0 : th->reserrno;
		call_flags |= call_flag_finished |
			      (th->fault_injected ? call_flag_fault_injected : 0);
	}
#if SYZ_EXECUTOR_USES_SHMEM
	write_output(kOutMagic);
	write_output(th->call_index);
	write_output(th->call_num);
	write_output(reserrno);
	write_output(call_flags);
	uint32* signal_count_pos = write_output(0); // filled in later
	uint32* cover_count_pos = write_output(0); // filled in later
	uint32* comps_count_pos = write_output(0); // filled in later

	if (flag_comparisons) {
		// Collect only the comparisons
		uint32 ncomps = th->cov.size;
		kcov_comparison_t* start = (kcov_comparison_t*)(th->cov.data + sizeof(uint64));
		kcov_comparison_t* end = start + ncomps;
		if ((char*)end > th->cov.data_end)
			failmsg("too many comparisons", "ncomps=%u", ncomps);
		cover_unprotect(&th->cov);
		std::sort(start, end);
		ncomps = std::unique(start, end) - start;
		cover_protect(&th->cov);
		uint32 comps_size = 0;
		for (uint32 i = 0; i < ncomps; ++i) {
			if (start[i].ignore())
				continue;
			comps_size++;
			start[i].write();
		}
		// Write out number of comparisons.
		*comps_count_pos = comps_size;
	} else if (flag_collect_signal || flag_collect_cover) {
		if (is_kernel_64_bit)
			write_coverage_signal<uint64>(&th->cov, signal_count_pos, cover_count_pos);
		else
			write_coverage_signal<uint32>(&th->cov, signal_count_pos, cover_count_pos);
	}
	debug_verbose("out #%u: index=%u num=%u errno=%d finished=%d blocked=%d sig=%u cover=%u comps=%u\n",
		      completed, th->call_index, th->call_num, reserrno, finished, blocked,
		      *signal_count_pos, *cover_count_pos, *comps_count_pos);
	completed++;
	write_completed(completed);
#else
	call_reply reply;
	reply.header.magic = kOutMagic;
	reply.header.done = 0;
	reply.header.status = 0;
	reply.magic = kOutMagic;
	reply.call_index = th->call_index;
	reply.call_num = th->call_num;
	reply.reserrno = reserrno;
	reply.flags = call_flags;
	reply.signal_size = 0;
	reply.cover_size = 0;
	reply.comps_size = 0;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe call write failed");
	debug_verbose("out: index=%u num=%u errno=%d finished=%d blocked=%d\n",
		      th->call_index, th->call_num, reserrno, finished, blocked);
#endif // if SYZ_EXECUTOR_USES_SHMEM
}

void write_extra_output()
{
#if SYZ_EXECUTOR_USES_SHMEM
	if (!cover_collection_required() || !flag_extra_coverage || flag_comparisons)
		return;
	cover_collect(&extra_cov);
	if (!extra_cov.size)
		return;
	write_output(kOutMagic);
	write_output(-1); // call index
	write_output(-1); // call num
	write_output(999); // errno
	write_output(0); // call flags
	uint32* signal_count_pos = write_output(0); // filled in later
	uint32* cover_count_pos = write_output(0); // filled in later
	write_output(0); // comps_count_pos
	if (is_kernel_64_bit)
		write_coverage_signal<uint64>(&extra_cov, signal_count_pos, cover_count_pos);
	else
		write_coverage_signal<uint32>(&extra_cov, signal_count_pos, cover_count_pos);
	cover_reset(&extra_cov);
	debug_verbose("extra: sig=%u cover=%u\n", *signal_count_pos, *cover_count_pos);
	completed++;
	write_completed(completed);
#endif // if SYZ_EXECUTOR_USES_SHMEM
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
	if (cover_collection_required())
		cover_enable(&th->cov, flag_comparisons, false);
	for (;;) {
		event_wait(&th->ready);
		event_reset(&th->ready);
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

	if (flag_coverage) {
		cover_collect(&th->cov);
		if (th->cov.size >= kCoverSize)
			failmsg("too much cover", "thr=%d, cov=%u", th->id, th->cov.size);
	}
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

#if SYZ_EXECUTOR_USES_SHMEM
static uint32 hash(uint32 a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}

const uint32 dedup_table_size = 8 << 10;
uint64 dedup_table[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
// The hashmap is global which means that we deduplicate across different calls.
// This is OK because we are interested only in new signals.
static bool dedup(uint32 sig)
{
	for (uint32 i = 0; i < 4; i++) {
		uint32 pos = (sig + i) % dedup_table_size;
		if (dedup_table[pos] == sig)
			return true;
		if (dedup_table[pos] == 0) {
			dedup_table[pos] = sig;
			return false;
		}
	}
	dedup_table[sig % dedup_table_size] = sig;
	return false;
}
#endif // if SYZ_EXECUTOR_USES_SHMEM

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
	debug_verbose("copyin_int<%zu>: new x=0x%llx\n", sizeof(T), (uint64)x);
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
			failmsg("varint overflow", "pos=%zu", *input_posp - input_data);
		if (input_pos >= input_data + kMaxInput)
			failmsg("input command overflows input", "pos=%p: [%p:%p)",
				input_pos, input_data, input_data + kMaxInput);
		uint8 b = *input_pos++;
		v |= uint64(b & 0x7f) << shift;
		if (b < 0x80) {
			if (i == maxLen - 1 && b > 1)
				failmsg("varint overflow", "pos=%zu", *input_posp - input_data);
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

#if SYZ_EXECUTOR_USES_SHMEM
uint32* write_output(uint32 v)
{
	if (output_pos < output_data || (char*)output_pos >= (char*)output_data + output_size)
		failmsg("output overflow", "pos=%p region=[%p:%p]",
			output_pos, output_data, (char*)output_data + output_size);
	*output_pos = v;
	return output_pos++;
}

uint32* write_output_64(uint64 v)
{
	if (output_pos < output_data || (char*)(output_pos + 1) >= (char*)output_data + output_size)
		failmsg("output overflow", "pos=%p region=[%p:%p]",
			output_pos, output_data, (char*)output_data + output_size);
	*(uint64*)output_pos = v;
	output_pos += 2;
	return output_pos;
}

void write_completed(uint32 completed)
{
	__atomic_store_n(output_data, completed, __ATOMIC_RELEASE);
}
#endif // if SYZ_EXECUTOR_USES_SHMEM

#if SYZ_EXECUTOR_USES_SHMEM
void kcov_comparison_t::write()
{
	if (type > (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK))
		failmsg("invalid kcov comp type", "type=%llx", type);

	// Write order: type arg1 arg2 pc.
	write_output((uint32)type);

	// KCOV converts all arguments of size x first to uintx_t and then to
	// uint64. We want to properly extend signed values, e.g we want
	// int8 c = 0xfe to be represented as 0xfffffffffffffffe.
	// Note that uint8 c = 0xfe will be represented the same way.
	// This is ok because during hints processing we will anyways try
	// the value 0x00000000000000fe.
	switch (type & KCOV_CMP_SIZE_MASK) {
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
	bool is_size_8 = (type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8;
	if (!is_size_8) {
		write_output((uint32)arg1);
		write_output((uint32)arg2);
	} else {
		write_output_64(arg1);
		write_output_64(arg2);
	}
}

bool kcov_comparison_t::ignore() const
{
	// Comparisons with 0 are not interesting, fuzzer should be able to guess 0's without help.
	if (arg1 == 0 && (arg2 == 0 || (type & KCOV_CMP_CONST)))
		return true;
	if ((type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8) {
		// This can be a pointer (assuming 64-bit kernel).
		// First of all, we want avert fuzzer from our output region.
		// Without this fuzzer manages to discover and corrupt it.
		uint64 out_start = (uint64)output_data;
		uint64 out_end = out_start + output_size;
		if (arg1 >= out_start && arg1 <= out_end)
			return true;
		if (arg2 >= out_start && arg2 <= out_end)
			return true;
#if defined(GOOS_linux)
		// Filter out kernel physical memory addresses.
		// These are internal kernel comparisons and should not be interesting.
		// The range covers first 1TB of physical mapping.
		uint64 kmem_start = (uint64)0xffff880000000000ull;
		uint64 kmem_end = (uint64)0xffff890000000000ull;
		bool kptr1 = arg1 >= kmem_start && arg1 <= kmem_end;
		bool kptr2 = arg2 >= kmem_start && arg2 <= kmem_end;
		if (kptr1 && kptr2)
			return true;
		if (kptr1 && arg2 == 0)
			return true;
		if (kptr2 && arg1 == 0)
			return true;
#endif
	}
	return !coverage_filter(pc);
}

bool kcov_comparison_t::operator==(const struct kcov_comparison_t& other) const
{
	// We don't check for PC equality now, because it is not used.
	return type == other.type && arg1 == other.arg1 && arg2 == other.arg2;
}

bool kcov_comparison_t::operator<(const struct kcov_comparison_t& other) const
{
	if (type != other.type)
		return type < other.type;
	if (arg1 != other.arg1)
		return arg1 < other.arg1;
	// We don't check for PC equality now, because it is not used.
	return arg2 < other.arg2;
}
#endif // if SYZ_EXECUTOR_USES_SHMEM

#if !SYZ_HAVE_FEATURES
static feature_t features[] = {};
#endif

void setup_features(char** enable, int n)
{
	// This does any one-time setup for the requested features on the machine.
	// Note: this can be called multiple times and must be idempotent.
	flag_debug = true;
	if (n != 1)
		fail("setup: more than one feature");
	char* endptr = nullptr;
	auto feature = static_cast<rpc::Feature>(strtoull(enable[0], &endptr, 10));
	if (endptr == enable[0] || (feature > rpc::Feature::ANY) ||
	    __builtin_popcountll(static_cast<uint64>(feature)) > 1)
		failmsg("setup: failed to parse feature", "feature='%s'", enable[0]);
	if (feature == rpc::Feature::NONE) {
#if SYZ_HAVE_FEATURES
		setup_sysctl();
		setup_cgroups();
#endif
#if SYZ_HAVE_SETUP_EXT
		// This can be defined in common_ext.h.
		setup_ext();
#endif
		return;
	}
	for (size_t i = 0; i < sizeof(features) / sizeof(features[0]); i++) {
		if (features[i].id == feature) {
			features[i].setup();
			return;
		}
	}
	// Note: pkg/host knows about this error message.
	fail("feature setup is not needed");
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
