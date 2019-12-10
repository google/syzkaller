// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <algorithm>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "defs.h"

#if defined(__GNUC__)
#define SYSCALLAPI
#define NORETURN __attribute__((noreturn))
#define ALIGNED(N) __attribute__((aligned(N)))
#define PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
// Assuming windows/cl.
#define SYSCALLAPI WINAPI
#define NORETURN __declspec(noreturn)
#define ALIGNED(N) __declspec(align(N))
#define PRINTF(fmt, args)
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

// Note: zircon max fd is 256.
// Some common_OS.h files know about this constant for RLIMIT_NOFILE.
const int kMaxFd = 250;
const int kMaxThreads = 16;
const int kInPipeFd = kMaxFd - 1; // remapped from stdin
const int kOutPipeFd = kMaxFd - 2; // remapped from stdout
const int kCoverFd = kOutPipeFd - kMaxThreads;
const int kMaxArgs = 9;
const int kCoverSize = 256 << 10;
const int kFailStatus = 67;

// Logical error (e.g. invalid input program), use as an assert() alternative.
static NORETURN PRINTF(1, 2) void fail(const char* msg, ...);
// Just exit (e.g. due to temporal ENOMEM error).
static NORETURN PRINTF(1, 2) void exitf(const char* msg, ...);
static NORETURN void doexit(int status);

// Print debug output, does not add \n at the end of msg as opposed to the previous functions.
static PRINTF(1, 2) void debug(const char* msg, ...);
void debug_dump_data(const char* data, int length);

#if 0
#define debug_verbose(...) debug(__VA_ARGS__)
#else
#define debug_verbose(...) (void)0
#endif

static void receive_execute();
static void reply_execute(int status);

#if GOOS_akaros
static void resend_execute(int fd);
#endif

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void receive_handshake();
static void reply_handshake();
#endif

#if SYZ_EXECUTOR_USES_SHMEM
const int kMaxOutput = 16 << 20;
const int kInFd = 3;
const int kOutFd = 4;
static uint32* output_data;
static uint32* output_pos;
static uint32* write_output(uint32 v);
static void write_completed(uint32 completed);
static uint32 hash(uint32 a);
static bool dedup(uint32 sig);
#endif

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

static bool flag_collect_cover;
static bool flag_dedup_cover;
static bool flag_threaded;
static bool flag_collide;

// If true, then executor should write the comparisons data to fuzzer.
static bool flag_comparisons;

// Inject fault into flag_fault_nth-th operation in flag_fault_call-th syscall.
static bool flag_fault;
static int flag_fault_call;
static int flag_fault_nth;

#define SYZ_EXECUTOR 1
#include "common.h"

const int kMaxCommands = 1000;
const int kMaxInput = 2 << 20;

const uint64 instr_eof = -1;
const uint64 instr_copyin = -2;
const uint64 instr_copyout = -3;

const uint64 arg_const = 0;
const uint64 arg_result = 1;
const uint64 arg_data = 2;
const uint64 arg_csum = 3;

const uint64 binary_format_native = 0;
const uint64 binary_format_bigendian = 1;
const uint64 binary_format_strdec = 2;
const uint64 binary_format_strhex = 3;
const uint64 binary_format_stroct = 4;

const uint64 no_copyout = -1;

static int running;
static bool collide;
uint32 completed;
bool is_kernel_64_bit = true;

ALIGNED(64 << 10)
static char input_data[kMaxInput];

// Checksum kinds.
static const uint64 arg_csum_inet = 0;

// Checksum chunk kinds.
static const uint64 arg_csum_chunk_data = 0;
static const uint64 arg_csum_chunk_const = 1;

typedef intptr_t(SYSCALLAPI* syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

struct call_t {
	const char* name;
	int sys_nr;
	syscall_t call;
};

struct cover_t {
	int fd;
	uint32 size;
	char* data;
	char* data_end;
};

struct thread_t {
	int id;
	bool created;
	event_t ready;
	event_t done;
	uint64* copyout_pos;
	uint64 copyout_index;
	bool colliding;
	bool executing;
	int call_index;
	int call_num;
	int num_args;
	intptr_t args[kMaxArgs];
	intptr_t res;
	uint32 reserrno;
	bool fault_injected;
	cover_t cov;
	bool extra_cover;
};

static thread_t threads[kMaxThreads];
static thread_t* last_scheduled;

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
};

struct handshake_reply {
	uint32 magic;
};

struct execute_req {
	uint64 magic;
	uint64 env_flags;
	uint64 exec_flags;
	uint64 pid;
	uint64 fault_call;
	uint64 fault_nth;
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

struct feature_t {
	const char* name;
	void (*setup)();
};

static thread_t* schedule_call(int call_index, int call_num, bool colliding, uint64 copyout_index, uint64 num_args, uint64* args, uint64* pos, bool extra_cover);
static void handle_completion(thread_t* th);
static void copyout_call_results(thread_t* th);
static void write_call_output(thread_t* th, bool finished);
static void write_extra_output();
static void execute_call(thread_t* th);
static void thread_create(thread_t* th, int id);
static void* worker_thread(void* arg);
static uint64 read_input(uint64** input_posp, bool peek = false);
static uint64 read_arg(uint64** input_posp);
static uint64 read_const_arg(uint64** input_posp, uint64* size_p, uint64* bf, uint64* bf_off_p, uint64* bf_len_p);
static uint64 read_result(uint64** input_posp);
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
#elif GOOS_akaros
#include "executor_akaros.h"
#elif GOOS_freebsd || GOOS_netbsd || GOOS_openbsd
#include "executor_bsd.h"
#elif GOOS_windows
#include "executor_windows.h"
#elif GOOS_test
#include "executor_test.h"
#else
#error "unknown OS"
#endif

#include "test.h"

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
	if (argc >= 2 && strcmp(argv[1], "setup_kcsan_blacklist") == 0) {
#if SYZ_HAVE_KCSAN
		setup_kcsan_filterlist(argv + 2, argc - 2, /*blacklist=*/true);
#else
		fail("KCSAN is not implemented");
#endif
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "test") == 0)
		return run_tests();

	start_time_ms = current_time_ms();

	os_init(argc, argv, (void*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);

#if SYZ_EXECUTOR_USES_SHMEM
	if (mmap(&input_data[0], kMaxInput, PROT_READ, MAP_PRIVATE | MAP_FIXED, kInFd, 0) != &input_data[0])
		fail("mmap of input file failed");
	// The output region is the only thing in executor process for which consistency matters.
	// If it is corrupted ipc package will fail to parse its contents and panic.
	// But fuzzer constantly invents new ways of how to currupt the region,
	// so we map the region at a (hopefully) hard to guess address with random offset,
	// surrounded by unmapped pages.
	// The address chosen must also work on 32-bit kernels with 1GB user address space.
	void* preferred = (void*)(0x1b2bc20000ull + (1 << 20) * (getpid() % 128));
	output_data = (uint32*)mmap(preferred, kMaxOutput,
				    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0);
	if (output_data != preferred)
		fail("mmap of output file failed");

	// Prevent test programs to mess with these fds.
	// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
	// which will cause fuzzer to crash.
	close(kInFd);
	close(kOutFd);
#endif

	use_temporary_dir();
	install_segv_handler();
	setup_control_pipes();
#if SYZ_EXECUTOR_USES_FORK_SERVER
	receive_handshake();
#else
	receive_execute();
#endif
	if (flag_coverage) {
		for (int i = 0; i < kMaxThreads; i++) {
			threads[i].cov.fd = kCoverFd + i;
			cover_open(&threads[i].cov, false);
			cover_protect(&threads[i].cov);
		}
		cover_open(&extra_cov, true);
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
		status = do_sandbox_android();
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
}

#if SYZ_EXECUTOR_USES_FORK_SERVER
void receive_handshake()
{
	handshake_req req = {};
	int n = read(kInPipeFd, &req, sizeof(req));
	if (n != sizeof(req))
		fail("handshake read failed: %d", n);
	if (req.magic != kInMagic)
		fail("bad handshake magic 0x%llx", req.magic);
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
		fail("bad execute request magic 0x%llx", req.magic);
	if (req.prog_size > kMaxInput)
		fail("bad execute prog size 0x%llx", req.prog_size);
	parse_env_flags(req.env_flags);
	procid = req.pid;
	flag_collect_cover = req.exec_flags & (1 << 0);
	flag_dedup_cover = req.exec_flags & (1 << 1);
	flag_fault = req.exec_flags & (1 << 2);
	flag_comparisons = req.exec_flags & (1 << 3);
	flag_threaded = req.exec_flags & (1 << 4);
	flag_collide = req.exec_flags & (1 << 5);
	flag_fault_call = req.fault_call;
	flag_fault_nth = req.fault_nth;
	if (!flag_threaded)
		flag_collide = false;
	debug("[%llums] exec opts: procid=%llu threaded=%d collide=%d cover=%d comps=%d dedup=%d fault=%d/%d/%d prog=%llu\n",
	      current_time_ms() - start_time_ms, procid, flag_threaded, flag_collide,
	      flag_collect_cover, flag_comparisons, flag_dedup_cover, flag_fault,
	      flag_fault_call, flag_fault_nth, req.prog_size);
	if (SYZ_EXECUTOR_USES_SHMEM) {
		if (req.prog_size)
			fail("need_prog: no program");
		return;
	}
	if (req.prog_size == 0)
		fail("need_prog: no program");
	uint64 pos = 0;
	for (;;) {
		ssize_t rv = read(kInPipeFd, input_data + pos, sizeof(input_data) - pos);
		if (rv < 0)
			fail("read failed");
		pos += rv;
		if (rv == 0 || pos >= req.prog_size)
			break;
	}
	if (pos != req.prog_size)
		fail("bad input size %lld, want %lld", pos, req.prog_size);
}

#if GOOS_akaros
void resend_execute(int fd)
{
	execute_req& req = last_execute_req;
	if (write(fd, &req, sizeof(req)) != sizeof(req))
		fail("child pipe header write failed");
	if (write(fd, input_data, req.prog_size) != (ssize_t)req.prog_size)
		fail("child pipe program write failed");
}
#endif

void reply_execute(int status)
{
	execute_reply reply = {};
	reply.magic = kOutMagic;
	reply.done = true;
	reply.status = status;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}

// execute_one executes program stored in input_data.
void execute_one()
{
	// Duplicate global collide variable on stack.
	// Fuzzer once come up with ioctl(fd, FIONREAD, 0x920000),
	// where 0x920000 was exactly collide address, so every iteration reset collide to 0.
	bool colliding = false;
#if SYZ_EXECUTOR_USES_SHMEM
	output_pos = output_data;
	write_output(0); // Number of executed syscalls (updated later).
#endif
	uint64 start = current_time_ms();

retry:
	uint64* input_pos = (uint64*)input_data;

	if (flag_coverage && !colliding) {
		if (!flag_threaded)
			cover_enable(&threads[0].cov, flag_comparisons, false);
		if (flag_extra_coverage)
			cover_reset(&extra_cov);
	}

	int call_index = 0;
	bool prog_extra_cover = false;
	int prog_extra_timeout = 0;
	for (;;) {
		uint64 call_num = read_input(&input_pos);
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)read_input(&input_pos);
			uint64 typ = read_input(&input_pos);
			switch (typ) {
			case arg_const: {
				uint64 size, bf, bf_off, bf_len;
				uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
				copyin(addr, arg, size, bf, bf_off, bf_len);
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
				NONFAILING(memcpy(addr, input_pos, size));
				// Read out the data.
				for (uint64 i = 0; i < (size + 7) / 8; i++)
					read_input(&input_pos);
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
						fail("inet checksum must be 2 bytes, not %llu", size);
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
							debug_verbose("#%lld: data chunk, addr: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							NONFAILING(csum_inet_update(&csum, (const uint8*)chunk_value, chunk_size));
							break;
						case arg_csum_chunk_const:
							if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8) {
								fail("bad checksum const chunk size %lld\n", chunk_size);
							}
							// Here we assume that const values come to us big endian.
							debug_verbose("#%lld: const chunk, value: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							csum_inet_update(&csum, (const uint8*)&chunk_value, chunk_size);
							break;
						default:
							fail("bad checksum chunk kind %llu", chunk_kind);
						}
					}
					uint16 csum_value = csum_inet_digest(&csum);
					debug_verbose("writing inet checksum %hx to %p\n", csum_value, csum_addr);
					copyin(csum_addr, csum_value, 2, binary_format_native, 0, 0);
					break;
				}
				default:
					fail("bad checksum kind %llu", csum_kind);
				}
				break;
			}
			default:
				fail("bad argument type %llu", typ);
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

		// Normal syscall.
		if (call_num >= ARRAY_SIZE(syscalls))
			fail("invalid command number %llu", call_num);
		bool call_extra_cover = false;
		// call_extra_timeout must match timeout in pkg/csource/csource.go.
		int call_extra_timeout = 0;
		// TODO: find a way to tune timeout values.
		if (strncmp(syscalls[call_num].name, "syz_usb", strlen("syz_usb")) == 0) {
			prog_extra_cover = true;
			call_extra_cover = true;
		}
		if (strncmp(syscalls[call_num].name, "syz_usb_connect", strlen("syz_usb_connect")) == 0) {
			prog_extra_timeout = 2000;
			call_extra_timeout = 2000;
		}
		if (strncmp(syscalls[call_num].name, "syz_usb_control_io", strlen("syz_usb_control_io")) == 0)
			call_extra_timeout = 300;
		if (strncmp(syscalls[call_num].name, "syz_usb_ep_write", strlen("syz_usb_ep_write")) == 0)
			call_extra_timeout = 300;
		if (strncmp(syscalls[call_num].name, "syz_usb_ep_read", strlen("syz_usb_ep_read")) == 0)
			call_extra_timeout = 300;
		if (strncmp(syscalls[call_num].name, "syz_usb_disconnect", strlen("syz_usb_disconnect")) == 0)
			call_extra_timeout = 300;
		if (strncmp(syscalls[call_num].name, "syz_open_dev$hiddev", strlen("syz_open_dev$hiddev")) == 0)
			call_extra_timeout = 50;
		if (strncmp(syscalls[call_num].name, "syz_mount_image", strlen("syz_mount_image")) == 0)
			call_extra_timeout = 50;
		uint64 copyout_index = read_input(&input_pos);
		uint64 num_args = read_input(&input_pos);
		if (num_args > kMaxArgs)
			fail("command has bad number of arguments %llu", num_args);
		uint64 args[kMaxArgs] = {};
		for (uint64 i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
		for (uint64 i = num_args; i < kMaxArgs; i++)
			args[i] = 0;
		thread_t* th = schedule_call(call_index++, call_num, colliding, copyout_index,
					     num_args, args, input_pos, call_extra_cover);

		if (colliding && (call_index % 2) == 0) {
			// Don't wait for every other call.
			// We already have results from the previous execution.
		} else if (flag_threaded) {
			// Wait for call completion.
			// Note: sys knows about this 25ms timeout when it generates timespec/timeval values.
			uint64 timeout_ms = 45 + call_extra_timeout;
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
	}

	if (!colliding && !collide && running > 0) {
		// Give unfinished syscalls some additional time.
		last_scheduled = 0;
		uint64 wait = 100;
		uint64 wait_start = current_time_ms();
		uint64 wait_end = wait_start + wait;
		if (wait_end < start + 800)
			wait_end = start + 800;
		wait_end += prog_extra_timeout;
		while (running > 0 && current_time_ms() <= wait_end) {
			sleep_ms(1);
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
					if (flag_coverage)
						cover_collect(&th->cov);
					write_call_output(th, false);
				}
			}
			if (prog_extra_cover)
				write_extra_output();
		}
	}

#if SYZ_HAVE_CLOSE_FDS
	close_fds();
#endif

	if (prog_extra_cover) {
		sleep_ms(500);
		if (!colliding && !collide)
			write_extra_output();
	}

	if (flag_collide && !flag_fault && !colliding && !collide) {
		debug("enabling collider\n");
		collide = colliding = true;
		goto retry;
	}
}

thread_t* schedule_call(int call_index, int call_num, bool colliding, uint64 copyout_index, uint64 num_args, uint64* args, uint64* pos, bool extra_cover)
{
	// Find a spare thread to execute the call.
	int i;
	for (i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		if (!th->created)
			thread_create(th, i);
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
		fail("bad thread state in schedule: ready=%d done=%d executing=%d",
		     event_isset(&th->ready), event_isset(&th->done), th->executing);
	last_scheduled = th;
	th->colliding = colliding;
	th->copyout_pos = pos;
	th->copyout_index = copyout_index;
	event_reset(&th->done);
	th->executing = true;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	th->extra_cover = extra_cover;
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
	cover_data_t* cover_data = ((cover_data_t*)cov->data) + 1;
	uint32 nsig = 0;
	cover_data_t prev = 0;
	for (uint32 i = 0; i < cov->size; i++) {
		cover_data_t pc = cover_data[i];
		if (!cover_check(pc)) {
			debug("got bad pc: 0x%llx\n", (uint64)pc);
			doexit(0);
		}
		cover_data_t sig = pc ^ prev;
		prev = hash(pc);
		if (dedup(sig))
			continue;
		write_output(sig);
		nsig++;
	}
	// Write out number of signals.
	*signal_count_pos = nsig;

	if (!flag_collect_cover)
		return;
	// Write out real coverage (basic block PCs).
	uint32 cover_size = cov->size;
	if (flag_dedup_cover) {
		cover_data_t* end = cover_data + cover_size;
		cover_unprotect(cov);
		std::sort(cover_data, end);
		cover_size = std::unique(cover_data, end) - cover_data;
		cover_protect(cov);
	}
	// Truncate PCs to uint32 assuming that they fit into 32-bits.
	// True for x86_64 and arm64 without KASLR.
	for (uint32 i = 0; i < cover_size; i++)
		write_output(cover_data[i]);
	*cover_count_pos = cover_size;
}
#endif

void handle_completion(thread_t* th)
{
	if (event_isset(&th->ready) || !event_isset(&th->done) || !th->executing)
		fail("bad thread state in completion: ready=%d done=%d executing=%d",
		     event_isset(&th->ready), event_isset(&th->done), th->executing);
	if (th->res != (intptr_t)-1)
		copyout_call_results(th);
	if (!collide && !th->colliding) {
		write_call_output(th, true);
		if (th->extra_cover)
			write_extra_output();
	}
	th->executing = false;
	running--;
	if (running < 0)
		fail("running = %d", running);
}

void copyout_call_results(thread_t* th)
{
	if (th->copyout_index != no_copyout) {
		if (th->copyout_index >= kMaxCommands)
			fail("result idx %lld overflows kMaxCommands", th->copyout_index);
		results[th->copyout_index].executed = true;
		results[th->copyout_index].val = th->res;
	}
	for (bool done = false; !done;) {
		uint64 instr = read_input(&th->copyout_pos);
		switch (instr) {
		case instr_copyout: {
			uint64 index = read_input(&th->copyout_pos);
			if (index >= kMaxCommands)
				fail("result idx %lld overflows kMaxCommands", index);
			char* addr = (char*)read_input(&th->copyout_pos);
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
	uint32 reserrno = 999;
	const bool blocked = th != last_scheduled;
	uint32 call_flags = call_flag_executed | (blocked ? call_flag_blocked : 0);
	if (finished) {
		reserrno = th->res != -1 ? 0 : th->reserrno;
		call_flags |= call_flag_finished |
			      (th->fault_injected ? call_flag_fault_injected : 0);
	}
#if SYZ_EXECUTOR_USES_SHMEM
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
			fail("too many comparisons %u", ncomps);
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
	} else if (flag_coverage) {
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
#endif
}

void write_extra_output()
{
#if SYZ_EXECUTOR_USES_SHMEM
	if (!flag_coverage || !flag_extra_coverage || flag_comparisons)
		return;
	cover_collect(&extra_cov);
	if (!extra_cov.size)
		return;
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
#endif
}

void thread_create(thread_t* th, int id)
{
	th->created = true;
	th->id = id;
	th->executing = false;
	event_init(&th->ready);
	event_init(&th->done);
	event_set(&th->done);
	if (flag_threaded)
		thread_start(worker_thread, th);
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;

	if (flag_coverage)
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
	if (flag_fault && th->call_index == flag_fault_call) {
		if (collide)
			fail("both collide and fault injection are enabled");
		fail_fd = inject_fault(flag_fault_nth);
	}

	if (flag_coverage)
		cover_reset(&th->cov);
	errno = 0;
	th->res = execute_syscall(call, th->args);
	th->reserrno = errno;
	if (th->res == -1 && th->reserrno == 0)
		th->reserrno = EINVAL; // our syz syscalls may misbehave
	if (flag_coverage) {
		cover_collect(&th->cov);
		if (th->cov.size >= kCoverSize)
			fail("#%d: too much cover %u", th->id, th->cov.size);
	}
	th->fault_injected = false;

	if (flag_fault && th->call_index == flag_fault_call) {
		th->fault_injected = fault_injected(fail_fd);
	}

	debug("#%d [%llums] <- %s=0x%llx errno=%d ",
	      th->id, current_time_ms() - start_time_ms, call->name, (uint64)th->res, th->reserrno);
	if (flag_coverage)
		debug("cover=%u ", th->cov.size);
	if (flag_fault && th->call_index == flag_fault_call)
		debug("fault=%d ", th->fault_injected);
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
uint32 dedup_table[dedup_table_size];

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
#endif

template <typename T>
void copyin_int(char* addr, uint64 val, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	if (bf_off == 0 && bf_len == 0) {
		*(T*)addr = swap(val, sizeof(T), bf);
		return;
	}
	T x = swap(*(T*)addr, sizeof(T), bf);
	x = (x & ~BITMASK(bf_off, bf_len)) | ((val << bf_off) & BITMASK(bf_off, bf_len));
	*(T*)addr = swap(x, sizeof(T), bf);
}

void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	if (bf != binary_format_native && bf != binary_format_bigendian && (bf_off != 0 || bf_len != 0))
		fail("bitmask for string format %llu/%llu", bf_off, bf_len);
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
				fail("copyin: bad argument size %llu", size);
		});
		break;
	case binary_format_strdec:
		if (size != 20)
			fail("bad strdec size %llu", size);
		NONFAILING(sprintf((char*)addr, "%020llu", val));
		break;
	case binary_format_strhex:
		if (size != 18)
			fail("bad strhex size %llu", size);
		NONFAILING(sprintf((char*)addr, "0x%016llx", val));
		break;
	case binary_format_stroct:
		if (size != 23)
			fail("bad stroct size %llu", size);
		NONFAILING(sprintf((char*)addr, "%023llo", val));
		break;
	default:
		fail("unknown binary format %llu", bf);
	}
}

bool copyout(char* addr, uint64 size, uint64* res)
{
	bool ok = false;
	NONFAILING(
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
			    fail("copyout: bad argument size %llu", size);
	    } __atomic_store_n(&ok, true, __ATOMIC_RELEASE););
	return ok;
}

uint64 read_arg(uint64** input_posp)
{
	uint64 typ = read_input(input_posp);
	switch (typ) {
	case arg_const: {
		uint64 size, bf, bf_off, bf_len;
		uint64 val = read_const_arg(input_posp, &size, &bf, &bf_off, &bf_len);
		if (bf != binary_format_native && bf != binary_format_bigendian)
			fail("bad argument binary format %llu", bf);
		if (bf_off != 0 || bf_len != 0)
			fail("bad argument bitfield %llu/%llu", bf_off, bf_len);
		return swap(val, size, bf);
	}
	case arg_result: {
		uint64 meta = read_input(input_posp);
		uint64 bf = meta >> 8;
		if (bf != binary_format_native)
			fail("bad result argument format %llu", bf);
		return read_result(input_posp);
	}
	default:
		fail("bad argument type %llu", typ);
	}
}

uint64 swap(uint64 v, uint64 size, uint64 bf)
{
	if (bf == binary_format_native)
		return v;
	if (bf != binary_format_bigendian)
		fail("bad binary format in swap: %llu", bf);
	switch (size) {
	case 2:
		return htobe16(v);
	case 4:
		return htobe32(v);
	case 8:
		return htobe64(v);
	default:
		fail("bad big-endian int size %llu", size);
	}
}

uint64 read_const_arg(uint64** input_posp, uint64* size_p, uint64* bf_p, uint64* bf_off_p, uint64* bf_len_p)
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

uint64 read_result(uint64** input_posp)
{
	uint64 idx = read_input(input_posp);
	uint64 op_div = read_input(input_posp);
	uint64 op_add = read_input(input_posp);
	uint64 arg = read_input(input_posp);
	if (idx >= kMaxCommands)
		fail("command refers to bad result %lld", idx);
	if (results[idx].executed) {
		arg = results[idx].val;
		if (op_div != 0)
			arg = arg / op_div;
		arg += op_add;
	}
	return arg;
}

uint64 read_input(uint64** input_posp, bool peek)
{
	uint64* input_pos = *input_posp;
	if ((char*)input_pos >= input_data + kMaxInput)
		fail("input command overflows input %p: [%p:%p)", input_pos, input_data, input_data + kMaxInput);
	if (!peek)
		*input_posp = input_pos + 1;
	return *input_pos;
}

#if SYZ_EXECUTOR_USES_SHMEM
uint32* write_output(uint32 v)
{
	if (output_pos < output_data || (char*)output_pos >= (char*)output_data + kMaxOutput)
		fail("output overflow: pos=%p region=[%p:%p]",
		     output_pos, output_data, (char*)output_data + kMaxOutput);
	*output_pos = v;
	return output_pos++;
}

void write_completed(uint32 completed)
{
	__atomic_store_n(output_data, completed, __ATOMIC_RELEASE);
}
#endif

#if SYZ_EXECUTOR_USES_SHMEM
void kcov_comparison_t::write()
{
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
		return;
	}
	// If we have 64 bits arguments then write them in Little-endian.
	write_output((uint32)(arg1 & 0xFFFFFFFF));
	write_output((uint32)(arg1 >> 32));
	write_output((uint32)(arg2 & 0xFFFFFFFF));
	write_output((uint32)(arg2 >> 32));
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
		uint64 out_end = out_start + kMaxOutput;
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
	return false;
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
#endif

void setup_features(char** enable, int n)
{
	// This does any one-time setup for the requested features on the machine.
	// Note: this can be called multiple times and must be idempotent.
	for (int i = 0; i < n; i++) {
		bool found = false;
#if SYZ_HAVE_FEATURES
		for (unsigned f = 0; f < sizeof(features) / sizeof(features[0]); f++) {
			if (strcmp(enable[i], features[f].name) == 0) {
				features[f].setup();
				found = true;
				break;
			}
		}
#endif
		if (!found)
			fail("unknown feature %s", enable[i]);
	}
}

void fail(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(kFailStatus);
}

void exitf(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(0);
}

void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
}

void debug_dump_data(const char* data, int length)
{
	if (!flag_debug)
		return;
	int i;
	for (i = 0; i < length; i++) {
		debug("%02x ", data[i] & 0xff);
		if (i % 16 == 15)
			debug("\n");
	}
	if (i % 16 != 0)
		debug("\n");
}
