// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.
// csource does a bunch of transformations with this file:
// - unused parts are stripped using #if SYZ* defines
// - includes are hoisted to the top and deduplicated
// - comments and empty lines are stripped
// - NORETURN/PRINTF/debug are removed
// - exitf/fail are replaced with exit
// - uintN types are replaced with uintN_t
// - /*{{{FOO}}}*/ placeholders are replaced by actual values

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <endian.h> // for htobe*.
#include <stdint.h>
#include <stdio.h> // for fmt arguments
#include <stdlib.h>
#include <string.h>

#if SYZ_TRACE
#include <errno.h>
#endif

#if !SYZ_EXECUTOR
/*{{{SYSCALL_DEFINES}}}*/
#endif


#if SYZ_EXECUTOR || SYZ_MULTI_PROC || SYZ_REPEAT && SYZ_CGROUPS ||                      \
    SYZ_NET_DEVICES || __NR_syz_mount_image || __NR_syz_read_part_table ||              \
    __NR_syz_usb_connect || __NR_syz_usb_connect_ath9k || __NR_syz_usbip_server_init
static unsigned long long procid;
#endif

#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
#include <setjmp.h>
#include <signal.h>
#include <string.h>

#if GOOS_linux
#include <sys/syscall.h>
#endif

static __thread int clone_ongoing;
static __thread int skip_segv;
static __thread jmp_buf segv_env;

static void segv_handler(int sig, siginfo_t* info, void* ctx)
{
	// Generated programs can contain bad (unmapped/protected) addresses,
	// which cause SIGSEGVs during copyin/copyout.
	// This handler ignores such crashes to allow the program to proceed.
	// We additionally opportunistically check that the faulty address
	// is not within executable data region, because such accesses can corrupt
	// output region and then fuzzer will fail on corrupted data.

	if (__atomic_load_n(&clone_ongoing, __ATOMIC_RELAXED) != 0) {
		// During clone, we always exit on a SEGV. If we do not, then
		// it might prevent us from running child-specific code. E.g.
		// if an invalid stack is passed to the clone() call, then it
		// will trigger a seg fault, which in turn causes the child to
		// jump over the NONFAILING macro and continue execution in
		// parallel with the parent.
		doexit_thread(sig);
	}

	uintptr_t addr = (uintptr_t)info->si_addr;
	const uintptr_t prog_start = 1 << 20;
	const uintptr_t prog_end = 100 << 20;
	int skip = __atomic_load_n(&skip_segv, __ATOMIC_RELAXED) != 0;
	int valid = addr < prog_start || addr > prog_end;
	if (skip && valid) {
		debug("SIGSEGV on %p, skipping\n", (void*)addr);
		_longjmp(segv_env, 1);
	}
	debug("SIGSEGV on %p, exiting\n", (void*)addr);
	doexit(sig);
}

static void install_segv_handler(void)
{
	struct sigaction sa;
#if GOOS_linux
	// Don't need that SIGCANCEL/SIGSETXID glibc stuff.
	// SIGCANCEL sent to main thread causes it to exit
	// without bringing down the whole group.
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	syscall(SYS_rt_sigaction, 0x20, &sa, NULL, 8);
	syscall(SYS_rt_sigaction, 0x21, &sa, NULL, 8);
#endif
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

#define NONFAILING(...)                                              \
	({                                                           \
		int ok = 1;                                          \
		__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		if (_setjmp(segv_env) == 0) {                        \
			__VA_ARGS__;                                 \
		} else                                               \
			ok = 0;                                      \
		__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		ok;                                                  \
	})
#endif
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER || \
    __NR_syz_usb_connect || __NR_syz_usb_connect_ath9k || __NR_syz_sleep_ms ||     \
    __NR_syz_usb_control_io || __NR_syz_usb_ep_read || __NR_syz_usb_ep_write ||    \
    __NR_syz_usb_disconnect
static void sleep_ms(uint64 ms)
{
	usleep(ms * 1000);
}
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER || \
    SYZ_LEAK
#include <time.h>

static uint64 current_time_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fail("clock_gettime failed");
	return (uint64)ts.tv_sec * 1000 + (uint64)ts.tv_nsec / 1000000;
}
#endif

#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void use_temporary_dir(void)
{
	char tmpdir_template[] = "./syzkaller.XXXXXX";
	char* tmpdir = mkdtemp(tmpdir_template);
	if (!tmpdir)
		fail("failed to mkdtemp");
	if (chmod(tmpdir, 0777))
		fail("failed to chmod");
	if (chdir(tmpdir))
		fail("failed to chdir");
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_THREADED
#include <errno.h>
#include <pthread.h>

static void thread_start(void* (*fn)(void*), void* arg)
{
	pthread_t th;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 << 10);
	// Clone can fail spuriously with EAGAIN if there is a concurrent execve in progress.
	// (see linux kernel commit 498052bba55ec). But it can also be a true limit imposed by cgroups.
	// In one case we want to retry infinitely, in another -- fail immidiately...
	int i = 0;
	for (; i < 100; i++) {
		if (pthread_create(&th, &attr, fn, arg) == 0) {
			pthread_attr_destroy(&attr);
			return;
		}
		if (errno == EAGAIN) {
			usleep(50);
			continue;
		}
		break;
	}
	exitf("pthread_create failed");
}

#endif
#endif

#if SYZ_EXECUTOR || SYZ_USE_BITMASKS
#define BITMASK(bf_off, bf_len) (((1ull << (bf_len)) - 1) << (bf_off))
#define STORE_BY_BITMASK(type, htobe, addr, val, bf_off, bf_len)                        \
	*(type*)(addr) = htobe((htobe(*(type*)(addr)) & ~BITMASK((bf_off), (bf_len))) | \
			       (((type)(val) << (bf_off)) & BITMASK((bf_off), (bf_len))))
#endif

#if SYZ_EXECUTOR || SYZ_USE_CHECKSUMS
struct csum_inet {
	uint32 acc;
};

static void csum_inet_init(struct csum_inet* csum)
{
	csum->acc = 0;
}

static void csum_inet_update(struct csum_inet* csum, const uint8* data, size_t length)
{
	if (length == 0)
		return;

	size_t i = 0;
	for (; i < length - 1; i += 2)
		csum->acc += *(uint16*)&data[i];

	if (length & 1)
		csum->acc += le16toh((uint16)data[length - 1]);

	while (csum->acc > 0xffff)
		csum->acc = (csum->acc & 0xffff) + (csum->acc >> 16);
}

static uint16 csum_inet_digest(struct csum_inet* csum)
{
	return ~csum->acc;
}
#endif

#include "common_linux.h"

#if SYZ_TEST_COMMON_EXT_EXAMPLE
#include "common_ext_example.h"
#else
#include "common_ext.h"
#endif

#if SYZ_EXECUTOR || __NR_syz_execute_func
// syz_execute_func(text ptr[in, text[taget]])
static long syz_execute_func(volatile long text)
{
	// Here we just to random code which is inherently unsafe.
	// But we only care about coverage in the output region.
	// The following code tries to remove left-over pointers in registers
	// from the reach of the random code, otherwise it's known to reach
	// the output region somehow. The asm block is arch-independent except
	// for the number of available registers.
#if defined(__GNUC__)
	volatile long p[8] = {0};
	(void)p;
#if GOARCH_amd64
	asm volatile("" ::"r"(0l), "r"(1l), "r"(2l), "r"(3l), "r"(4l), "r"(5l), "r"(6l),
		     "r"(7l), "r"(8l), "r"(9l), "r"(10l), "r"(11l), "r"(12l), "r"(13l));
#endif
#endif
	((void (*)(void))(text))();
	return 0;
}
#endif

#if SYZ_THREADED
struct thread_t {
	int created, call;
	event_t ready, done;
};

static struct thread_t threads[16];
static void execute_call(int call);
static int running;

static void* thr(void* arg)
{
	struct thread_t* th = (struct thread_t*)arg;
	for (;;) {
		event_wait(&th->ready);
		event_reset(&th->ready);
		execute_call(th->call);
		__atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
		event_set(&th->done);
	}
	return 0;
}

#if SYZ_REPEAT
static void execute_one(void)
#else
static void loop(void)
#endif
{
	if (write(1, "executing program\n", sizeof("executing program\n") - 1)) {
	}
#if SYZ_TRACE
	fprintf(stderr, "### start\n");
#endif
	int i, call, thread;
	for (call = 0; call < /*{{{NUM_CALLS}}}*/; call++) {
		for (thread = 0; thread < (int)(sizeof(threads) / sizeof(threads[0])); thread++) {
			struct thread_t* th = &threads[thread];
			if (!th->created) {
				th->created = 1;
				event_init(&th->ready);
				event_init(&th->done);
				event_set(&th->done);
				thread_start(thr, th);
			}
			if (!event_isset(&th->done))
				continue;
			event_reset(&th->done);
			th->call = call;
			__atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
			event_set(&th->ready);
#if SYZ_ASYNC
			if (/*{{{ASYNC_CONDITIONS}}}*/)
				break;
#endif
			event_timedwait(&th->done, /*{{{CALL_TIMEOUT_MS}}}*/);
			break;
		}
	}
	for (i = 0; i < 100 && __atomic_load_n(&running, __ATOMIC_RELAXED); i++)
		sleep_ms(1);
#if SYZ_HAVE_CLOSE_FDS
	close_fds();
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
static void execute_one(void);

#if GOOS_linux
#define WAIT_FLAGS __WALL
#else
#define WAIT_FLAGS 0
#endif

#if SYZ_EXECUTOR_USES_FORK_SERVER
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

static void loop(void)
{
#if SYZ_HAVE_SETUP_LOOP
	setup_loop();
#endif
#if SYZ_EXECUTOR
	// Tell parent that we are ready to serve.
	if (!flag_snapshot)
		reply_execute(0);
#endif
	int iter = 0;
#if SYZ_REPEAT_TIMES
	for (; iter < /*{{{REPEAT_TIMES}}}*/; iter++) {
#else
	for (;; iter++) {
#endif
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
		// Create a new private work dir for this test (removed at the end of the loop).
		char cwdbuf[32];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");
#endif
#if SYZ_HAVE_RESET_LOOP
		reset_loop();
#endif
#if SYZ_EXECUTOR
		if (!flag_snapshot)
			receive_execute();
#endif
		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
			if (chdir(cwdbuf))
				fail("failed to chdir");
#endif
#if SYZ_HAVE_SETUP_TEST
			setup_test();
#endif
#if SYZ_HAVE_SETUP_EXT_TEST
			setup_ext_test();
#endif
#if SYZ_EXECUTOR
			close(kInPipeFd);
#endif
#if SYZ_EXECUTOR
			close(kOutPipeFd);
#endif
			execute_one();
#if !SYZ_EXECUTOR && SYZ_HAVE_CLOSE_FDS && !SYZ_THREADED
			// Executor's execute_one has already called close_fds.
			close_fds();
#endif
			doexit(0);
		}
		debug("spawned worker pid %d\n", pid);

#if SYZ_EXECUTOR
		if (flag_snapshot)
			SnapshotPrepareParent();
#endif

		// We used to use sigtimedwait(SIGCHLD) to wait for the subprocess.
		// But SIGCHLD is also delivered when a process stops/continues,
		// so it would require a loop with status analysis and timeout recalculation.
		// SIGCHLD should also unblock the usleep below, so the spin loop
		// should be as efficient as sigtimedwait.
		int status = 0;
		uint64 start = current_time_ms();
#if SYZ_EXECUTOR
		uint64 last_executed = start;
		uint32 executed_calls = output_data->completed.load(std::memory_order_relaxed);
#endif
		for (;;) {
			sleep_ms(10);
			if (waitpid(-1, &status, WNOHANG | WAIT_FLAGS) == pid)
				break;
#if SYZ_EXECUTOR
			// Even though the test process executes exit at the end
			// and execution time of each syscall is bounded by syscall_timeout_ms (~50ms),
			// this backup watchdog is necessary and its performance is important.
			// The problem is that exit in the test processes can fail (sic).
			// One observed scenario is that the test processes prohibits
			// exit_group syscall using seccomp. Another observed scenario
			// is that the test processes setups a userfaultfd for itself,
			// then the main thread hangs when it wants to page in a page.
			// Below we check if the test process still executes syscalls
			// and kill it after ~1s of inactivity.
			// (Globs are an exception: they can be slow, so we allow up to ~120s)
			uint64 min_timeout_ms = program_timeout_ms * 3 / 5;
			uint64 inactive_timeout_ms = syscall_timeout_ms * 20;
			uint64 glob_timeout_ms = program_timeout_ms * 120;

			uint64 now = current_time_ms();
			uint32 now_executed = output_data->completed.load(std::memory_order_relaxed);
			if (executed_calls != now_executed) {
				executed_calls = now_executed;
				last_executed = now;
			}

			// TODO: adjust timeout for progs with syz_usb_connect call.
			// If the max program timeout is exceeded, kill unconditionally.
			if ((now - start > program_timeout_ms && request_type != rpc::RequestType::Glob) || (now - start > glob_timeout_ms && request_type == rpc::RequestType::Glob))
				goto kill_test;
			// If the request type is not a normal test program (currently, glob expansion request),
			// then wait for the full timeout (these requests don't update number of completed calls
			// + they are more important and we don't want timing flakes).
			if (request_type != rpc::RequestType::Program)
				continue;
			// Always wait at least the min timeout for each program.
			if (now - start < min_timeout_ms)
				continue;
			// If it keeps completing syscalls, then don't kill it.
			if (now - last_executed < inactive_timeout_ms)
				continue;
		kill_test:
#else
			if (current_time_ms() - start < /*{{{PROGRAM_TIMEOUT_MS}}}*/)
				continue;
#endif
			debug("killing hanging pid %d\n", pid);
			kill_and_wait(pid, &status);
			break;
		}
#if SYZ_EXECUTOR
		if (WEXITSTATUS(status) == kFailStatus) {
			errno = 0;
			fail("child failed");
		}
		reply_execute(0);
#endif
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
		remove_dir(cwdbuf);
#endif
#if SYZ_LEAK
		// Note: this will fail under setuid sandbox because we don't have
		// write permissions for the kmemleak file.
		check_leaks();
#endif
	}
}
#else
static void loop(void)
{
	execute_one();
}
#endif
#endif

#if !SYZ_EXECUTOR

/*{{{RESULTS}}}*/

#if SYZ_THREADED || SYZ_REPEAT || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE
#if SYZ_THREADED
void execute_call(int call)
#elif SYZ_REPEAT
void execute_one(void)
#else
void loop(void)
#endif
{
	/*{{{SYSCALLS}}}*/
#if SYZ_HAVE_CLOSE_FDS && !SYZ_THREADED && !SYZ_REPEAT
	close_fds();
#endif
}
#endif

// This is the main function for csource.
int main(void)
{
	/*{{{MMAP_DATA}}}*/

#if SYZ_SYSCTL
	setup_sysctl();
#endif
#if SYZ_CGROUPS
	setup_cgroups();
#endif
	const char* reason;
	(void)reason;
#if SYZ_BINFMT_MISC
	if ((reason = setup_binfmt_misc()))
		printf("the reproducer may not work as expected: binfmt_misc setup failed: %s\n", reason);
#endif
#if SYZ_LEAK
	if ((reason = setup_leak()))
		printf("the reproducer may not work as expected: leak checking setup failed: %s\n", reason);
#endif
#if SYZ_FAULT
	if ((reason = setup_fault()))
		printf("the reproducer may not work as expected: fault injection setup failed: %s\n", reason);
#endif
#if SYZ_KCSAN
	if ((reason = setup_kcsan()))
		printf("the reproducer may not work as expected: KCSAN setup failed: %s\n", reason);
#endif
#if SYZ_USB
	if ((reason = setup_usb()))
		printf("the reproducer may not work as expected: USB injection setup failed: %s\n", reason);
#endif
#if SYZ_802154
	if ((reason = setup_802154()))
		printf("the reproducer may not work as expected: 802154 injection setup failed: %s\n", reason);
#endif
#if SYZ_SWAP
	if ((reason = setup_swap()))
		printf("the reproducer may not work as expected: swap setup failed: %s\n", reason);
#endif
#if SYZ_HANDLE_SEGV
	install_segv_handler();
#endif
#if SYZ_HAVE_SETUP_EXT
	setup_ext();
#endif
#if SYZ_MULTI_PROC
	for (procid = 0; procid < /*{{{PROCS}}}*/; procid++) {
		if (fork() == 0) {
#endif
#if SYZ_USE_TMP_DIR
			use_temporary_dir();
#endif
			/*{{{SANDBOX_FUNC}}}*/
#if SYZ_HAVE_CLOSE_FDS && !SYZ_THREADED && !SYZ_REPEAT && !SYZ_SANDBOX_NONE && \
    !SYZ_SANDBOX_SETUID && !SYZ_SANDBOX_NAMESPACE
			close_fds();
#endif
#if SYZ_MULTI_PROC
		}
	}
	sleep(1000000);
#endif
#if !SYZ_MULTI_PROC && !SYZ_REPEAT && SYZ_LEAK
	check_leaks();
#endif
	return 0;
}
#endif
