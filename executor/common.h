// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.
// csource does a bunch of transformations with this file:
// - unused parts are stripped using #if SYZ* defines
// - includes are hoisted to the top and deduplicated
// - comments and empty lines are stripped
// - NORETURN/PRINTF/debug are removed
// - exitf/failf/fail are replaced with exit
// - uintN types are replaced with uintN_t
// - [[FOO]] placeholders are replaced by actual values

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

#if SYZ_EXECUTOR && !GOOS_linux
#include <unistd.h>
NORETURN void doexit(int status)
{
	_exit(status);
	for (;;) {
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_PROCS || SYZ_REPEAT && SYZ_ENABLE_CGROUPS || \
    __NR_syz_mount_image || __NR_syz_read_part_table
unsigned long long procid;
#endif

#if !GOOS_fuchsia && !GOOS_windows
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
#include <setjmp.h>
#include <signal.h>
#include <string.h>

#if GOOS_linux
#include <sys/syscall.h>
#endif

static __thread int skip_segv;
static __thread jmp_buf segv_env;

#if GOOS_akaros
#include <parlib/parlib.h>
static void recover()
{
	_longjmp(segv_env, 1);
}
#endif

static void segv_handler(int sig, siginfo_t* info, void* ctx)
{
	// Generated programs can contain bad (unmapped/protected) addresses,
	// which cause SIGSEGVs during copyin/copyout.
	// This handler ignores such crashes to allow the program to proceed.
	// We additionally opportunistically check that the faulty address
	// is not within executable data region, because such accesses can corrupt
	// output region and then fuzzer will fail on corrupted data.
	uintptr_t addr = (uintptr_t)info->si_addr;
	const uintptr_t prog_start = 1 << 20;
	const uintptr_t prog_end = 100 << 20;
	if (__atomic_load_n(&skip_segv, __ATOMIC_RELAXED) && (addr < prog_start || addr > prog_end)) {
		debug("SIGSEGV on %p, skipping\n", (void*)addr);
#if GOOS_akaros
		struct user_context* uctx = (struct user_context*)ctx;
		uctx->tf.hw_tf.tf_rip = (long)(void*)recover;
		return;
#else
		_longjmp(segv_env, 1);
#endif
	}
	debug("SIGSEGV on %p, exiting\n", (void*)addr);
	doexit(sig);
}

static void install_segv_handler()
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
	{                                                            \
		__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		if (_setjmp(segv_env) == 0) {                        \
			__VA_ARGS__;                                 \
		}                                                    \
		__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); \
	}
#endif
#endif

#if !GOOS_linux
#if (SYZ_EXECUTOR || SYZ_REPEAT) && SYZ_EXECUTOR_USES_FORK_SERVER
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

static void kill_and_wait(int pid, int* status)
{
	kill(pid, SIGKILL);
	while (waitpid(-1, status, 0) != pid) {
	}
}
#endif
#endif

#if !GOOS_windows
#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER
static void sleep_ms(uint64 ms)
{
	usleep(ms * 1000);
}
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER
#include <time.h>

static uint64 current_time_ms()
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

static void use_temporary_dir()
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

#if GOOS_akaros || GOOS_netbsd || GOOS_freebsd || GOOS_test
#if SYZ_EXECUTOR || SYZ_EXECUTOR_USES_FORK_SERVER && SYZ_REPEAT && SYZ_USE_TMP_DIR
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static void remove_dir(const char* dir)
{
	DIR* dp;
	struct dirent* ep;
	dp = opendir(dir);
	if (dp == NULL)
		exitf("opendir(%s) failed", dir);
	while ((ep = readdir(dp))) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
		char filename[FILENAME_MAX];
		snprintf(filename, sizeof(filename), "%s/%s", dir, ep->d_name);
		struct stat st;
		if (lstat(filename, &st))
			exitf("lstat(%s) failed", filename);
		if (S_ISDIR(st.st_mode)) {
			remove_dir(filename);
			continue;
		}
		if (unlink(filename))
			exitf("unlink(%s) failed", filename);
	}
	closedir(dp);
	if (rmdir(dir))
		exitf("rmdir(%s) failed", dir);
}
#endif
#endif

#if !GOOS_linux
#if SYZ_EXECUTOR || SYZ_FAULT_INJECTION
static int inject_fault(int nth)
{
	return 0;
}
#endif
#if SYZ_EXECUTOR
static int fault_injected(int fail_fd)
{
	return 0;
}
#endif
#endif

#if !GOOS_windows
#if SYZ_EXECUTOR || SYZ_THREADED
#include <pthread.h>

static void thread_start(void* (*fn)(void*), void* arg)
{
	pthread_t th;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 << 10);
	if (pthread_create(&th, &attr, fn, arg))
		exitf("pthread_create failed");
	pthread_attr_destroy(&attr);
}

#endif
#endif

#if GOOS_freebsd || GOOS_netbsd || GOOS_akaros || GOOS_test
#if SYZ_EXECUTOR || SYZ_THREADED

#include <pthread.h>
#include <time.h>

typedef struct {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int state;
} event_t;

static void event_init(event_t* ev)
{
	if (pthread_mutex_init(&ev->mu, 0))
		fail("pthread_mutex_init failed");
	if (pthread_cond_init(&ev->cv, 0))
		fail("pthread_cond_init failed");
	ev->state = 0;
}

static void event_reset(event_t* ev)
{
	ev->state = 0;
}

static void event_set(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	if (ev->state)
		fail("event already set");
	ev->state = 1;
	pthread_mutex_unlock(&ev->mu);
	pthread_cond_broadcast(&ev->cv);
}

static void event_wait(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	while (!ev->state)
		pthread_cond_wait(&ev->cv, &ev->mu);
	pthread_mutex_unlock(&ev->mu);
}

static int event_isset(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	int res = ev->state;
	pthread_mutex_unlock(&ev->mu);
	return res;
}

static int event_timedwait(event_t* ev, uint64 timeout)
{
	uint64 start = current_time_ms();
	uint64 now = start;
	pthread_mutex_lock(&ev->mu);
	for (;;) {
		if (ev->state)
			break;
		uint64 remain = timeout - (now - start);
		struct timespec ts;
		ts.tv_sec = remain / 1000;
		ts.tv_nsec = (remain % 1000) * 1000 * 1000;
		pthread_cond_timedwait(&ev->cv, &ev->mu, &ts);
		now = current_time_ms();
		if (now - start > timeout)
			break;
	}
	int res = ev->state;
	pthread_mutex_unlock(&ev->mu);
	return res;
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_USE_BITMASKS
#define BITMASK_LEN(type, bf_len) (type)((1ull << (bf_len)) - 1)

#define BITMASK_LEN_OFF(type, bf_off, bf_len) (type)(BITMASK_LEN(type, (bf_len)) << (bf_off))

#define STORE_BY_BITMASK(type, addr, val, bf_off, bf_len)                         \
	if ((bf_off) == 0 && (bf_len) == 0) {                                     \
		*(type*)(addr) = (type)(val);                                     \
	} else {                                                                  \
		type new_val = *(type*)(addr);                                    \
		new_val &= ~BITMASK_LEN_OFF(type, (bf_off), (bf_len));            \
		new_val |= ((type)(val)&BITMASK_LEN(type, (bf_len))) << (bf_off); \
		*(type*)(addr) = new_val;                                         \
	}
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

	size_t i;
	for (i = 0; i < length - 1; i += 2)
		csum->acc += *(uint16*)&data[i];

	if (length & 1)
		csum->acc += (uint16)data[length - 1];

	while (csum->acc > 0xffff)
		csum->acc = (csum->acc & 0xffff) + (csum->acc >> 16);
}

static uint16 csum_inet_digest(struct csum_inet* csum)
{
	return ~csum->acc;
}
#endif

#if GOOS_akaros
#include "common_akaros.h"
#elif GOOS_freebsd || GOOS_netbsd
#include "common_bsd.h"
#elif GOOS_fuchsia
#include "common_fuchsia.h"
#elif GOOS_linux
#include "common_linux.h"
#elif GOOS_test
#include "common_test.h"
#elif GOOS_windows
#include "common_windows.h"
#elif GOOS_test
#include "common_test.h"
#else
#error "unknown OS"
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
static void execute_one()
#else
static void loop()
#endif
{
#if SYZ_REPRO
	if (write(1, "executing program\n", sizeof("executing program\n") - 1)) {
	}
#endif
#if SYZ_TRACE
	printf("### start\n");
#endif
	int i, call, thread;
#if SYZ_COLLIDE
	int collide = 0;
again:
#endif
	for (call = 0; call < [[NUM_CALLS]]; call++) {
		for (thread = 0; thread < sizeof(threads) / sizeof(threads[0]); thread++) {
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
#if SYZ_COLLIDE
			if (collide && (call % 2) == 0)
				break;
#endif
			event_timedwait(&th->done, 45);
			break;
		}
	}
	for (i = 0; i < 100 && __atomic_load_n(&running, __ATOMIC_RELAXED); i++)
		sleep_ms(1);
#if SYZ_COLLIDE
	if (!collide) {
		collide = 1;
		goto again;
	}
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
static void execute_one();
#if SYZ_EXECUTOR_USES_FORK_SERVER
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#if GOOS_linux
#define WAIT_FLAGS __WALL
#else
#define WAIT_FLAGS 0
#endif

#if SYZ_EXECUTOR
static void reply_handshake();
#endif

static void loop()
{
#if SYZ_HAVE_SETUP_LOOP
	setup_loop();
#endif
#if SYZ_EXECUTOR
	// Tell parent that we are ready to serve.
	reply_handshake();
#endif
#if SYZ_EXECUTOR && GOOS_akaros
	// For akaros we do exec in the child process because new threads can't be created in the fork child.
	// Thus we proxy input program over the child_pipe to the child process.
	int child_pipe[2];
	if (pipe(child_pipe))
		fail("pipe failed");
#endif
	int iter;
#if SYZ_REPEAT_TIMES
	for (iter = 0; iter < [[REPEAT_TIMES]]; iter++) {
#else
	for (iter = 0;; iter++) {
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
#if GOOS_akaros
#if SYZ_EXECUTOR
			dup2(child_pipe[0], kInPipeFd);
			close(child_pipe[0]);
			close(child_pipe[1]);
#endif
			execl(program_name, program_name, "child", NULL);
			fail("execl failed");
#else
#if SYZ_EXECUTOR
			close(kInPipeFd);
#endif
#if SYZ_EXECUTOR && SYZ_EXECUTOR_USES_SHMEM
			close(kOutPipeFd);
#endif
			execute_one();
			debug("worker exiting\n");
#if SYZ_HAVE_RESET_TEST
			reset_test();
#endif
			doexit(0);
#endif
		}
		debug("spawned worker pid %d\n", pid);

#if SYZ_EXECUTOR && GOOS_akaros
		resend_execute(child_pipe[1]);
#endif
		// We used to use sigtimedwait(SIGCHLD) to wait for the subprocess.
		// But SIGCHLD is also delivered when a process stops/continues,
		// so it would require a loop with status analysis and timeout recalculation.
		// SIGCHLD should also unblock the usleep below, so the spin loop
		// should be as efficient as sigtimedwait.
		int status = 0;
		uint64 start = current_time_ms();
#if SYZ_EXECUTOR && SYZ_EXECUTOR_USES_SHMEM
		uint64 last_executed = start;
		uint32 executed_calls = __atomic_load_n(output_data, __ATOMIC_RELAXED);
#endif
		for (;;) {
			if (waitpid(-1, &status, WNOHANG | WAIT_FLAGS) == pid)
				break;
			sleep_ms(1);
#if SYZ_EXECUTOR && SYZ_EXECUTOR_USES_SHMEM
			// Even though the test process executes exit at the end
			// and execution time of each syscall is bounded by 20ms,
			// this backup watchdog is necessary and its performance is important.
			// The problem is that exit in the test processes can fail (sic).
			// One observed scenario is that the test processes prohibits
			// exit_group syscall using seccomp. Another observed scenario
			// is that the test processes setups a userfaultfd for itself,
			// then the main thread hangs when it wants to page in a page.
			// Below we check if the test process still executes syscalls
			// and kill it after 1s of inactivity.
			uint64 now = current_time_ms();
			uint32 now_executed = __atomic_load_n(output_data, __ATOMIC_RELAXED);
			if (executed_calls != now_executed) {
				executed_calls = now_executed;
				last_executed = now;
			}
			if ((now - start < 5 * 1000) && (now - start < 3 * 1000 || now - last_executed < 1000))
				continue;
#else
			if (current_time_ms() - start < 5 * 1000)
				continue;
#endif
			debug("killing\n");
			kill_and_wait(pid, &status);
			break;
		}
#if SYZ_EXECUTOR
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		reply_execute(0);
#endif
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
		remove_dir(cwdbuf);
#endif
	}
}
#else
static void loop()
{
	execute_one();
}
#endif
#endif

// clang-format off
// clang-format badly mishandles this part, moreover different versions mishandle it differently.
#if !SYZ_EXECUTOR
[[SYSCALL_DEFINES]]

[[RESULTS]]

#if SYZ_THREADED || SYZ_REPEAT || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE
#if SYZ_THREADED
void execute_call(int call)
#elif SYZ_REPEAT
void execute_one()
#else
void loop()
#endif
{
	[[SYSCALLS]]
}
#endif

// This is the main function for csource.
#if GOOS_akaros && SYZ_REPEAT
#include <string.h>

int main(int argc, char** argv)
{
	[[MMAP_DATA]]

	program_name = argv[0];
	if (argc == 2 && strcmp(argv[1], "child") == 0)
		child();
#else
int main()
{
	[[MMAP_DATA]]
#endif
		// clang-format on

#if SYZ_HANDLE_SEGV
	install_segv_handler();
#endif
#if SYZ_PROCS
	for (procid = 0; procid < [[PROCS]]; procid++) {
		if (fork() == 0) {
#endif
#if SYZ_USE_TMP_DIR
			use_temporary_dir();
#endif
			[[SANDBOX_FUNC]]
#if SYZ_PROCS
		}
	}
	sleep(1000000);
#endif
	return 0;
}
#endif
