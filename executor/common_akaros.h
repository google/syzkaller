// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/syscall.h>
#include <unistd.h>
#if defined(SYZ_EXECUTOR) || defined(SYZ_THREADED) || defined(SYZ_COLLIDE)
#include <pthread.h>
#include <stdlib.h>
#endif
#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT))
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
#include <parlib/parlib.h>
#include <setjmp.h>
#include <signal.h>
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
#include <stdlib.h>
#include <sys/stat.h>
#endif
#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT) && defined(SYZ_USE_TMP_DIR))
#include <dirent.h>
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||      \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_HANDLE_SEGV) || defined(SYZ_TUN_ENABLE) || \
    defined(SYZ_SANDBOX_NAMESPACE) || defined(SYZ_SANDBOX_SETUID) ||                   \
    defined(SYZ_SANDBOX_NONE) || defined(SYZ_FAULT_INJECTION) || defined(__NR_syz_kvm_setup_cpu)
__attribute__((noreturn)) static void doexit(int status)
{
	_exit(status);
	for (;;) {
	}
}
#endif

#include "common.h"

#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
static __thread int skip_segv;
static __thread jmp_buf segv_env;

static void recover()
{
	_longjmp(segv_env, 1);
}

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
		debug("SIGSEGV on 0x%lx, skipping\n", addr);
		struct user_context* uctx = (struct user_context*)ctx;
		uctx->tf.hw_tf.tf_rip = (long)(void*)recover;
		return;
	}
	debug("SIGSEGV on 0x%lx, exiting\n", addr);
	doexit(sig);
	for (;;) {
	}
}

static void install_segv_handler()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
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

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT))
static uint64 current_time_ms()
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fail("clock_gettime failed");
	return (uint64)ts.tv_sec * 1000 + (uint64)ts.tv_nsec / 1000000;
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
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

#if defined(SYZ_EXECUTOR)
static void sleep_ms(uint64 ms)
{
	usleep(ms * 1000);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_FAULT_INJECTION)
static int inject_fault(int nth)
{
	return 0;
}

static int fault_injected(int fail_fd)
{
	return 0;
}
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT) && defined(SYZ_USE_TMP_DIR))
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

#if defined(SYZ_SANDBOX_NONE)
static void loop();
static int do_sandbox_none(void)
{
	loop();
	doexit(0);
	fail("doexit returned");
	return 0;
}
#endif

#if defined(SYZ_REPEAT)
static void execute_one();

#if defined(SYZ_WAIT_REPEAT)
void loop()
{
	int iter;
	for (iter = 0;; iter++) {
#ifdef SYZ_USE_TMP_DIR
		char cwdbuf[256];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");
#endif
		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
#ifdef SYZ_USE_TMP_DIR
			if (chdir(cwdbuf))
				fail("failed to chdir");
#endif
			execute_one();
			doexit(0);
		}
		int status = 0;
		uint64 start = current_time_ms();
		for (;;) {
			int res = waitpid(-1, &status, WNOHANG);
			if (res == pid)
				break;
			usleep(1000);
			if (current_time_ms() - start > 5 * 1000) {
				kill(pid, SIGKILL);
				while (waitpid(-1, &status, 0) != pid) {
				}
				break;
			}
		}
#ifdef SYZ_USE_TMP_DIR
		remove_dir(cwdbuf);
#endif
	}
}
#else
void loop()
{
	while (1) {
		execute_one();
	}
}
#endif
#endif

#if defined(SYZ_THREADED)
struct thread_t {
	int created, running, call;
	pthread_t th;
};

static struct thread_t threads[16];
static void execute_call(int call);
static int running;
#if defined(SYZ_COLLIDE)
static int collide;
#endif

static void* thr(void* arg)
{
	struct thread_t* th = (struct thread_t*)arg;
	for (;;) {
		while (!__atomic_load_n(&th->running, __ATOMIC_ACQUIRE))
			usleep(200);
		execute_call(th->call);
		__atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&th->running, 0, __ATOMIC_RELEASE);
	}
	return 0;
}

static void execute(int num_calls)
{
	int i, call, thread;
	running = 0;
	for (call = 0; call < num_calls; call++) {
		for (thread = 0; thread < sizeof(threads) / sizeof(threads[0]); thread++) {
			struct thread_t* th = &threads[thread];
			if (!th->created) {
				th->created = 1;
				pthread_attr_t attr;
				pthread_attr_init(&attr);
				pthread_attr_setstacksize(&attr, 128 << 10);
				pthread_create(&th->th, &attr, thr, th);
			}
			if (!__atomic_load_n(&th->running, __ATOMIC_ACQUIRE)) {
				th->call = call;
				__atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
				__atomic_store_n(&th->running, 1, __ATOMIC_RELEASE);
#if defined(SYZ_COLLIDE)
				if (collide && call % 2)
					break;
#endif
				for (i = 0; i < 100; i++) {
					if (!__atomic_load_n(&th->running, __ATOMIC_ACQUIRE))
						break;
					usleep(200);
				}
				if (__atomic_load_n(&running, __ATOMIC_RELAXED))
					usleep((call == num_calls - 1) ? 10000 : 1000);
				break;
			}
		}
	}
}
#endif
