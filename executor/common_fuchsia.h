// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ddk/driver.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <zircon/process.h>
#include <zircon/syscalls.h>
#if defined(SYZ_EXECUTOR) || defined(SYZ_THREADED) || defined(SYZ_COLLIDE) || defined(SYZ_HANDLE_SEGV)
#include <pthread.h>
#include <stdlib.h>
#endif
#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT) && defined(SYZ_USE_TMP_DIR))
#include <dirent.h>
#endif
#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT))
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/wait.h>
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
#include <zircon/syscalls/debug.h>
#include <zircon/syscalls/exception.h>
#include <zircon/syscalls/object.h>
#include <zircon/syscalls/port.h>
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||      \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_HANDLE_SEGV) || defined(SYZ_TUN_ENABLE) || \
    defined(SYZ_SANDBOX_NAMESPACE) || defined(SYZ_SANDBOX_SETUID) ||                   \
    defined(SYZ_SANDBOX_NONE) || defined(SYZ_FAULT_INJECTION) ||                       \
    defined(__NR_syz_mmap)
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

static void segv_handler()
{
	if (__atomic_load_n(&skip_segv, __ATOMIC_RELAXED)) {
		debug("recover: skipping\n");
		longjmp(segv_env, 1);
	}
	debug("recover: exiting\n");
	doexit(SIGSEGV);
}

static void* ex_handler(void* arg)
{
	zx_handle_t port = (zx_handle_t)(long)arg;
	for (int i = 0; i < 10000; i++) {
		zx_port_packet_t packet = {};
		zx_status_t status = zx_port_wait(port, ZX_TIME_INFINITE, &packet);
		if (status != ZX_OK) {
			debug("zx_port_wait failed: %d\n", status);
			continue;
		}
		debug("got exception packet: type=%d status=%d tid=%llu\n",
		      packet.type, packet.status, (unsigned long long)(packet.exception.tid));
		zx_handle_t thread;
		status = zx_object_get_child(zx_process_self(), packet.exception.tid,
					     ZX_RIGHT_SAME_RIGHTS, &thread);
		if (status != ZX_OK) {
			debug("zx_object_get_child failed: %d\n", status);
			continue;
		}
		zx_thread_state_general_regs_t regs;
		status = zx_thread_read_state(thread, ZX_THREAD_STATE_GENERAL_REGS,
					      &regs, sizeof(regs));
		if (status != ZX_OK) {
			debug("zx_thread_read_state failed: %d (%d)\n",
			      (int)sizeof(regs), status);
		} else {
#if defined(__x86_64__)
			regs.rip = (uint64)(void*)&segv_handler;
#elif defined(__aarch64__)
			regs.pc = (uint64)(void*)&segv_handler;
#else
#error "unsupported arch"
#endif
			status = zx_thread_write_state(thread, ZX_THREAD_STATE_GENERAL_REGS, &regs, sizeof(regs));
			if (status != ZX_OK) {
				debug("zx_thread_write_state failed: %d\n", status);
			}
		}
		status = zx_task_resume(thread, ZX_RESUME_EXCEPTION);
		if (status != ZX_OK) {
			debug("zx_task_resume failed: %d\n", status);
		}
		zx_handle_close(thread);
	}
	doexit(1);
	return 0;
}

static void install_segv_handler()
{
	zx_status_t status;
	zx_handle_t port;
	if ((status = zx_port_create(0, &port)) != ZX_OK)
		fail("zx_port_create failed: %d", status);
	if ((status = zx_task_bind_exception_port(zx_process_self(), port, 0, 0)) != ZX_OK)
		fail("zx_task_bind_exception_port failed: %d", status);
	pthread_t th;
	if (pthread_create(&th, 0, ex_handler, (void*)(long)port))
		fail("pthread_create failed");
}

#define NONFAILING(...)                                              \
	{                                                            \
		__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		if (sigsetjmp(segv_env, 0) == 0) {                   \
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

#if defined(SYZ_EXECUTOR) || defined(__NR_syz_mmap)
long syz_mmap(size_t addr, size_t size)
{
	zx_handle_t root = zx_vmar_root_self();
	zx_info_vmar_t info;
	zx_status_t status = zx_object_get_info(root, ZX_INFO_VMAR, &info, sizeof(info), 0, 0);
	if (status != ZX_OK)
		fail("zx_object_get_info(ZX_INFO_VMAR) failed: %d", status);
	zx_handle_t vmo;
	status = zx_vmo_create(size, 0, &vmo);
	if (status != ZX_OK)
		return status;
	uintptr_t mapped_addr;
	status = zx_vmar_map(root, addr - info.base, vmo, 0, size,
			     ZX_VM_FLAG_SPECIFIC_OVERWRITE | ZX_VM_FLAG_PERM_READ |
				 ZX_VM_FLAG_PERM_WRITE | ZX_VM_FLAG_PERM_EXECUTE,
			     &mapped_addr);
	return status;
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_syz_process_self)
long syz_process_self()
{
	return zx_process_self();
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_syz_thread_self)
long syz_thread_self()
{
	return zx_thread_self();
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_syz_vmar_root_self)
long syz_vmar_root_self()
{
	return zx_vmar_root_self();
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_syz_job_default)
long syz_job_default()
{
	return zx_job_default();
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_syz_future_time)
long syz_future_time(long when)
{
	zx_time_t delta_ms;
	switch (when) {
	case 0:
		delta_ms = 5;
	case 1:
		delta_ms = 30;
	default:
		delta_ms = 10000;
	}
	zx_time_t now = zx_clock_get(ZX_CLOCK_MONOTONIC);
	return now + delta_ms * 1000 * 1000;
}
#endif

#if defined(SYZ_SANDBOX_NONE)
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

#if defined(SYZ_USE_TMP_DIR)
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

#if defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT) && defined(SYZ_USE_TMP_DIR)
static void remove_dir(const char* dir)
{
	struct dirent* ep;
	DIR* dp = opendir(dir);
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

#if defined(SYZ_EXECUTOR) || defined(SYZ_REPEAT)
static void execute_one();
extern unsigned long long procid;

#if defined(SYZ_EXECUTOR)
void reply_handshake();
void receive_execute();
void reply_execute(int status);
extern uint32* output_data;
extern uint32* output_pos;
#endif

#if defined(SYZ_WAIT_REPEAT)
static void loop()
{
#if defined(SYZ_EXECUTOR)
	// Tell parent that we are ready to serve.
	reply_handshake();
#endif
	int iter;
	for (iter = 0;; iter++) {
#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
		// Create a new private work dir for this test (removed at the end of the loop).
		char cwdbuf[32];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");
#endif
#if defined(SYZ_EXECUTOR)
		// TODO: consider moving the read into the child.
		// Potentially it can speed up things a bit -- when the read finishes
		// we already have a forked worker process.
		receive_execute();
#endif
		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
			if (chdir(cwdbuf))
				fail("failed to chdir");
#endif
#if defined(SYZ_EXECUTOR)
			close(kInPipeFd);
			close(kOutPipeFd);
#endif
#if defined(SYZ_EXECUTOR)
			output_pos = output_data;
#endif
			execute_one();
			debug("worker exiting\n");
			doexit(0);
		}
		debug("spawned worker pid %d\n", pid);

		// We used to use sigtimedwait(SIGCHLD) to wait for the subprocess.
		// But SIGCHLD is also delivered when a process stops/continues,
		// so it would require a loop with status analysis and timeout recalculation.
		// SIGCHLD should also unblock the usleep below, so the spin loop
		// should be as efficient as sigtimedwait.
		int status = 0;
		uint64 start = current_time_ms();
#if defined(SYZ_EXECUTOR)
		uint64 last_executed = start;
		uint32 executed_calls = __atomic_load_n(output_data, __ATOMIC_RELAXED);
#endif
		for (;;) {
			int res = waitpid(-1, &status, WNOHANG);
			if (res == pid) {
				debug("waitpid(%d)=%d\n", pid, res);
				break;
			}
			usleep(1000);
#if defined(SYZ_EXECUTOR)
			// Even though the test process executes exit at the end
			// and execution time of each syscall is bounded by 20ms,
			// this backup watchdog is necessary and its performance is important.
			// The problem is that exit in the test processes can fail (sic).
			// One observed scenario is that the test processes prohibits
			// exit_group syscall using seccomp. Another observed scenario
			// is that the test processes setups a userfaultfd for itself,
			// then the main thread hangs when it wants to page in a page.
			// Below we check if the test process still executes syscalls
			// and kill it after 500ms of inactivity.
			uint64 now = current_time_ms();
			uint32 now_executed = __atomic_load_n(output_data, __ATOMIC_RELAXED);
			if (executed_calls != now_executed) {
				executed_calls = now_executed;
				last_executed = now;
			}
			if ((now - start < 3 * 1000) && (now - start < 1000 || now - last_executed < 500))
				continue;
#else
			if (current_time_ms() - start < 3 * 1000)
				continue;
#endif
			debug("waitpid(%d)=%d\n", pid, res);
			debug("killing\n");
			kill(-pid, SIGKILL);
			kill(pid, SIGKILL);
			while (waitpid(-1, &status, 0) != pid) {
			}
			break;
		}
#if defined(SYZ_EXECUTOR)
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		reply_execute(0);
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
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
