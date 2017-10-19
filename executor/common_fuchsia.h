// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <utime.h>
#include <zircon/process.h>
#include <zircon/syscalls.h>
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
#include <zircon/syscalls/debug.h>
#include <zircon/syscalls/exception.h>
#include <zircon/syscalls/object.h>
#include <zircon/syscalls/port.h>
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

static void segv_handler()
{
	if (__atomic_load_n(&skip_segv, __ATOMIC_RELAXED)) {
		debug("recover: skipping\n");
		_longjmp(segv_env, 1);
	}
	debug("recover: exiting\n");
	doexit(1);
}

static void* ex_handler(void* arg)
{
	zx_handle_t port = (zx_handle_t)(long)arg;
	for (int i = 0; i < 10000; i++) {
		zx_port_packet_t packet = {};
		zx_status_t status = zx_port_wait(port, ZX_TIME_INFINITE, &packet, 0);
		if (status != ZX_OK) {
			debug("zx_port_wait failed: %d\n", status);
			continue;
		}
		debug("got exception packet: type=%d status=%d tid=%llu\n",
		      packet.type, packet.status, packet.exception.tid);
		zx_handle_t thread;
		status = zx_object_get_child(zx_process_self(), packet.exception.tid,
					     ZX_RIGHT_SAME_RIGHTS, &thread);
		if (status != ZX_OK) {
			debug("zx_object_get_child failed: %d\n", status);
			continue;
		}
		uint32_t bytes_read;
		zx_x86_64_general_regs_t regs;
		status = zx_thread_read_state(thread, ZX_THREAD_STATE_REGSET0,
					      &regs, sizeof(regs), &bytes_read);
		if (status != ZX_OK || bytes_read != sizeof(regs)) {
			debug("zx_thread_read_state failed: %d/%d (%d)\n",
			      bytes_read, (int)sizeof(regs), status);
		} else {
			regs.rip = (uint64_t)(void*)&segv_handler;
			status = zx_thread_write_state(thread, ZX_THREAD_STATE_REGSET0, &regs, sizeof(regs));
			if (status != ZX_OK)
				debug("zx_thread_write_state failed: %d\n", status);
		}
		status = zx_task_resume(thread, ZX_RESUME_EXCEPTION);
		if (status != ZX_OK)
			debug("zx_task_resume failed: %d\n", status);
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
		if (_setjmp(segv_env) == 0) {                        \
			__VA_ARGS__;                                 \
		}                                                    \
		__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); \
	}
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT))
static uint64_t current_time_ms()
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fail("clock_gettime failed");
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
#endif

#if defined(SYZ_EXECUTOR)
static void sleep_ms(uint64_t ms)
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
		error("zx_object_get_info(ZX_INFO_VMAR) failed: %d", status);
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
	zx_time_t now = zx_time_get(ZX_CLOCK_MONOTONIC);
	return now + delta_ms * 1000 * 1000;
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_zx_channel_call_finish) || defined(zx_channel_call_noretry)
#include "kernel/lib/vdso/vdso-code.h"
#define UNEXPORTED(name) ((syscall_t)((long)&zx_handle_close - VDSO_SYSCALL_zx_handle_close + VDSO_SYSCALL_##name))
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_zx_channel_call_finish)
zx_status_t zx_channel_call_finish(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	return UNEXPORTED(zx_channel_call_finish)(a0, a1, a2, a3, a4, a5, a6, a7, a8);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(__NR_zx_channel_call_noretry)
zx_status_t zx_channel_call_noretry(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	return UNEXPORTED(zx_channel_call_noretry)(a0, a1, a2, a3, a4, a5, a6, a7, a8);
}
#endif
