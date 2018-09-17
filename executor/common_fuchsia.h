// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <fcntl.h>
#include <lib/fdio/util.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
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

#if SYZ_EXECUTOR || __NR_get_root_resource
#include <ddk/driver.h>
#endif

#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
#include <pthread.h>
#include <setjmp.h>
#include <zircon/syscalls/debug.h>
#include <zircon/syscalls/exception.h>
#include <zircon/syscalls/object.h>
#include <zircon/syscalls/port.h>

static __thread int skip_segv;
static __thread jmp_buf segv_env;

static void segv_handler(void)
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
#if GOARCH_amd64
			regs.rip = (uint64)(void*)&segv_handler;
#elif GOARCH_arm64
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

static void install_segv_handler(void)
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

#if SYZ_EXECUTOR || SYZ_THREADED
#include <unistd.h>

// Fuchsia's pthread_cond_timedwait just returns immidiately, so we use simple spin wait.
typedef struct {
	int state;
} event_t;

static void event_init(event_t* ev)
{
	ev->state = 0;
}

static void event_reset(event_t* ev)
{
	ev->state = 0;
}

static void event_set(event_t* ev)
{
	if (ev->state)
		fail("event already set");
	__atomic_store_n(&ev->state, 1, __ATOMIC_RELEASE);
}

static void event_wait(event_t* ev)
{
	while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
		usleep(200);
}

static int event_isset(event_t* ev)
{
	return __atomic_load_n(&ev->state, __ATOMIC_ACQUIRE);
}

static int event_timedwait(event_t* ev, uint64 timeout_ms)
{
	uint64 start = current_time_ms();
	for (;;) {
		if (__atomic_load_n(&ev->state, __ATOMIC_RELAXED))
			return 1;
		if (current_time_ms() - start > timeout_ms)
			return 0;
		usleep(200);
	}
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mmap
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

#if SYZ_EXECUTOR || __NR_syz_process_self
static long syz_process_self(void)
{
	return zx_process_self();
}
#endif

#if SYZ_EXECUTOR || __NR_syz_thread_self
static long syz_thread_self(void)
{
	return zx_thread_self();
}
#endif

#if SYZ_EXECUTOR || __NR_syz_vmar_root_self
static long syz_vmar_root_self(void)
{
	return zx_vmar_root_self();
}
#endif

#if SYZ_EXECUTOR || __NR_syz_job_default
static long syz_job_default(void)
{
	return zx_job_default();
}
#endif

#if SYZ_EXECUTOR || __NR_syz_future_time
static long syz_future_time(long when)
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

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

#if SYZ_EXECUTOR
#define do_sandbox_setuid() 0
#define do_sandbox_namespace() 0
#define do_sandbox_android_untrusted_app() 0
#endif

// Ugly way to work around gcc's "error: function called through a non-compatible type".
// The macro is used in generated C code.
#define CAST(f) ({void* p = (void*)f; p; })
