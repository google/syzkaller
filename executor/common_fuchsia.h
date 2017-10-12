// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <unistd.h>
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

#define doexit exit
#define NORETURN __attribute__((noreturn))

#include "common.h"

#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
static __thread int skip_segv;
static __thread jmp_buf segv_env;

static void segv_handler(int sig, siginfo_t* info, void* uctx)
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
		debug("SIGSEGV on %p, skipping\n", addr);
		_longjmp(segv_env, 1);
	}
	debug("SIGSEGV on %p, exiting\n", addr);
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
	uintptr_t res = 0;
	zx_handle_t mapping = 0;
	status = zx_vmar_allocate(root, addr - info.base, size,
				  ZX_VM_FLAG_SPECIFIC | ZX_VM_FLAG_CAN_MAP_READ | ZX_VM_FLAG_CAN_MAP_WRITE,
				  &mapping, &res);
	if (status == ZX_OK && addr != res)
		error("zx_vmar_allocate allocated wrong address: %p, want %p", (void*)res, (void*)addr);
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
