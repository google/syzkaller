// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <zircon/process.h>
#include <zircon/syscalls.h>

#define doexit exit

#include "common.h"

#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
static void install_segv_handler()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
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
	zx_handle_t mapping = 0;
	uintptr_t res = 0;
	uintptr_t offset = 16 << 20;
	zx_status_t status = zx_vmar_allocate(zx_vmar_root_self(), addr - offset, size,
					      ZX_VM_FLAG_SPECIFIC | ZX_VM_FLAG_CAN_MAP_READ | ZX_VM_FLAG_CAN_MAP_WRITE,
					      &mapping, &res);
	if (addr != res)
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
