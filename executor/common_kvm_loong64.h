// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_LOONG64_H
#define EXECUTOR_COMMON_KVM_LOONG64_H

// This file is shared between executor and csource package.

// Minimal implementation of syz_kvm_setup_cpu$loong64 pseudo-syscall.

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_syzos_kvm_exit
static long syz_kvm_assert_syzos_kvm_exit(volatile long a0, volatile long a1)
{
	struct kvm_run* run = (struct kvm_run*)a0;
	uint64 expect = a1;

	if (!run) {
		errno = EINVAL;
		return -1;
	}
	if (run->exit_reason != expect) {
		errno = EDOM;
		return -1;
	}
	return 0;
}
#endif

#ifndef NONFAILING
// csource removes the common NONFAILING definition when HandleSegv is off.
// This header also uses its result in conditions, so provide the equivalent
// direct-access behavior locally instead of leaving an undefined macro.
#define NONFAILING(...) ((void)(__VA_ARGS__), 1)
#define LOONG64_KVM_UNDEFINE_NONFAILING
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu

// syz_kvm_setup_cpu$loong64(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text_loong64, 1]], ntext len[text], flags const[0], opts ptr[in, array[kvm_setup_opt_loong64, 1]], nopt len[opts])
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	char* const host_mem = (char*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;
	// This file is also emitted into csource, where executor-only
	// SYZ_PAGE_SIZE is not defined. Keep this value synchronized with the
	// linux/loong64 target page-size policy.
	const uintptr_t page_size = 16 << 10;
	const uintptr_t guest_pages = 24;
	const uintptr_t guest_mem_size = guest_pages * page_size;

	(void)a4;
	(void)a5;
	(void)a6;
	(void)a7;
	if (!host_mem || !text_array_ptr) {
		errno = EINVAL;
		return -1;
	}

	for (uintptr_t i = 0; i < guest_pages; i++) {
		struct kvm_userspace_memory_region memreg = {
		    .slot = (unsigned int)i,
		    .flags = 0,
		    .guest_phys_addr = i * page_size,
		    .memory_size = page_size,
		    .userspace_addr = (uintptr_t)(host_mem + i * page_size),
		};
		if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg))
			return -1;
	}

	const void* text = 0;
	uintptr_t text_size = 0;
	if (!NONFAILING(text = text_array_ptr[0].text) ||
	    !NONFAILING(text_size = text_array_ptr[0].size)) {
		errno = EFAULT;
		return -1;
	}
	if (text_size > guest_mem_size)
		text_size = guest_mem_size;
	if (text_size > 0 &&
	    (!text || !NONFAILING(memcpy(host_mem, text, text_size)))) {
		errno = EFAULT;
		return -1;
	}

	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	// LoongArch KVM UAPI exposes general registers plus pc in struct kvm_regs.
	regs.pc = 0;
	if (ioctl(cpufd, KVM_SET_REGS, &regs))
		return -1;

	return 0;
}
#endif

#ifdef LOONG64_KVM_UNDEFINE_NONFAILING
#undef NONFAILING
#undef LOONG64_KVM_UNDEFINE_NONFAILING
#endif

#endif // EXECUTOR_COMMON_KVM_LOONG64_H
