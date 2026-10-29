// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_H
#define EXECUTOR_COMMON_KVM_H

// This file is shared between executor and csource package.

// Common KVM-related definitions.

#include "common_kvm_syzos.h"
#include "kvm.h"

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_setup_syzos_vm || __NR_syz_kvm_assert_syzos_uexit || __NR_syz_kvm_assert_syzos_kvm_exit
extern char* __start_guest;

// executor_fn_guest_addr() is compiled into both the host and the guest code.
static always_inline uintptr_t executor_fn_guest_addr(void* fn)
{
	// Prevent the compiler from creating a .rodata constant for
	// &__start_guest + SYZOS_ADDR_EXECUTOR_CODE.
	volatile uintptr_t start = (uintptr_t)&__start_guest;
	volatile uintptr_t offset = SYZOS_ADDR_EXECUTOR_CODE;
	return (uintptr_t)fn - start + offset;
}

#if SYZ_EXECUTOR
// In Clang-based C++ builds, use template magic to ensure that only guest functions can be passed
// to executor_fn_guest_addr().
template <typename R, typename... A>
uintptr_t static always_inline executor_fn_guest_addr(__addrspace_guest R (*fn)(A...))
{
	return executor_fn_guest_addr((void*)fn);
}

#endif

#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
// Argument descriptors of syz_kvm_setup_cpu and syz_kvm_add_vcpu, see sys/linux/dev_kvm*.txt.
struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_setup_syzos_vm
// Simple bump allocator for carving guest memory regions out of a host buffer.
struct addr_size {
	void* addr;
	size_t size;
};

// These helpers are inline, because not every architecture uses them for syz_kvm_setup_cpu,
// and unused static functions would break the build of C reproducers.
static inline struct addr_size alloc_guest_mem(struct addr_size* free, size_t size)
{
	struct addr_size ret = {.addr = NULL, .size = 0};

	if (free->size < size)
		return ret;
	ret.addr = free->addr;
	ret.size = size;
	free->addr = (void*)((char*)free->addr + size);
	free->size -= size;
	return ret;
}

// Call KVM_SET_USER_MEMORY_REGION for the given pages.
static inline void vm_set_user_memory_region(int vmfd, uint32 slot, uint32 flags, uint64 guest_phys_addr, uint64 memory_size, uint64 userspace_addr)
{
	struct kvm_userspace_memory_region memreg;
	memreg.slot = slot;
	memreg.flags = flags;
	memreg.guest_phys_addr = guest_phys_addr;
	memreg.memory_size = memory_size;
	memreg.userspace_addr = userspace_addr;
	ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_syzos_kvm_exit
static long syz_kvm_assert_syzos_kvm_exit(volatile long a0, volatile long a1)
{
	struct kvm_run* run = (struct kvm_run*)a0;
	uint64 expect = a1;

	if (!run) {
#if !SYZ_EXECUTOR
		fprintf(stderr, "[SYZOS-DEBUG] Assertion Triggered: run is NULL\n");
#endif
		errno = EINVAL;
		return -1;
	}

	if (run->exit_reason != expect) {
#if !SYZ_EXECUTOR
		fprintf(stderr, "[SYZOS-DEBUG] KVM Exit Reason Mismatch\n");
		fprintf(stderr, "   is_write: %d\n", run->mmio.is_write);
		fprintf(stderr, "   Expected: 0x%lx\n", (unsigned long)expect);
		fprintf(stderr, "   Actual:   0x%lx\n", (unsigned long)run->exit_reason);
#endif
		errno = EDOM;
		return -1;
	}
	return 0;
}
#endif

#endif // EXECUTOR_COMMON_KVM_H
