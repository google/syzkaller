// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Common KVM-related definitions.

#include "common_kvm_syzos.h"
#include "kvm.h"

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
extern char* __start_guest;

// executor_fn_guest_addr() is compiled into both the host and the guest code.
static inline uintptr_t executor_fn_guest_addr(void* fn)
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
uintptr_t static inline executor_fn_guest_addr(__addrspace_guest R (*fn)(A...))
{
	return executor_fn_guest_addr((void*)fn);
}

#endif

#endif

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
