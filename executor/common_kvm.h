// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Common KVM-related definitions.

extern char *__start_guest, *__stop_guest;
static inline uintptr_t arch_executor_fn_guest_address(uintptr_t f, uintptr_t exec_offset)
{
	if (((uintptr_t)(f) >= (uintptr_t)&__start_guest) && ((f) < (uintptr_t)&__stop_guest))
		return (uintptr_t)(f) - (uintptr_t)&__start_guest + (exec_offset);
	fail("SYZOS: arch_executor_fn_guest_address: invalid guest address");
	return 0;
}

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
