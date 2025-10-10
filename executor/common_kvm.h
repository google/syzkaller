// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Common KVM-related definitions.

extern char *__start_guest, *__stop_guest;

// Calculate the guest physical address for a guest function.
// Execute failure_action if the function does not belong to the guest section.
// This function is using volatile accesses, otherwise the compiler may attempt
// to store e.g. &__start_guest + offset as a constant in .rodata.
#define DEFINE_GUEST_FN_TO_GPA_FN(fn_name, offset, failure_action)    \
	static inline uintptr_t fn_name(uintptr_t f)                  \
	{                                                             \
		volatile uintptr_t start = (uintptr_t)&__start_guest; \
		volatile uintptr_t stop = (uintptr_t)&__stop_guest;   \
		if (f >= start && f < stop) {                         \
			return f - start + offset;                    \
		}                                                     \
		(failure_action);                                     \
		return 0;                                             \
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
