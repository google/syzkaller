// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_SYZOS_H
#define EXECUTOR_COMMON_KVM_SYZOS_H

// Common SYZOS definitions.

// Prevent function inlining. This attribute is applied to every guest_handle_* function,
// making sure they remain small so that the compiler does not attempt to be too clever
// (e.g. generate switch tables).
#define noinline __attribute__((noinline))

// __no_stack_protector disables -fstack-protector which may introduce unwanted global accesses.
// TODO(glider): once syz-env-old migrates to GCC>11 we can just use
// __attribute__((no_stack_protector)).
#if defined(__clang__)

// Clang supports the no_stack_protector attribute.
#define __no_stack_protector __attribute__((no_stack_protector))
#define __addrspace_guest __attribute__((address_space(10)))

#elif defined(__GNUC__)
// The no_stack_protector attribute was introduced in GCC 11.1.
#if __GNUC__ > 11
#define __no_stack_protector __attribute__((no_stack_protector))
#else
// Fallback to the optimize attribute for older GCC versions.
#define __no_stack_protector __attribute__((__optimize__("-fno-stack-protector")))
#endif
#define __addrspace_guest

#else
#define __no_stack_protector
#define __addrspace_guest
#endif

// Disable optimizations for a particular function.
#if defined(__clang__)
#define __optnone __attribute__((optnone))
#elif defined(__GNUC__)
#define __optnone __attribute__((optimize("O0")))
#else
#define __optnone
#endif

// Host will map the code in this section into the guest address space.
#define GUEST_CODE __attribute__((section("guest"))) __no_stack_protector __addrspace_guest

// Start/end of the guest section.
extern char *__start_guest, *__stop_guest;

#endif // EXECUTOR_COMMON_KVM_SYZOS_H
