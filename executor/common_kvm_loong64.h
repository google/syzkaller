// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_LOONG64_H
#define EXECUTOR_COMMON_KVM_LOONG64_H

// This file is shared between executor and csource package.

// Loong64 KVM pseudo-syscalls: minimal setup_cpu plus full-SYZOS UEXIT path.

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#include "common_kvm.h"
#include "kvm.h"

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_setup_syzos_vm || __NR_syz_kvm_add_vcpu
#include "common_kvm_loong64_syzos.h"
#endif

// LoongArch ELF ABI (lp64):
//   r2 = tp, r3 = sp, r4 = a0, r5 = a1.
#define LOONG64_REG_TP 2
#define LOONG64_REG_SP 3
#define LOONG64_REG_A0 4
#define LOONG64_REG_A1 5

// PC-relative address formers that may be unsafe after a raw guest-section copy.
// Encoding reference: LoongArch Reference Manual, Volume 1.
#define LOONG64_OPCODE_PCALAU12I 0x1a000000
#define LOONG64_OPCODE_PCADDI 0x18000000
#define LOONG64_OPCODE_PCADDU12I 0x1c000000
#define LOONG64_OPCODE_PCADDU18I 0x1e000000
#define LOONG64_OPCODE_PCREL_MASK 0xfe000000

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_reg
static long syz_kvm_assert_reg(volatile long a0, volatile long a1, volatile long a2)
{
	int vcpu_fd = (int)a0;
	uint64 id = (uint64)a1;
	uint64 expect = a2, val = 0;

	// KVM_REG_SIZE is not present in all installed UAPI headers.
	if ((id & KVM_REG_SIZE_MASK) > KVM_REG_SIZE_U64) {
		errno = EINVAL;
		return -1;
	}
	struct kvm_one_reg reg = {.id = id, .addr = (uint64)&val};
	int ret = ioctl(vcpu_fd, KVM_GET_ONE_REG, &reg);
	if (ret)
		return ret;
	if (val != expect) {
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
	const uintptr_t page_size = LOONG64_KVM_PAGE_SIZE;
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

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm || __NR_syz_kvm_add_vcpu
struct kvm_syz_vm {
	int vmfd;
	int next_cpu_id;
	void* host_mem;
	size_t total_pages;
	void* user_text;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm
struct addr_size {
	void* addr;
	size_t size;
};

static struct addr_size alloc_guest_mem(struct addr_size* free, size_t size)
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

static int vm_set_user_memory_region(int vmfd, uint32 slot, uint32 flags, uint64 guest_phys_addr, uint64 memory_size, uint64 userspace_addr)
{
	struct kvm_userspace_memory_region memreg;
	memreg.slot = slot;
	memreg.flags = flags;
	memreg.guest_phys_addr = guest_phys_addr;
	memreg.memory_size = memory_size;
	memreg.userspace_addr = userspace_addr;
	return ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
}

// Code loading SYZOS into guest memory does not handle data relocations (see
// https://github.com/google/syzkaller/issues/5565). Detect PC-relative address
// formers so regressions fail early. Relative branches/calls within the guest
// section are fine.
static void validate_guest_code(const void* mem, size_t size)
{
	const uint32* insns = (const uint32*)mem;
	for (size_t i = 0; i < size / 4; i++) {
		uint32 op = insns[i] & LOONG64_OPCODE_PCREL_MASK;
		if (op == LOONG64_OPCODE_PCADDI) {
			int32_t imm = (insns[i] >> 5) & 0xfffff;
			if (imm & 0x80000)
				imm -= 0x100000;
			int64_t target = (int64_t)(i * 4) + (int64_t)imm * 4;
			if (target >= 0 && (uint64)target < size)
				continue;
		}
		if (op == LOONG64_OPCODE_PCALAU12I ||
		    op == LOONG64_OPCODE_PCADDI ||
		    op == LOONG64_OPCODE_PCADDU12I ||
		    op == LOONG64_OPCODE_PCADDU18I)
			fail("PC-relative absolute address former detected in SYZOS, exiting");
	}
}

static int install_syzos_code(void* host_mem, size_t mem_size)
{
	size_t size = (char*)&__stop_guest - (char*)&__start_guest;
	if (size > mem_size)
		fail("SYZOS size exceeds guest memory");
	validate_guest_code(&__start_guest, size);
	if (size && !NONFAILING(memcpy(host_mem, &__start_guest, size))) {
		errno = EFAULT;
		return -1;
	}
	return 0;
}

#define MEM_REGION_FLAG_USER_CODE (1 << 0)
#define MEM_REGION_FLAG_DIRTY_LOG (1 << 1)
#define MEM_REGION_FLAG_READONLY (1 << 2)
#define MEM_REGION_FLAG_EXECUTOR_CODE (1 << 3)
#define MEM_REGION_FLAG_NO_HOST_MEM (1 << 6)

struct mem_region {
	uint64 gpa;
	int pages;
	uint32 flags;
};

// SYZOS guest physical memory layout (must stay in sync with executor/kvm.h).
static const struct mem_region syzos_mem_regions[] = {
    // Unmapped region to trigger page faults (1 page at LOONG64_ADDR_EXIT).
    {LOONG64_ADDR_EXIT, 1, MEM_REGION_FLAG_NO_HOST_MEM},
    // Writable region with KVM_MEM_LOG_DIRTY_PAGES (2 pages).
    {LOONG64_ADDR_DIRTY_PAGES, 2, MEM_REGION_FLAG_DIRTY_LOG},
    // User API payload (KVM_MAX_VCPU pages).
    {LOONG64_ADDR_USER_CODE, KVM_MAX_VCPU, MEM_REGION_FLAG_READONLY | MEM_REGION_FLAG_USER_CODE},
    // Executor guest code.
    {SYZOS_ADDR_EXECUTOR_CODE, 4, MEM_REGION_FLAG_READONLY | MEM_REGION_FLAG_EXECUTOR_CODE},
    // Scratch memory reserved for later CODE API use.
    {LOONG64_ADDR_SCRATCH_CODE, 1, 0},
    // Stack pages (one per VCPU).
    {LOONG64_ADDR_STACK_BASE, KVM_MAX_VCPU, 0},
};

static int setup_vm(int vmfd, void* host_mem, size_t total_pages, void** user_text)
{
	struct addr_size allocator = {.addr = host_mem, .size = total_pages * LOONG64_KVM_PAGE_SIZE};
	int slot = 0;

	for (size_t i = 0; i < sizeof(syzos_mem_regions) / sizeof(syzos_mem_regions[0]); i++) {
		const struct mem_region* r = &syzos_mem_regions[i];
		if (r->flags & MEM_REGION_FLAG_NO_HOST_MEM)
			continue;
		struct addr_size next = alloc_guest_mem(&allocator, r->pages * LOONG64_KVM_PAGE_SIZE);
		if (!next.addr) {
			errno = ENOMEM;
			return -1;
		}
		uint32 flags = 0;
		if (r->flags & MEM_REGION_FLAG_DIRTY_LOG)
			flags |= KVM_MEM_LOG_DIRTY_PAGES;
		if (r->flags & MEM_REGION_FLAG_READONLY)
			flags |= KVM_MEM_READONLY;
		if ((r->flags & MEM_REGION_FLAG_EXECUTOR_CODE) &&
		    install_syzos_code(next.addr, next.size))
			return -1;
		if (vm_set_user_memory_region(vmfd, slot++, flags, r->gpa, next.size,
					      (uintptr_t)next.addr))
			return -1;
		if (r->flags & MEM_REGION_FLAG_USER_CODE)
			*user_text = next.addr;
	}

	// Map the remaining pages at an unused low address.
	if (allocator.size > 0) {
		struct addr_size next = alloc_guest_mem(&allocator, allocator.size);
		if (!next.addr) {
			errno = ENOMEM;
			return -1;
		}
		if (vm_set_user_memory_region(vmfd, slot++, 0, 0, next.size,
					      (uintptr_t)next.addr))
			return -1;
	}
	return 0;
}

static long syz_kvm_setup_syzos_vm(volatile long a0, volatile long a1)
{
	const int vmfd = a0;
	void* host_mem = (void*)a1;
	if (!host_mem) {
		errno = EINVAL;
		return -1;
	}
	struct kvm_syz_vm* ret = (struct kvm_syz_vm*)host_mem;
	void* guest_mem = (void*)((uintptr_t)host_mem + LOONG64_KVM_PAGE_SIZE);
	const size_t total_pages = LOONG64_KVM_GUEST_PAGES - 1;
	void* user_text = NULL;
	if (setup_vm(vmfd, guest_mem, total_pages, &user_text))
		return -1;
	if (!NONFAILING(ret->vmfd = vmfd) ||
	    !NONFAILING(ret->next_cpu_id = 0) ||
	    !NONFAILING(ret->host_mem = guest_mem) ||
	    !NONFAILING(ret->total_pages = total_pages) ||
	    !NONFAILING(ret->user_text = user_text)) {
		errno = EFAULT;
		return -1;
	}

	return (long)ret;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
// LoongArch exposes GPRs/PC through KVM_SET_REGS, not ordinary one-reg IDs.
static int reset_cpu_regs(int cpufd, int cpu_id, size_t text_size)
{
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	regs.pc = executor_fn_guest_addr(guest_main);
	regs.gpr[LOONG64_REG_SP] = LOONG64_ADDR_STACK_BASE +
				   (cpu_id + 1) * LOONG64_KVM_PAGE_SIZE - 128;
	regs.gpr[LOONG64_REG_TP] = cpu_id;
	regs.gpr[LOONG64_REG_A0] = text_size;
	regs.gpr[LOONG64_REG_A1] = cpu_id;
	return ioctl(cpufd, KVM_SET_REGS, &regs);
}

static int install_user_code(int cpufd, void* user_text_slot, int cpu_id, const void* text, size_t text_size)
{
	if ((cpu_id < 0) || (cpu_id >= KVM_MAX_VCPU) || !user_text_slot) {
		errno = EINVAL;
		return -1;
	}
	if (text_size > LOONG64_KVM_PAGE_SIZE)
		text_size = LOONG64_KVM_PAGE_SIZE;
	void* target = (void*)((uintptr_t)user_text_slot + (LOONG64_KVM_PAGE_SIZE * cpu_id));
	if (text_size > 0 &&
	    (!text || !NONFAILING(memcpy(target, text, text_size)))) {
		errno = EFAULT;
		return -1;
	}
	return reset_cpu_regs(cpufd, cpu_id, text_size);
}

static long syz_kvm_add_vcpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	struct kvm_syz_vm* vm = (struct kvm_syz_vm*)a0;
	struct kvm_text* utext = (struct kvm_text*)a1;
	const void* text = 0;
	size_t text_size = 0;
	int vmfd = -1;
	int cpu_id = -1;
	void* user_text = NULL;

	(void)a2;
	(void)a3;

	if (!vm || !utext) {
		errno = EINVAL;
		return -1;
	}
	if (!NONFAILING(text = utext->text) ||
	    !NONFAILING(text_size = utext->size) ||
	    !NONFAILING(vmfd = vm->vmfd) ||
	    !NONFAILING(cpu_id = vm->next_cpu_id) ||
	    !NONFAILING(user_text = vm->user_text)) {
		errno = EFAULT;
		return -1;
	}
	if (cpu_id < 0) {
		errno = EINVAL;
		return -1;
	}
	if (cpu_id >= KVM_MAX_VCPU) {
		errno = ENOMEM;
		return -1;
	}
	int cpufd = ioctl(vmfd, KVM_CREATE_VCPU, cpu_id);
	if (cpufd == -1)
		return -1;
	if (install_user_code(cpufd, user_text, cpu_id, text, text_size)) {
		int err = errno;
		close(cpufd);
		errno = err;
		return -1;
	}
	if (!NONFAILING(vm->next_cpu_id = cpu_id + 1)) {
		close(cpufd);
		errno = EFAULT;
		return -1;
	}
	return cpufd;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_syzos_uexit
static long syz_kvm_assert_syzos_uexit(volatile long a0, volatile long a1,
				       volatile long a2)
{
#if !SYZ_EXECUTOR
	int cpufd = (int)a0;
#endif
	struct kvm_run* run = (struct kvm_run*)a1;
	uint64 expect = a2;

	if (!run) {
		errno = EINVAL;
		return -1;
	}
	uint32 exit_reason = 0;
	uint32 mmio_len = 0;
	uint8 is_write = 0;
	uint64 phys_addr = 0;
	if (!NONFAILING(exit_reason = run->exit_reason) ||
	    !NONFAILING(phys_addr = run->mmio.phys_addr) ||
	    !NONFAILING(mmio_len = run->mmio.len) ||
	    !NONFAILING(is_write = run->mmio.is_write)) {
		errno = EFAULT;
		return -1;
	}
	if ((exit_reason != KVM_EXIT_MMIO) ||
	    (phys_addr != LOONG64_ADDR_UEXIT) ||
	    !is_write || (mmio_len != sizeof(uint64))) {
#if !SYZ_EXECUTOR
		fprintf(stderr, "[SYZOS-DEBUG] Assertion Triggered on VCPU %d\n", cpufd);
#endif
		errno = EINVAL;
		return -1;
	}

	uint64 actual_code = 0;
	if (!NONFAILING(memcpy(&actual_code, run->mmio.data, sizeof(actual_code)))) {
		errno = EFAULT;
		return -1;
	}
	if (actual_code != expect) {
#if !SYZ_EXECUTOR
		fprintf(stderr, "[SYZOS-DEBUG] Exit Code Mismatch on VCPU %d\n", cpufd);
		fprintf(stderr, "   Expected: 0x%lx\n", (unsigned long)expect);
		fprintf(stderr, "   Actual:   0x%lx\n",
			(unsigned long)actual_code);
#endif
		errno = EDOM;
		return -1;
	}
	return 0;
}
#endif

#ifdef LOONG64_KVM_UNDEFINE_NONFAILING
#undef NONFAILING
#undef LOONG64_KVM_UNDEFINE_NONFAILING
#endif

#endif // EXECUTOR_COMMON_KVM_LOONG64_H
