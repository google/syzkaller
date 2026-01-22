// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_RISCV64_H
#define EXECUTOR_COMMON_KVM_RISCV64_H

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#include "common_kvm.h"
#include "kvm.h"

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_setup_syzos_vm || __NR_syz_kvm_add_vcpu
#include "common_kvm_riscv64_syzos.h"
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
// Construct RISC-V register id for KVM.
#define RISCV_CORE_REG(idx) (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | (idx))
#define RISCV_CSR_REG(idx) (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CSR | (idx))

// Represent CSR indices in the kvm_riscv_csr structure.
enum riscv_csr_index {
	CSR_SSTATUS = 0,
	CSR_SIE,
	CSR_STVEC,
	CSR_SSCRATCH,
	CSR_SEPC,
	CSR_SCAUSE,
	CSR_STVAL,
	CSR_SIP,
	CSR_SATP,
	CSR_SCOUNTEREN,
	CSR_SENVCFG
};

// Represent CORE register indices in the kvm_riscv_core structure.
enum riscv_core_index {
	CORE_PC = 0x00,
	CORE_RA,
	CORE_SP,
	CORE_GP,
	CORE_TP,
	CORE_T0,
	CORE_T1,
	CORE_T2,
	CORE_S0,
	CORE_S1,
	CORE_A0,
	CORE_A1,
	CORE_A2,
	CORE_A3,
	CORE_A4,
	CORE_A5,
	CORE_A6,
	CORE_A7,
	CORE_S2,
	CORE_S3,
	CORE_S4,
	CORE_S5,
	CORE_S6,
	CORE_S7,
	CORE_S8,
	CORE_S9,
	CORE_S10,
	CORE_S11,
	CORE_T3,
	CORE_T4,
	CORE_T5,
	CORE_T6,
	// Store the privilege mode: 1=S-mode, 0=U-mode.
	CORE_MODE
};

// Indicate the Supervisor Previous Privilege mode.
#define SSTATUS_SPP (1UL << 8)
// Indicate the Supervisor Previous Interrupt Enable state.
#define SSTATUS_SPIE (1UL << 5)
// Indicate the Supervisor Interrupt Enable state.
#define SSTATUS_SIE (1UL << 1)

// Set a single register value for the specified CPU file descriptor.
static inline int kvm_set_reg(int cpufd, unsigned long id, unsigned long value)
{
	struct kvm_one_reg reg = {
	    .id = id,
	    .addr = (unsigned long)&value,
	};
	return ioctl(cpufd, KVM_SET_ONE_REG, &reg);
}

struct kvm_text {
	uintptr_t type;
	const void* text;
	uintptr_t size;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_setup_syzos_vm
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu

// syz_kvm_setup_cpu$riscv64(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text_riscv64, 1]], ntext len[text], flags const[0], opts ptr[in, array[kvm_setup_opt_riscv64, 1]], nopt len[opts])
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	char* const host_mem = (char*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;

	const uintptr_t page_size = 4096;
	const uintptr_t guest_pages = 24;
	const uintptr_t guest_mem_size = guest_pages * page_size;

	// Install guest memory.
	for (uintptr_t i = 0; i < guest_pages; i++) {
		struct kvm_userspace_memory_region mem = {
		    .slot = (unsigned int)i,
		    .flags = 0,
		    .guest_phys_addr = RISCV64_ADDR_USER_CODE + i * page_size,
		    .memory_size = page_size,
		    .userspace_addr =
			(uintptr_t)(host_mem + i * page_size),
		};

		if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &mem))
			return -1;
	}

	// Copy guest code.
	const void* text = 0;
	uintptr_t size = 0;
	NONFAILING(text = text_array_ptr[0].text);
	NONFAILING(size = text_array_ptr[0].size);
	if (size > guest_mem_size)
		size = guest_mem_size;
	memcpy(host_mem, text, size);
	memcpy(host_mem + page_size, (void*)guest_unexp_trap, MIN(KVM_PAGE_SIZE, (size_t)((char*)__stop_guest - (char*)guest_unexp_trap)));

	// Initialize VCPU registers.
	// Set PC (program counter) to start of code.
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_PC), RISCV64_ADDR_USER_CODE))
		return -1;
	// Set SP (stack pointer) at end of memory, reserving space for stack.
	unsigned long stack_top = RISCV64_ADDR_USER_CODE + guest_mem_size - page_size;
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_SP), stack_top))
		return -1;
	// Set privilege mode to S-mode.
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_MODE), 1))
		return -1;
	// Set SSTATUS CSR with SPP and SPIE.
	unsigned long sstatus = SSTATUS_SPP | SSTATUS_SPIE;
	if (kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_SSTATUS), sstatus))
		return -1;
	// Set STVEC.
	unsigned long stvec = RISCV64_ADDR_USER_CODE + page_size;
	if (kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_STVEC), stvec))
		return -1;
	// Set GP.
	unsigned long current_gp = 0;
	asm volatile("add %0, gp, zero"
		     : "=r"(current_gp)
		     :
		     : "memory");
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_GP), current_gp))
		return -1;

	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_reg
static long syz_kvm_assert_reg(volatile long a0, volatile long a1, volatile long a2)
{
	int vcpu_fd = (int)a0;
	uint64 id = (uint64)a1;
	uint64 expect = a2, val = 0;

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

// Call KVM_SET_USER_MEMORY_REGION for the given pages.
static void vm_set_user_memory_region(int vmfd, uint32 slot, uint32 flags, uint64 guest_phys_addr, uint64 memory_size, uint64 userspace_addr)
{
	struct kvm_userspace_memory_region memreg;
	memreg.slot = slot;
	memreg.flags = flags;
	memreg.guest_phys_addr = guest_phys_addr;
	memreg.memory_size = memory_size;
	memreg.userspace_addr = userspace_addr;
	ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
}

#define AUIPC_OPCODE 0x17
#define AUIPC_OPCODE_MASK 0x7f

// Code loading SYZOS into guest memory does not handle data relocations (see
// https://github.com/google/syzkaller/issues/5565), so SYZOS will crash soon after encountering an
// AUIPC instruction. Detect these instructions to catch regressions early.
// The most common reason for using data relocaions is accessing global variables and constants.
// Sometimes the compiler may choose to emit a read-only constant to zero-initialize a structure
// or to generate a jump table for a switch statement.
static void validate_guest_code(void* mem, size_t size)
{
	uint32* insns = (uint32*)mem;
	for (size_t i = 0; i < size / 4; i++) {
		if ((insns[i] & AUIPC_OPCODE_MASK) == AUIPC_OPCODE)
			fail("AUIPC instruction detected in SYZOS, exiting");
	}
}

static void install_syzos_code(void* host_mem, size_t mem_size)
{
	size_t size = (char*)&__stop_guest - (char*)&__start_guest;
	if (size > mem_size)
		fail("SYZOS size exceeds guest memory");
	memcpy(host_mem, &__start_guest, size);
	validate_guest_code(host_mem, size);
}

// Flags for mem_region.
#define MEM_REGION_FLAG_USER_CODE (1 << 0)
#define MEM_REGION_FLAG_DIRTY_LOG (1 << 1)
#define MEM_REGION_FLAG_READONLY (1 << 2)
#define MEM_REGION_FLAG_EXECUTOR_CODE (1 << 3)
#define MEM_REGION_FLAG_EXCEPTION_VEC (1 << 4)
#define MEM_REGION_FLAG_NO_HOST_MEM (1 << 6)

struct mem_region {
	uint64 gpa;
	int pages;
	uint32 flags;
};

// SYZOS guest virtual memory layout (must be in sync with executor/kvm.h):
static const struct mem_region syzos_mem_regions[] = {
    // Exception vector table (1 page at 0x1000).
    {RISCV64_ADDR_EXCEPTION_VECTOR, 1, MEM_REGION_FLAG_READONLY | MEM_REGION_FLAG_EXCEPTION_VEC},
    // CLINT at 0x02000000 (MMIO, no memory).
    {RISCV64_ADDR_CLINT, 1, MEM_REGION_FLAG_NO_HOST_MEM},
    // PLIC at 0x0c000000 (MMIO, no memory).
    {RISCV64_ADDR_PLIC, 1, MEM_REGION_FLAG_NO_HOST_MEM},
    // Unmapped region to trigger page faults (1 page at 0x40000000).
    {RISCV64_ADDR_EXIT, 1, MEM_REGION_FLAG_NO_HOST_MEM},
    // Writable region with KVM_MEM_LOG_DIRTY_PAGES (2 pages).
    {RISCV64_ADDR_DIRTY_PAGES, 2, MEM_REGION_FLAG_DIRTY_LOG},
    // User code (KVM_MAX_VCPU pages, starting at 0x80000000).
    {RISCV64_ADDR_USER_CODE, KVM_MAX_VCPU, MEM_REGION_FLAG_READONLY | MEM_REGION_FLAG_USER_CODE},
    // Executor guest code (4 pages).
    {SYZOS_ADDR_EXECUTOR_CODE, 4, MEM_REGION_FLAG_READONLY | MEM_REGION_FLAG_EXECUTOR_CODE},
    // Scratch memory for runtime code (1 page).
    {RISCV64_ADDR_SCRATCH_CODE, 1, 0},
    // Per-vCPU stacks (1 page).
    {RISCV64_ADDR_STACK_BASE, 1, 0},
};

static void setup_vm(int vmfd, struct kvm_syz_vm* vm)
{
	struct addr_size allocator = {.addr = vm->host_mem, .size = vm->total_pages * KVM_PAGE_SIZE};
	int slot = 0; // Slot numbers do not matter, they just have to be different.

	for (size_t i = 0; i < sizeof(syzos_mem_regions) / sizeof(syzos_mem_regions[0]); i++) {
		const struct mem_region* r = &syzos_mem_regions[i];
		if (r->flags & MEM_REGION_FLAG_NO_HOST_MEM)
			continue;
		struct addr_size next = alloc_guest_mem(&allocator, r->pages * KVM_PAGE_SIZE);
		uint32 flags = 0;
		if (r->flags & MEM_REGION_FLAG_DIRTY_LOG)
			flags |= KVM_MEM_LOG_DIRTY_PAGES;
		if (r->flags & MEM_REGION_FLAG_READONLY)
			flags |= KVM_MEM_READONLY;
		if (r->flags & MEM_REGION_FLAG_USER_CODE)
			vm->user_text = next.addr;
		if (r->flags & MEM_REGION_FLAG_EXCEPTION_VEC)
			memcpy(next.addr, (void*)guest_unexp_trap, MIN(KVM_PAGE_SIZE, (size_t)((char*)__stop_guest - (char*)guest_unexp_trap)));
		if (r->flags & MEM_REGION_FLAG_EXECUTOR_CODE)
			install_syzos_code(next.addr, next.size);
		vm_set_user_memory_region(vmfd, slot++, flags, r->gpa, next.size, (uintptr_t)next.addr);
	}

	// Map the remaining pages at an unused address.
	if (allocator.size > 0) {
		struct addr_size next = alloc_guest_mem(&allocator, allocator.size);
		vm_set_user_memory_region(vmfd, slot++, 0, 0, next.size, (uintptr_t)next.addr);
	}
}

static long syz_kvm_setup_syzos_vm(volatile long a0, volatile long a1)
{
	const int vmfd = a0;
	void* host_mem = (void*)a1;
	struct kvm_syz_vm* ret = (struct kvm_syz_vm*)host_mem;
	ret->host_mem = (void*)((uint64)host_mem + KVM_PAGE_SIZE);
	ret->total_pages = KVM_GUEST_PAGES - 1;
	setup_vm(vmfd, ret);
	ret->vmfd = vmfd;
	ret->next_cpu_id = 0;

	return (long)ret;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
// Set up CPU registers.
static void reset_cpu_regs(int cpufd, int cpu_id, size_t text_size)
{
	// PC points to the relative offset of guest_main() within the guest code.
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_PC), executor_fn_guest_addr(guest_main));
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_SP), RISCV64_ADDR_STACK_BASE + KVM_PAGE_SIZE - 128);
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_TP), cpu_id);
	// Pass parameters to guest_main().
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_A0), text_size);
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_A1), cpu_id);
	// Set SSTATUS and MODE.
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_MODE), 1);
	kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_SSTATUS), SSTATUS_SPP | SSTATUS_SPIE);
	// Set GP.
	unsigned long current_gp = 0;
	asm volatile("add %0, gp, zero"
		     : "=r"(current_gp)
		     :
		     : "memory");
	kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_GP), current_gp);
	// Set STVEC.
	kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_STVEC), RISCV64_ADDR_EXCEPTION_VECTOR);
}

static void install_user_code(int cpufd, void* user_text_slot, int cpu_id, const void* text, size_t text_size)
{
	if ((cpu_id < 0) || (cpu_id >= KVM_MAX_VCPU))
		return;
	if (!user_text_slot)
		return;
	if (text_size > KVM_PAGE_SIZE)
		text_size = KVM_PAGE_SIZE;
	void* target = (void*)((uint64)user_text_slot + (KVM_PAGE_SIZE * cpu_id));
	memcpy(target, text, text_size);
	reset_cpu_regs(cpufd, cpu_id, text_size);
}

static long syz_kvm_add_vcpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	struct kvm_syz_vm* vm = (struct kvm_syz_vm*)a0;
	struct kvm_text* utext = (struct kvm_text*)a1;
	const void* text = utext->text;
	size_t text_size = utext->size;

	if (!vm) {
		errno = EINVAL;
		return -1;
	}
	if (vm->next_cpu_id == KVM_MAX_VCPU) {
		errno = ENOMEM;
		return -1;
	}
	int cpu_id = vm->next_cpu_id;
	int cpufd = ioctl(vm->vmfd, KVM_CREATE_VCPU, cpu_id);
	if (cpufd == -1)
		return -1;
	// Only increment next_cpu_id if CPU creation succeeded.
	vm->next_cpu_id++;
	install_user_code(cpufd, vm->user_text, cpu_id, text, text_size);
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

	if (!run || (run->exit_reason != KVM_EXIT_MMIO) ||
	    (run->mmio.phys_addr != RISCV64_ADDR_UEXIT)) {
#if !SYZ_EXECUTOR
		fprintf(stderr, "[SYZOS-DEBUG] Assertion Triggered on VCPU %d\n", cpufd);
#endif
		errno = EINVAL;
		return -1;
	}

	uint64 actual_code = ((uint64*)(run->mmio.data))[0];
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

#endif // EXECUTOR_COMMON_KVM_RISCV64_H
