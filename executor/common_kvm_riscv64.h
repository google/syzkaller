// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_RISCV64_H
#define EXECUTOR_COMMON_KVM_RISCV64_H

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
struct kvm_text {
	uintptr_t type;
	const void* text;
	uintptr_t size;
};

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

// Define the starting physical address for the guest code.
#define CODE_START 0x80000000ULL

// Set a single register value for the specified CPU file descriptor.
static inline int kvm_set_reg(int cpufd, unsigned long id, unsigned long value)
{
	struct kvm_one_reg reg = {
	    .id = id,
	    .addr = (unsigned long)&value,
	};
	return ioctl(cpufd, KVM_SET_ONE_REG, &reg);
}

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
		    .guest_phys_addr = CODE_START + i * page_size,
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

	// Initialize VCPU registers.
	// Set PC (program counter) to start of code.
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_PC), CODE_START))
		return -1;
	// Set SP (stack pointer) at end of memory, reserving space for stack.
	unsigned long stack_top = CODE_START + guest_mem_size - page_size;
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
	unsigned long stvec = CODE_START + page_size;
	if (kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_STVEC), stvec))
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

#endif // EXECUTOR_COMMON_KVM_RISCV64_H