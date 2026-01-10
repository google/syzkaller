// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_RISCV64_H
#define EXECUTOR_COMMON_KVM_RISCV64_H

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

struct kvm_text {
	uintptr_t type;
	const void* text;
	uintptr_t size;
};

// RISC-V register ID construction macros
#define RISCV_CORE_REG(idx) (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | (idx))
#define RISCV_CSR_REG(idx) (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CSR | (idx))

// CSR register indices in kvm_riscv_csr struct
#define CSR_SSTATUS 0
#define CSR_SIE 1
#define CSR_STVEC 2
#define CSR_SSCRATCH 3
#define CSR_SEPC 4
#define CSR_SCAUSE 5
#define CSR_STVAL 6
#define CSR_SIP 7
#define CSR_SATP 8

// CORE register indices
#define CORE_PC 0x00
#define CORE_RA 0x01
#define CORE_SP 0x02
#define CORE_GP 0x03
#define CORE_TP 0x04
#define CORE_T0 0x05
#define CORE_T1 0x06
#define CORE_T2 0x07
#define CORE_S0 0x08
#define CORE_S1 0x09
#define CORE_A0 0x0a
#define CORE_A1 0x0b
#define CORE_A2 0x0c
#define CORE_A3 0x0d
#define CORE_A4 0x0e
#define CORE_A5 0x0f
#define CORE_A6 0x10
#define CORE_A7 0x11
#define CORE_S2 0x12
#define CORE_S3 0x13
#define CORE_S4 0x14
#define CORE_S5 0x15
#define CORE_S6 0x16
#define CORE_S7 0x17
#define CORE_S8 0x18
#define CORE_S9 0x19
#define CORE_S10 0x1a
#define CORE_S11 0x1b
#define CORE_T3 0x1c
#define CORE_T4 0x1d
#define CORE_T5 0x1e
#define CORE_T6 0x1f
#define CORE_MODE 0x20 // Privilege mode: 1=S-mode, 0=U-mode

// SSTATUS register bit definitions
#define SSTATUS_SPP (1UL << 8) // Previous privilege (0=User, 1=Supervisor)
#define SSTATUS_SPIE (1UL << 5) // Previous interrupt enable
#define SSTATUS_SIE (1UL << 1) // Supervisor interrupt enable

// Helper function to set a register
static inline int kvm_set_reg(int cpufd, unsigned long id, unsigned long value)
{
	struct kvm_one_reg reg = {
	    .id = id,
	    .addr = (unsigned long)&value,
	};
	return ioctl(cpufd, KVM_SET_ONE_REG, &reg);
}

#define CODE_START 0x80000000ULL

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

	ioctl(vmfd, KVM_GET_API_VERSION, NULL);

	// ---- 1. Install guest memory ----
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

	// ---- 2. Copy guest text ----
	const void* text = 0;
	uintptr_t size = 0;

	NONFAILING(text = text_array_ptr[0].text);
	NONFAILING(size = text_array_ptr[0].size);

	if (size > guest_mem_size)
		size = guest_mem_size;

	memcpy(host_mem, text, size);

	// ---- 3. Initialize VCPU registers ----

	// Set PC (program counter) to start of code
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_PC), CODE_START))
		return -1;

	// Set SP (stack pointer) at end of memory, reserving space for stack
	unsigned long stack_top = CODE_START + guest_mem_size - page_size;
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_SP), stack_top))
		return -1;

	// Set privilege mode to S-mode (Supervisor mode)
	if (kvm_set_reg(cpufd, RISCV_CORE_REG(CORE_MODE), 1))
		return -1;

	// Set SSTATUS CSR with SPP (previous privilege) and SPIE (previous interrupt enable)
	unsigned long sstatus = SSTATUS_SPP | SSTATUS_SPIE;
	if (kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_SSTATUS), sstatus))
		return -1;

	// Set STVEC (exception vector address)
	unsigned long stvec = CODE_START + page_size;
	if (kvm_set_reg(cpufd, RISCV_CSR_REG(CSR_STVEC), stvec))
		return -1;

	return 0;
}

#endif // EXECUTOR_COMMON_KVM_RISCV64_H