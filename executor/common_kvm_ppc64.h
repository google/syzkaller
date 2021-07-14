// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

#include "kvm_ppc64le.S.h"

#define BOOK3S_INTERRUPT_SYSTEM_RESET 0x100
#define BOOK3S_INTERRUPT_MACHINE_CHECK 0x200
#define BOOK3S_INTERRUPT_DATA_STORAGE 0x300
#define BOOK3S_INTERRUPT_DATA_SEGMENT 0x380
#define BOOK3S_INTERRUPT_INST_STORAGE 0x400
#define BOOK3S_INTERRUPT_INST_SEGMENT 0x480
#define BOOK3S_INTERRUPT_EXTERNAL 0x500
#define BOOK3S_INTERRUPT_EXTERNAL_HV 0x502
#define BOOK3S_INTERRUPT_ALIGNMENT 0x600
#define BOOK3S_INTERRUPT_PROGRAM 0x700
#define BOOK3S_INTERRUPT_FP_UNAVAIL 0x800
#define BOOK3S_INTERRUPT_DECREMENTER 0x900
#define BOOK3S_INTERRUPT_HV_DECREMENTER 0x980
#define BOOK3S_INTERRUPT_DOORBELL 0xa00
#define BOOK3S_INTERRUPT_SYSCALL 0xc00
#define BOOK3S_INTERRUPT_TRACE 0xd00
#define BOOK3S_INTERRUPT_H_DATA_STORAGE 0xe00
#define BOOK3S_INTERRUPT_H_INST_STORAGE 0xe20
#define BOOK3S_INTERRUPT_H_EMUL_ASSIST 0xe40
#define BOOK3S_INTERRUPT_HMI 0xe60
#define BOOK3S_INTERRUPT_H_DOORBELL 0xe80
#define BOOK3S_INTERRUPT_H_VIRT 0xea0
#define BOOK3S_INTERRUPT_PERFMON 0xf00
#define BOOK3S_INTERRUPT_ALTIVEC 0xf20
#define BOOK3S_INTERRUPT_VSX 0xf40
#define BOOK3S_INTERRUPT_FAC_UNAVAIL 0xf60
#define BOOK3S_INTERRUPT_H_FAC_UNAVAIL 0xf80

#define BITS_PER_LONG 64
#define PPC_BITLSHIFT(be) (BITS_PER_LONG - 1 - (be))
#define PPC_BIT(bit) (1ULL << PPC_BITLSHIFT(bit))

#define cpu_to_be32(x) __builtin_bswap32(x)
#define LPCR_ILE PPC_BIT(38)
#ifndef KVM_REG_PPC_LPCR_64
#define KVM_REG_PPC_LPCR_64 (KVM_REG_PPC | KVM_REG_SIZE_U64 | 0xb5)
#endif
#ifndef KVM_REG_PPC_DEC_EXPIRY
#define KVM_REG_PPC_DEC_EXPIRY (KVM_REG_PPC | KVM_REG_SIZE_U64 | 0xbe)
#endif

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

static int kvmppc_get_one_reg(int cpufd, uint64 id, void* target)
{
	struct kvm_one_reg reg = {.id = id, .addr = (uintptr_t)target};

	return ioctl(cpufd, KVM_GET_ONE_REG, &reg);
}

static int kvmppc_set_one_reg(int cpufd, uint64 id, void* target)
{
	struct kvm_one_reg reg = {.id = id, .addr = (uintptr_t)target};

	return ioctl(cpufd, KVM_SET_ONE_REG, &reg);
}

static int kvm_vcpu_enable_cap(int cpufd, uint32 capability)
{
	struct kvm_enable_cap cap = {
	    .cap = capability,
	};
	return ioctl(cpufd, KVM_ENABLE_CAP, &cap);
}

static void dump_text(const char* mem, unsigned start, unsigned cw, uint32 debug_inst_opcode)
{
#ifdef DEBUG
	printf("Text @%x: ", start);

	for (unsigned i = 0; i < cw; ++i) {
		uint32 w = ((uint32*)(mem + start))[i];

		printf(" %08x", w);
		if (debug_inst_opcode && debug_inst_opcode == w)
			break;
	}

	printf("\n");
#endif
}

// Flags
#define KVM_SETUP_PPC64_LE (1 << 0) // Little endian

// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags_ppc64], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	char* const host_mem = (char*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;
	const uintptr_t text_count = a4;
	uintptr_t flags = a5;
	const uintptr_t page_size = 0x10000; // SYZ_PAGE_SIZE
	const uintptr_t guest_mem_size = 24 * page_size; // vma[24] from dev_kvm.txt
	unsigned long gpa_off = 0;
	uint32 debug_inst_opcode = 0;

	(void)text_count; // fuzzer can spoof count and we need just 1 text, so ignore text_count
	const void* text = 0;
	uintptr_t text_size = 0;
	uint64 lpcr = 0;
	NONFAILING(text = text_array_ptr[0].text);
	NONFAILING(text_size = text_array_ptr[0].size);

	if (kvm_vcpu_enable_cap(cpufd, KVM_CAP_PPC_PAPR))
		return -1;

	for (uintptr_t i = 0; i < guest_mem_size / page_size; i++) {
		struct kvm_userspace_memory_region memreg;
		memreg.slot = i;
		memreg.flags = 0; // can be KVM_MEM_LOG_DIRTY_PAGES but not KVM_MEM_READONLY
		memreg.guest_phys_addr = i * page_size;
		memreg.memory_size = page_size;
		memreg.userspace_addr = (uintptr_t)host_mem + i * page_size;
		if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg)) {
			return -1;
		}
	}

	struct kvm_regs regs;
	struct kvm_sregs sregs;
	if (ioctl(cpufd, KVM_GET_SREGS, &sregs))
		return -1;
	if (ioctl(cpufd, KVM_GET_REGS, &regs))
		return -1;

	regs.msr = PPC_BIT(0); // MSR_SF == Sixty Four == 64bit
	if (flags & KVM_SETUP_PPC64_LE)
		regs.msr |= PPC_BIT(63); // Little endian

	// KVM HV on POWER is hard to force to exit, it will bounce between
	// the fault handlers in KVM and the VM. Forcing all exception
	// vectors to do software debug breakpoint ensures the exit from KVM.
	if (kvmppc_get_one_reg(cpufd, KVM_REG_PPC_DEBUG_INST, &debug_inst_opcode))
		return -1;

#define VEC(x) (*((uint32*)(host_mem + (x))))
	VEC(BOOK3S_INTERRUPT_SYSTEM_RESET) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_MACHINE_CHECK) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_DATA_STORAGE) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_DATA_SEGMENT) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_INST_STORAGE) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_INST_SEGMENT) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_EXTERNAL) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_EXTERNAL_HV) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_ALIGNMENT) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_PROGRAM) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_FP_UNAVAIL) = debug_inst_opcode;
	memcpy(host_mem + BOOK3S_INTERRUPT_DECREMENTER, kvm_ppc64_recharge_dec, sizeof(kvm_ppc64_recharge_dec) - 1);
	VEC(BOOK3S_INTERRUPT_DECREMENTER + sizeof(kvm_ppc64_recharge_dec) - 1) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_HV_DECREMENTER) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_DOORBELL) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_SYSCALL) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_TRACE) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_H_DATA_STORAGE) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_H_INST_STORAGE) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_H_EMUL_ASSIST) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_HMI) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_H_DOORBELL) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_H_VIRT) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_PERFMON) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_ALTIVEC) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_VSX) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_FAC_UNAVAIL) = debug_inst_opcode;
	VEC(BOOK3S_INTERRUPT_H_FAC_UNAVAIL) = debug_inst_opcode;

	struct kvm_guest_debug dbg = {0};
	dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;

	if (ioctl(cpufd, KVM_SET_GUEST_DEBUG, &dbg))
		return -1;

	// Exception vector occupy 128K, including "System Call Vectored"
	gpa_off = 128 << 10;

	memcpy(host_mem + gpa_off, text, text_size);
	regs.pc = gpa_off;

	uintptr_t end_of_text = gpa_off + ((text_size + 3) & ~3);
	memcpy(host_mem + end_of_text, &debug_inst_opcode, sizeof(debug_inst_opcode));

	// The code generator produces little endian instructions so swap bytes here
	if (!(flags & KVM_SETUP_PPC64_LE)) {
		uint32* p = (uint32*)(host_mem + gpa_off);
		for (unsigned long i = 0; i < text_size / sizeof(*p); ++i)
			p[i] = cpu_to_be32(p[i]);

		p = (uint32*)(host_mem + BOOK3S_INTERRUPT_DECREMENTER);
		for (unsigned long i = 0; i < sizeof(kvm_ppc64_recharge_dec) / sizeof(*p); ++i)
			p[i] = cpu_to_be32(p[i]);
	} else {
		// PPC by default calls exception handlers in big endian unless ILE
		lpcr |= LPCR_ILE;
	}

	if (ioctl(cpufd, KVM_SET_SREGS, &sregs))
		return -1;
	if (ioctl(cpufd, KVM_SET_REGS, &regs))
		return -1;
	if (kvmppc_set_one_reg(cpufd, KVM_REG_PPC_LPCR_64, &lpcr))
		return -1;

		// Hypercalls need to be enable so we enable them all here to
		// allow fuzzing
#define MAX_HCALL 0x450
	for (unsigned hcall = 4; hcall < MAX_HCALL; hcall += 4) {
		struct kvm_enable_cap cap = {
		    .cap = KVM_CAP_PPC_ENABLE_HCALL,
		    .flags = 0,
		    .args = {hcall, 1},
		};
		ioctl(vmfd, KVM_ENABLE_CAP, &cap);
	}

	dump_text(host_mem, regs.pc, 8, debug_inst_opcode);
	dump_text(host_mem, BOOK3S_INTERRUPT_DECREMENTER, 16, debug_inst_opcode);

	uint64 decr = 0x7fffffff;
	if (kvmppc_set_one_reg(cpufd, KVM_REG_PPC_DEC_EXPIRY, &decr))
		return -1;

	return 0;
}
