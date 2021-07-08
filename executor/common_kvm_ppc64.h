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
#define PPC_BITMASK(bs, be) ((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))

#define RADIX_PTE_INDEX_SIZE 5 // size: 8B <<  5 = 256B, maps 2^5  x   64K =   2MB
#define RADIX_PMD_INDEX_SIZE 9 // size: 8B <<  9 =  4KB, maps 2^9  x   2MB =   1GB
#define RADIX_PUD_INDEX_SIZE 9 // size: 8B <<  9 =  4KB, maps 2^9  x   1GB = 512GB
#define RADIX_PGD_INDEX_SIZE 13 // size: 8B << 13 = 64KB, maps 2^13 x 512GB =   4PB

#define cpu_to_be32(x) __builtin_bswap32(x)
#define cpu_to_be64(x) __builtin_bswap64(x)
#define be64_to_cpu(x) __builtin_bswap64(x)

#define LPCR_ILE PPC_BIT(38)
#define LPCR_UPRT PPC_BIT(41) // Use Process Table
#define LPCR_EVIRT PPC_BIT(42) // Enhanced Virtualisation
#define LPCR_HR PPC_BIT(43) // Host Radix
#ifndef KVM_REG_PPC_LPCR_64
#define KVM_REG_PPC_LPCR_64 (KVM_REG_PPC | KVM_REG_SIZE_U64 | 0xb5)
#endif

#define PRTB_SIZE_SHIFT 12 // log2((64 << 10) / 16)
#define PATB_GR (1UL << 63) // guest uses radix; must match HR
#define PATB_HR (1UL << 63)
#define PRTB_MASK 0x0ffffffffffff000UL

#define ALIGNUP(p, q) ((void*)(((unsigned long)(p) + (q)-1) & ~((q)-1)))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#ifndef KVM_REG_PPC_DEC_EXPIRY
#define KVM_REG_PPC_DEC_EXPIRY (KVM_REG_PPC | KVM_REG_SIZE_U64 | 0xbe)
#endif

#ifndef KVM_PPC_CONFIGURE_V3_MMU
// Available with KVM_CAP_PPC_RADIX_MMU or KVM_CAP_PPC_HASH_MMU_V3
#define KVM_PPC_CONFIGURE_V3_MMU _IOW(KVMIO, 0xaf, struct kvm_ppc_mmuv3_cfg)

// For KVM_PPC_CONFIGURE_V3_MMU
struct kvm_ppc_mmuv3_cfg {
	__u64 flags;
	__u64 process_table; // second doubleword of partition table entry
};

// Flag values for KVM_PPC_CONFIGURE_V3_MMU
#define KVM_PPC_MMUV3_RADIX 1 // 1 = radix mode, 0 = HPT
#define KVM_PPC_MMUV3_GTSE 2 // global translation shootdown enb
#endif

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

static int kvmppc_define_rtas_kernel_token(int vmfd, unsigned token, const char* func)
{
	struct kvm_rtas_token_args args;

	args.token = token;
	strncpy(args.name, func, sizeof(args.name) - 1);

	return ioctl(vmfd, KVM_PPC_RTAS_DEFINE_TOKEN, &args);
}

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
#define KVM_SETUP_PPC64_IR (1 << 1) // Paging for instructions
#define KVM_SETUP_PPC64_DR (1 << 2) // Paging for data
#define KVM_SETUP_PPC64_PR (1 << 3) // Run with MSR_PR (==usermode)
#define KVM_SETUP_PPC64_PID1 (1 << 4) // Set PID=1 i.e. not kernel's PID

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
	uint64 pid = 0;
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

	// PR == "problem state" == non priveledged == userspace
	if (flags & KVM_SETUP_PPC64_PR) {
		regs.msr |= PPC_BIT(49);
		// When PR=1, the hardware enforces IR and DR as well.
		flags |= KVM_SETUP_PPC64_IR | KVM_SETUP_PPC64_DR | KVM_SETUP_PPC64_PID1;
	}

	if (flags & KVM_SETUP_PPC64_IR)
		regs.msr |= PPC_BIT(58); // IR - MMU=on for instructions
	if (flags & KVM_SETUP_PPC64_DR)
		regs.msr |= PPC_BIT(59); // DR - MMU=on for data
	if (flags & KVM_SETUP_PPC64_PID1)
		pid = 1;

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

	// Set up a radix page table, the hash mode is not supported
	if (flags & (KVM_SETUP_PPC64_IR | KVM_SETUP_PPC64_DR)) {
		uintptr_t process_tb_off = gpa_off;
		unsigned long process_tb_size = 1UL << (PRTB_SIZE_SHIFT + 4);
		struct prtb_entry {
			__be64 prtb0;
			__be64 prtb1;
		}* process_tb = (struct prtb_entry*)(host_mem + gpa_off);

		memset(process_tb, 0xcc, process_tb_size);

		// PRTB_SIZE_SHIFT is defined to use 64K for the process table
		gpa_off += process_tb_size;

		unsigned long *pgd, *pud, *pmd, *pte, i;

		// Create 4 level page table, just like Linux does for PAGE_SIZE==64K,
		// put each level to a separate page including the last level which won't
		// need more than as we only allocate 24 pages for the entire VM.
		uintptr_t pgd_off = gpa_off;
		pgd = (unsigned long*)(host_mem + pgd_off);
		gpa_off += page_size;
		uintptr_t pud_off = gpa_off;
		pud = (unsigned long*)(host_mem + pud_off);
		gpa_off += page_size;
		uintptr_t pmd_off = gpa_off;
		pmd = (unsigned long*)(host_mem + pmd_off);
		gpa_off += page_size;
		uintptr_t pte_off = gpa_off;
		pte = (unsigned long*)(host_mem + pte_off);
		gpa_off += page_size;

		memset(pgd, 0, page_size);
		memset(pud, 0, page_size);
		memset(pmd, 0, page_size);
		memset(pte, 0, page_size);
		pgd[0] = cpu_to_be64(PPC_BIT(0) | // Valid
				     (pud_off & PPC_BITMASK(4, 55)) |
				     RADIX_PUD_INDEX_SIZE);
		pud[0] = cpu_to_be64(PPC_BIT(0) | // Valid
				     (pmd_off & PPC_BITMASK(4, 55)) |
				     RADIX_PMD_INDEX_SIZE);
		pmd[0] = cpu_to_be64(PPC_BIT(0) | // Valid
				     (pte_off & PPC_BITMASK(4, 55)) |
				     RADIX_PTE_INDEX_SIZE);

		// Map all 24 pages and allow write+execute for better coverage.
		for (i = 0; i < 24; ++i)
			pte[i] = cpu_to_be64(PPC_BIT(0) | // Valid
					     PPC_BIT(1) | // Leaf
					     ((i * page_size) & PPC_BITMASK(7, 51)) |
					     PPC_BIT(55) | // Reference
					     PPC_BIT(56) | // Change
					     PPC_BIT(61) | // Read permitted
					     PPC_BIT(62) | // Write permitted
					     PPC_BIT(63)); // Execute permitted

		const long max_shift = 52;
		const unsigned long rts = (max_shift - 31) & 0x1f;
		const unsigned long rts1 = (rts >> 3) << PPC_BITLSHIFT(2);
		const unsigned long rts2 = (rts & 7) << PPC_BITLSHIFT(58);

		process_tb[0].prtb0 = cpu_to_be64(PATB_HR | rts1 | pgd_off | rts2 | RADIX_PGD_INDEX_SIZE);
		if (pid)
			process_tb[pid].prtb0 = cpu_to_be64(PATB_HR | rts1 | pgd_off | rts2 | RADIX_PGD_INDEX_SIZE);

		// PATB_GR is not in the spec but KVM HV wants it for some reason
		struct kvm_ppc_mmuv3_cfg cfg = {
		    .flags = KVM_PPC_MMUV3_RADIX | KVM_PPC_MMUV3_GTSE,
		    .process_table = (process_tb_off & PRTB_MASK) | (PRTB_SIZE_SHIFT - 12) | PATB_GR,
		};
		if (ioctl(vmfd, KVM_PPC_CONFIGURE_V3_MMU, &cfg))
			return -1;

		lpcr |= LPCR_UPRT | LPCR_HR;
#ifdef DEBUG
		printf("MMUv3: flags=%lx %016lx\n", cfg.flags, cfg.process_table);
		printf("PTRB0=%016lx PGD0=%016lx PUD0=%016lx PMD0=%016lx\n",
		       be64_to_cpu((unsigned long)process_tb[0].prtb0), be64_to_cpu((unsigned long)pgd[0]),
		       be64_to_cpu((unsigned long)pud[0]), be64_to_cpu((unsigned long)pmd[0]));
		printf("PTEs @%lx:\n  %016lx %016lx %016lx %016lx\n  %016lx %016lx %016lx %016lx\n",
		       pte_off,
		       be64_to_cpu((unsigned long)pte[0]), be64_to_cpu((unsigned long)pte[1]),
		       be64_to_cpu((unsigned long)pte[2]), be64_to_cpu((unsigned long)pte[3]),
		       be64_to_cpu((unsigned long)pte[4]), be64_to_cpu((unsigned long)pte[5]),
		       be64_to_cpu((unsigned long)pte[6]), be64_to_cpu((unsigned long)pte[7]));
#endif
	}

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
	if (kvmppc_set_one_reg(cpufd, KVM_REG_PPC_PID, &pid))
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

	// Only a few of many RTAS calls are actually in the KVM and the rest
	// are handled in QEMU, enable the KVM handling for those 4 here.
	kvmppc_define_rtas_kernel_token(vmfd, 1, "ibm,set-xive");
	kvmppc_define_rtas_kernel_token(vmfd, 2, "ibm,get-xive");
	kvmppc_define_rtas_kernel_token(vmfd, 3, "ibm,int-on");
	kvmppc_define_rtas_kernel_token(vmfd, 4, "ibm,int-off");

	dump_text(host_mem, regs.pc, 8, debug_inst_opcode);
	dump_text(host_mem, BOOK3S_INTERRUPT_DECREMENTER, 16, debug_inst_opcode);

	uint64 decr = 0x7fffffff;
	if (kvmppc_set_one_reg(cpufd, KVM_REG_PPC_DEC_EXPIRY, &decr))
		return -1;

	return 0;
}
