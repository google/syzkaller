// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.
// See Intel Software Developer’s Manual Volume 3: System Programming Guide
// for details on what happens here.

#include "kvm.S.h"
#include "kvm.h"

#ifndef KVM_SMI
#define KVM_SMI _IO(KVMIO, 0xb7)
#endif

#define CR0_PE 1
#define CR0_MP (1 << 1)
#define CR0_EM (1 << 2)
#define CR0_TS (1 << 3)
#define CR0_ET (1 << 4)
#define CR0_NE (1 << 5)
#define CR0_WP (1 << 16)
#define CR0_AM (1 << 18)
#define CR0_NW (1 << 29)
#define CR0_CD (1 << 30)
#define CR0_PG (1 << 31)

#define CR4_VME 1
#define CR4_PVI (1 << 1)
#define CR4_TSD (1 << 2)
#define CR4_DE (1 << 3)
#define CR4_PSE (1 << 4)
#define CR4_PAE (1 << 5)
#define CR4_MCE (1 << 6)
#define CR4_PGE (1 << 7)
#define CR4_PCE (1 << 8)
#define CR4_OSFXSR (1 << 8)
#define CR4_OSXMMEXCPT (1 << 10)
#define CR4_UMIP (1 << 11)
#define CR4_VMXE (1 << 13)
#define CR4_SMXE (1 << 14)
#define CR4_FSGSBASE (1 << 16)
#define CR4_PCIDE (1 << 17)
#define CR4_OSXSAVE (1 << 18)
#define CR4_SMEP (1 << 20)
#define CR4_SMAP (1 << 21)
#define CR4_PKE (1 << 22)

#define EFER_SCE 1
#define EFER_LME (1 << 8)
#define EFER_LMA (1 << 10)
#define EFER_NXE (1 << 11)
#define EFER_SVME (1 << 12)
#define EFER_LMSLE (1 << 13)
#define EFER_FFXSR (1 << 14)
#define EFER_TCE (1 << 15)

// 32-bit page directory entry bits
#define PDE32_PRESENT 1
#define PDE32_RW (1 << 1)
#define PDE32_USER (1 << 2)
#define PDE32_PS (1 << 7)

// 64-bit page * entry bits
#define PDE64_PRESENT 1
#define PDE64_RW (1 << 1)
#define PDE64_USER (1 << 2)
#define PDE64_ACCESSED (1 << 5)
#define PDE64_DIRTY (1 << 6)
#define PDE64_PS (1 << 7)
#define PDE64_G (1 << 8)

struct tss16 {
	uint16 prev;
	uint16 sp0;
	uint16 ss0;
	uint16 sp1;
	uint16 ss1;
	uint16 sp2;
	uint16 ss2;
	uint16 ip;
	uint16 flags;
	uint16 ax;
	uint16 cx;
	uint16 dx;
	uint16 bx;
	uint16 sp;
	uint16 bp;
	uint16 si;
	uint16 di;
	uint16 es;
	uint16 cs;
	uint16 ss;
	uint16 ds;
	uint16 ldt;
} __attribute__((packed));

struct tss32 {
	uint16 prev, prevh;
	uint32 sp0;
	uint16 ss0, ss0h;
	uint32 sp1;
	uint16 ss1, ss1h;
	uint32 sp2;
	uint16 ss2, ss2h;
	uint32 cr3;
	uint32 ip;
	uint32 flags;
	uint32 ax;
	uint32 cx;
	uint32 dx;
	uint32 bx;
	uint32 sp;
	uint32 bp;
	uint32 si;
	uint32 di;
	uint16 es, esh;
	uint16 cs, csh;
	uint16 ss, ssh;
	uint16 ds, dsh;
	uint16 fs, fsh;
	uint16 gs, gsh;
	uint16 ldt, ldth;
	uint16 trace;
	uint16 io_bitmap;
} __attribute__((packed));

struct tss64 {
	uint32 reserved0;
	uint64 rsp[3];
	uint64 reserved1;
	uint64 ist[7];
	uint64 reserved2;
	uint32 reserved3;
	uint32 io_bitmap;
} __attribute__((packed));

static void fill_segment_descriptor(uint64* dt, uint64* lt, struct kvm_segment* seg)
{
	uint16 index = seg->selector >> 3;
	uint64 limit = seg->g ? seg->limit >> 12 : seg->limit;
	uint64 sd = (limit & 0xffff) | (seg->base & 0xffffff) << 16 | (uint64)seg->type << 40 | (uint64)seg->s << 44 | (uint64)seg->dpl << 45 | (uint64)seg->present << 47 | (limit & 0xf0000ULL) << 48 | (uint64)seg->avl << 52 | (uint64)seg->l << 53 | (uint64)seg->db << 54 | (uint64)seg->g << 55 | (seg->base & 0xff000000ULL) << 56;
	dt[index] = sd;
	lt[index] = sd;
}

static void fill_segment_descriptor_dword(uint64* dt, uint64* lt, struct kvm_segment* seg)
{
	fill_segment_descriptor(dt, lt, seg);
	uint16 index = seg->selector >> 3;
	dt[index + 1] = 0;
	lt[index + 1] = 0;
}

static void setup_syscall_msrs(int cpufd, uint16 sel_cs, uint16 sel_cs_cpl3)
{
	char buf[sizeof(struct kvm_msrs) + 5 * sizeof(struct kvm_msr_entry)];
	memset(buf, 0, sizeof(buf));
	struct kvm_msrs* msrs = (struct kvm_msrs*)buf;
	struct kvm_msr_entry* entries = msrs->entries;
	msrs->nmsrs = 5;
	entries[0].index = MSR_IA32_SYSENTER_CS;
	entries[0].data = sel_cs;
	entries[1].index = MSR_IA32_SYSENTER_ESP;
	entries[1].data = ADDR_STACK0;
	entries[2].index = MSR_IA32_SYSENTER_EIP;
	entries[2].data = ADDR_VAR_SYSEXIT;
	entries[3].index = MSR_IA32_STAR;
	entries[3].data = ((uint64)sel_cs << 32) | ((uint64)sel_cs_cpl3 << 48);
	entries[4].index = MSR_IA32_LSTAR;
	entries[4].data = ADDR_VAR_SYSRET;
	ioctl(cpufd, KVM_SET_MSRS, msrs);
}

static void setup_32bit_idt(struct kvm_sregs* sregs, char* host_mem, uintptr_t guest_mem)
{
	sregs->idt.base = guest_mem + ADDR_VAR_IDT;
	sregs->idt.limit = 0x1ff;
	uint64* idt = (uint64*)(host_mem + sregs->idt.base);
	for (int i = 0; i < 32; i++) {
		struct kvm_segment gate;
		gate.selector = i << 3;
		switch (i % 6) {
		case 0:
			// 16-bit interrupt gate
			gate.type = 6;
			gate.base = SEL_CS16;
			break;
		case 1:
			// 16-bit trap gate
			gate.type = 7;
			gate.base = SEL_CS16;
			break;
		case 2:
			// 16-bit task gate
			gate.type = 3;
			gate.base = SEL_TGATE16;
			break;
		case 3:
			// 32-bit interrupt gate
			gate.type = 14;
			gate.base = SEL_CS32;
			break;
		case 4:
			// 32-bit trap gate
			gate.type = 15;
			gate.base = SEL_CS32;
			break;
		case 5:
			// 32-bit task gate
			gate.type = 11;
			gate.base = SEL_TGATE32;
			break;
		}
		gate.limit = guest_mem + ADDR_VAR_USER_CODE2; // entry offset
		gate.present = 1;
		gate.dpl = 0;
		gate.s = 0;
		gate.g = 0;
		gate.db = 0;
		gate.l = 0;
		gate.avl = 0;
		fill_segment_descriptor(idt, idt, &gate);
	}
}

static void setup_64bit_idt(struct kvm_sregs* sregs, char* host_mem, uintptr_t guest_mem)
{
	sregs->idt.base = guest_mem + ADDR_VAR_IDT;
	sregs->idt.limit = 0x1ff;
	uint64* idt = (uint64*)(host_mem + sregs->idt.base);
	for (int i = 0; i < 32; i++) {
		struct kvm_segment gate;
		gate.selector = (i * 2) << 3;
		gate.type = (i & 1) ? 14 : 15; // interrupt or trap gate
		gate.base = SEL_CS64;
		gate.limit = guest_mem + ADDR_VAR_USER_CODE2; // entry offset
		gate.present = 1;
		gate.dpl = 0;
		gate.s = 0;
		gate.g = 0;
		gate.db = 0;
		gate.l = 0;
		gate.avl = 0;
		fill_segment_descriptor_dword(idt, idt, &gate);
	}
}

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};

#define KVM_SETUP_PAGING (1 << 0)
#define KVM_SETUP_PAE (1 << 1)
#define KVM_SETUP_PROTECTED (1 << 2)
#define KVM_SETUP_CPL3 (1 << 3)
#define KVM_SETUP_VIRT86 (1 << 4)
#define KVM_SETUP_SMM (1 << 5)
#define KVM_SETUP_VM (1 << 6)

// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	char* const host_mem = (char*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;
	const uintptr_t text_count = a4;
	const uintptr_t flags = a5;
	const struct kvm_opt* const opt_array_ptr = (struct kvm_opt*)a6;
	uintptr_t opt_count = a7;

	const uintptr_t page_size = 4 << 10;
	const uintptr_t ioapic_page = 10;
	const uintptr_t guest_mem_size = 24 * page_size;
	const uintptr_t guest_mem = 0;

	(void)text_count; // fuzzer can spoof count and we need just 1 text, so ignore text_count
	int text_type = text_array_ptr[0].typ;
	const void* text = text_array_ptr[0].text;
	uintptr_t text_size = text_array_ptr[0].size;

	for (uintptr_t i = 0; i < guest_mem_size / page_size; i++) {
		struct kvm_userspace_memory_region memreg;
		memreg.slot = i;
		memreg.flags = 0; // can be KVM_MEM_LOG_DIRTY_PAGES | KVM_MEM_READONLY
		memreg.guest_phys_addr = guest_mem + i * page_size;
		if (i == ioapic_page)
			memreg.guest_phys_addr = 0xfec00000;
		memreg.memory_size = page_size;
		memreg.userspace_addr = (uintptr_t)host_mem + i * page_size;
		ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
	}
	// SMRAM
	struct kvm_userspace_memory_region memreg;
	memreg.slot = 1 + (1 << 16);
	memreg.flags = 0;
	memreg.guest_phys_addr = 0x30000;
	memreg.memory_size = 64 << 10;
	memreg.userspace_addr = (uintptr_t)host_mem;
	ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);

	struct kvm_sregs sregs;
	if (ioctl(cpufd, KVM_GET_SREGS, &sregs))
		return -1;

	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	regs.rip = guest_mem + ADDR_TEXT;
	regs.rsp = ADDR_STACK0;

	sregs.gdt.base = guest_mem + ADDR_GDT;
	sregs.gdt.limit = 256 * sizeof(uint64) - 1;
	uint64* gdt = (uint64*)(host_mem + sregs.gdt.base);

	struct kvm_segment seg_ldt;
	seg_ldt.selector = SEL_LDT;
	seg_ldt.type = 2;
	seg_ldt.base = guest_mem + ADDR_LDT;
	seg_ldt.limit = 256 * sizeof(uint64) - 1;
	seg_ldt.present = 1;
	seg_ldt.dpl = 0;
	seg_ldt.s = 0;
	seg_ldt.g = 0;
	seg_ldt.db = 1;
	seg_ldt.l = 0;
	sregs.ldt = seg_ldt;
	uint64* ldt = (uint64*)(host_mem + sregs.ldt.base);

	struct kvm_segment seg_cs16;
	seg_cs16.selector = SEL_CS16;
	seg_cs16.type = 11;
	seg_cs16.base = 0;
	seg_cs16.limit = 0xfffff;
	seg_cs16.present = 1;
	seg_cs16.dpl = 0;
	seg_cs16.s = 1;
	seg_cs16.g = 0;
	seg_cs16.db = 0;
	seg_cs16.l = 0;

	struct kvm_segment seg_ds16 = seg_cs16;
	seg_ds16.selector = SEL_DS16;
	seg_ds16.type = 3;

	struct kvm_segment seg_cs16_cpl3 = seg_cs16;
	seg_cs16_cpl3.selector = SEL_CS16_CPL3;
	seg_cs16_cpl3.dpl = 3;

	struct kvm_segment seg_ds16_cpl3 = seg_ds16;
	seg_ds16_cpl3.selector = SEL_DS16_CPL3;
	seg_ds16_cpl3.dpl = 3;

	struct kvm_segment seg_cs32 = seg_cs16;
	seg_cs32.selector = SEL_CS32;
	seg_cs32.db = 1;

	struct kvm_segment seg_ds32 = seg_ds16;
	seg_ds32.selector = SEL_DS32;
	seg_ds32.db = 1;

	struct kvm_segment seg_cs32_cpl3 = seg_cs32;
	seg_cs32_cpl3.selector = SEL_CS32_CPL3;
	seg_cs32_cpl3.dpl = 3;

	struct kvm_segment seg_ds32_cpl3 = seg_ds32;
	seg_ds32_cpl3.selector = SEL_DS32_CPL3;
	seg_ds32_cpl3.dpl = 3;

	struct kvm_segment seg_cs64 = seg_cs16;
	seg_cs64.selector = SEL_CS64;
	seg_cs64.l = 1;

	struct kvm_segment seg_ds64 = seg_ds32;
	seg_ds64.selector = SEL_DS64;

	struct kvm_segment seg_cs64_cpl3 = seg_cs64;
	seg_cs64_cpl3.selector = SEL_CS64_CPL3;
	seg_cs64_cpl3.dpl = 3;

	struct kvm_segment seg_ds64_cpl3 = seg_ds64;
	seg_ds64_cpl3.selector = SEL_DS64_CPL3;
	seg_ds64_cpl3.dpl = 3;

	struct kvm_segment seg_tss32;
	seg_tss32.selector = SEL_TSS32;
	seg_tss32.type = 9;
	seg_tss32.base = ADDR_VAR_TSS32;
	seg_tss32.limit = 0x1ff;
	seg_tss32.present = 1;
	seg_tss32.dpl = 0;
	seg_tss32.s = 0;
	seg_tss32.g = 0;
	seg_tss32.db = 0;
	seg_tss32.l = 0;

	struct kvm_segment seg_tss32_2 = seg_tss32;
	seg_tss32_2.selector = SEL_TSS32_2;
	seg_tss32_2.base = ADDR_VAR_TSS32_2;

	struct kvm_segment seg_tss32_cpl3 = seg_tss32;
	seg_tss32_cpl3.selector = SEL_TSS32_CPL3;
	seg_tss32_cpl3.base = ADDR_VAR_TSS32_CPL3;

	struct kvm_segment seg_tss32_vm86 = seg_tss32;
	seg_tss32_vm86.selector = SEL_TSS32_VM86;
	seg_tss32_vm86.base = ADDR_VAR_TSS32_VM86;

	struct kvm_segment seg_tss16 = seg_tss32;
	seg_tss16.selector = SEL_TSS16;
	seg_tss16.base = ADDR_VAR_TSS16;
	seg_tss16.limit = 0xff;
	seg_tss16.type = 1;

	struct kvm_segment seg_tss16_2 = seg_tss16;
	seg_tss16_2.selector = SEL_TSS16_2;
	seg_tss16_2.base = ADDR_VAR_TSS16_2;
	seg_tss16_2.dpl = 0;

	struct kvm_segment seg_tss16_cpl3 = seg_tss16;
	seg_tss16_cpl3.selector = SEL_TSS16_CPL3;
	seg_tss16_cpl3.base = ADDR_VAR_TSS16_CPL3;
	seg_tss16_cpl3.dpl = 3;

	struct kvm_segment seg_tss64 = seg_tss32;
	seg_tss64.selector = SEL_TSS64;
	seg_tss64.base = ADDR_VAR_TSS64;
	seg_tss64.limit = 0x1ff;

	struct kvm_segment seg_tss64_cpl3 = seg_tss64;
	seg_tss64_cpl3.selector = SEL_TSS64_CPL3;
	seg_tss64_cpl3.base = ADDR_VAR_TSS64_CPL3;
	seg_tss64_cpl3.dpl = 3;

	struct kvm_segment seg_cgate16;
	seg_cgate16.selector = SEL_CGATE16;
	seg_cgate16.type = 4;
	seg_cgate16.base = SEL_CS16 | (2 << 16); // selector + param count
	seg_cgate16.limit = ADDR_VAR_USER_CODE2; // entry offset
	seg_cgate16.present = 1;
	seg_cgate16.dpl = 0;
	seg_cgate16.s = 0;
	seg_cgate16.g = 0;
	seg_cgate16.db = 0;
	seg_cgate16.l = 0;
	seg_cgate16.avl = 0;

	struct kvm_segment seg_tgate16 = seg_cgate16;
	seg_tgate16.selector = SEL_TGATE16;
	seg_tgate16.type = 3;
	seg_cgate16.base = SEL_TSS16_2;
	seg_tgate16.limit = 0;

	struct kvm_segment seg_cgate32 = seg_cgate16;
	seg_cgate32.selector = SEL_CGATE32;
	seg_cgate32.type = 12;
	seg_cgate32.base = SEL_CS32 | (2 << 16); // selector + param count

	struct kvm_segment seg_tgate32 = seg_cgate32;
	seg_tgate32.selector = SEL_TGATE32;
	seg_tgate32.type = 11;
	seg_tgate32.base = SEL_TSS32_2;
	seg_tgate32.limit = 0;

	struct kvm_segment seg_cgate64 = seg_cgate16;
	seg_cgate64.selector = SEL_CGATE64;
	seg_cgate64.type = 12;
	seg_cgate64.base = SEL_CS64;

	int kvmfd = open("/dev/kvm", O_RDWR);
	char buf[sizeof(struct kvm_cpuid2) + 128 * sizeof(struct kvm_cpuid_entry2)];
	memset(buf, 0, sizeof(buf));
	struct kvm_cpuid2* cpuid = (struct kvm_cpuid2*)buf;
	cpuid->nent = 128;
	ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid);
	ioctl(cpufd, KVM_SET_CPUID2, cpuid);
	close(kvmfd);

	const char* text_prefix = 0;
	int text_prefix_size = 0;
	char* host_text = host_mem + ADDR_TEXT;

	if (text_type == 8) {
		if (flags & KVM_SETUP_SMM) {
			if (flags & KVM_SETUP_PROTECTED) {
				sregs.cs = seg_cs16;
				sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds16;
				sregs.cr0 |= CR0_PE;
			} else {
				sregs.cs.selector = 0;
				sregs.cs.base = 0;
			}

			*(host_mem + ADDR_TEXT) = 0xf4; // hlt for rsm
			host_text = host_mem + 0x8000;

			ioctl(cpufd, KVM_SMI, 0);
		} else if (flags & KVM_SETUP_VIRT86) {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;
			sregs.cr0 |= CR0_PE;
			sregs.efer |= EFER_SCE;

			setup_syscall_msrs(cpufd, SEL_CS32, SEL_CS32_CPL3);
			setup_32bit_idt(&sregs, host_mem, guest_mem);

			if (flags & KVM_SETUP_PAGING) {
				uint64 pd_addr = guest_mem + ADDR_PD;
				uint64* pd = (uint64*)(host_mem + ADDR_PD);
				// A single 4MB page to cover the memory region
				pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
				sregs.cr3 = pd_addr;
				sregs.cr4 |= CR4_PSE;

				text_prefix = kvm_asm32_paged_vm86;
				text_prefix_size = sizeof(kvm_asm32_paged_vm86) - 1;
			} else {
				text_prefix = kvm_asm32_vm86;
				text_prefix_size = sizeof(kvm_asm32_vm86) - 1;
			}
		} else {
			sregs.cs.selector = 0;
			sregs.cs.base = 0;
		}
	} else if (text_type == 16) {
		if (flags & KVM_SETUP_CPL3) {
			sregs.cs = seg_cs16;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds16;

			text_prefix = kvm_asm16_cpl3;
			text_prefix_size = sizeof(kvm_asm16_cpl3) - 1;
		} else {
			sregs.cr0 |= CR0_PE;
			sregs.cs = seg_cs16;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds16;
		}
	} else if (text_type == 32) {
		sregs.cr0 |= CR0_PE;
		sregs.efer |= EFER_SCE;

		setup_syscall_msrs(cpufd, SEL_CS32, SEL_CS32_CPL3);
		setup_32bit_idt(&sregs, host_mem, guest_mem);

		if (flags & KVM_SETUP_SMM) {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;

			*(host_mem + ADDR_TEXT) = 0xf4; // hlt for rsm
			host_text = host_mem + 0x8000;

			ioctl(cpufd, KVM_SMI, 0);
		} else if (flags & KVM_SETUP_PAGING) {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;

			uint64 pd_addr = guest_mem + ADDR_PD;
			uint64* pd = (uint64*)(host_mem + ADDR_PD);
			// A single 4MB page to cover the memory region
			pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
			sregs.cr3 = pd_addr;
			sregs.cr4 |= CR4_PSE;

			text_prefix = kvm_asm32_paged;
			text_prefix_size = sizeof(kvm_asm32_paged) - 1;
		} else if (flags & KVM_SETUP_CPL3) {
			sregs.cs = seg_cs32_cpl3;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32_cpl3;
		} else {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;
		}
	} else {
		sregs.efer |= EFER_LME | EFER_SCE;
		sregs.cr0 |= CR0_PE;

		setup_syscall_msrs(cpufd, SEL_CS64, SEL_CS64_CPL3);
		setup_64bit_idt(&sregs, host_mem, guest_mem);

		sregs.cs = seg_cs32;
		sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;

		uint64 pml4_addr = guest_mem + ADDR_PML4;
		uint64* pml4 = (uint64*)(host_mem + ADDR_PML4);
		uint64 pdpt_addr = guest_mem + ADDR_PDP;
		uint64* pdpt = (uint64*)(host_mem + ADDR_PDP);
		uint64 pd_addr = guest_mem + ADDR_PD;
		uint64* pd = (uint64*)(host_mem + ADDR_PD);
		pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
		pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
		pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
		sregs.cr3 = pml4_addr;
		sregs.cr4 |= CR4_PAE;

		if (flags & KVM_SETUP_VM) {
			sregs.cr0 |= CR0_NE;

			*((uint64*)(host_mem + ADDR_VAR_VMXON_PTR)) = ADDR_VAR_VMXON;
			*((uint64*)(host_mem + ADDR_VAR_VMCS_PTR)) = ADDR_VAR_VMCS;
			memcpy(host_mem + ADDR_VAR_VMEXIT_CODE, kvm_asm64_vm_exit, sizeof(kvm_asm64_vm_exit) - 1);
			*((uint64*)(host_mem + ADDR_VAR_VMEXIT_PTR)) = ADDR_VAR_VMEXIT_CODE;

			text_prefix = kvm_asm64_init_vm;
			text_prefix_size = sizeof(kvm_asm64_init_vm) - 1;
		} else if (flags & KVM_SETUP_CPL3) {
			text_prefix = kvm_asm64_cpl3;
			text_prefix_size = sizeof(kvm_asm64_cpl3) - 1;
		} else {
			text_prefix = kvm_asm64_enable_long;
			text_prefix_size = sizeof(kvm_asm64_enable_long) - 1;
		}
	}

	struct tss16 tss16;
	memset(&tss16, 0, sizeof(tss16));
	tss16.ss0 = tss16.ss1 = tss16.ss2 = SEL_DS16;
	tss16.sp0 = tss16.sp1 = tss16.sp2 = ADDR_STACK0;
	tss16.ip = ADDR_VAR_USER_CODE2;
	tss16.flags = (1 << 1);
	tss16.cs = SEL_CS16;
	tss16.es = tss16.ds = tss16.ss = SEL_DS16;
	tss16.ldt = SEL_LDT;
	struct tss16* tss16_addr = (struct tss16*)(host_mem + seg_tss16_2.base);
	memcpy(tss16_addr, &tss16, sizeof(tss16));

	memset(&tss16, 0, sizeof(tss16));
	tss16.ss0 = tss16.ss1 = tss16.ss2 = SEL_DS16;
	tss16.sp0 = tss16.sp1 = tss16.sp2 = ADDR_STACK0;
	tss16.ip = ADDR_VAR_USER_CODE2;
	tss16.flags = (1 << 1);
	tss16.cs = SEL_CS16_CPL3;
	tss16.es = tss16.ds = tss16.ss = SEL_DS16_CPL3;
	tss16.ldt = SEL_LDT;
	struct tss16* tss16_cpl3_addr = (struct tss16*)(host_mem + seg_tss16_cpl3.base);
	memcpy(tss16_cpl3_addr, &tss16, sizeof(tss16));

	struct tss32 tss32;
	memset(&tss32, 0, sizeof(tss32));
	tss32.ss0 = tss32.ss1 = tss32.ss2 = SEL_DS32;
	tss32.sp0 = tss32.sp1 = tss32.sp2 = ADDR_STACK0;
	tss32.ip = ADDR_VAR_USER_CODE;
	tss32.flags = (1 << 1) | (1 << 17);
	tss32.ldt = SEL_LDT;
	tss32.cr3 = sregs.cr3;
	tss32.io_bitmap = offsetof(struct tss32, io_bitmap);
	struct tss32* tss32_addr = (struct tss32*)(host_mem + seg_tss32_vm86.base);
	memcpy(tss32_addr, &tss32, sizeof(tss32));

	memset(&tss32, 0, sizeof(tss32));
	tss32.ss0 = tss32.ss1 = tss32.ss2 = SEL_DS32;
	tss32.sp0 = tss32.sp1 = tss32.sp2 = ADDR_STACK0;
	tss32.ip = ADDR_VAR_USER_CODE;
	tss32.flags = (1 << 1);
	tss32.cr3 = sregs.cr3;
	tss32.es = tss32.ds = tss32.ss = tss32.gs = tss32.fs = SEL_DS32;
	tss32.cs = SEL_CS32;
	tss32.ldt = SEL_LDT;
	tss32.cr3 = sregs.cr3;
	tss32.io_bitmap = offsetof(struct tss32, io_bitmap);
	struct tss32* tss32_cpl3_addr = (struct tss32*)(host_mem + seg_tss32_2.base);
	memcpy(tss32_cpl3_addr, &tss32, sizeof(tss32));

	struct tss64 tss64;
	memset(&tss64, 0, sizeof(tss64));
	tss64.rsp[0] = ADDR_STACK0;
	tss64.rsp[1] = ADDR_STACK0;
	tss64.rsp[2] = ADDR_STACK0;
	tss64.io_bitmap = offsetof(struct tss64, io_bitmap);
	struct tss64* tss64_addr = (struct tss64*)(host_mem + seg_tss64.base);
	memcpy(tss64_addr, &tss64, sizeof(tss64));

	memset(&tss64, 0, sizeof(tss64));
	tss64.rsp[0] = ADDR_STACK0;
	tss64.rsp[1] = ADDR_STACK0;
	tss64.rsp[2] = ADDR_STACK0;
	tss64.io_bitmap = offsetof(struct tss64, io_bitmap);
	struct tss64* tss64_cpl3_addr = (struct tss64*)(host_mem + seg_tss64_cpl3.base);
	memcpy(tss64_cpl3_addr, &tss64, sizeof(tss64));

	if (text_size > 1000)
		text_size = 1000;
	if (text_prefix) {
		memcpy(host_text, text_prefix, text_prefix_size);
		// Replace 0xbadc0de in LJMP with offset of a next instruction.
		void* patch = memmem(host_text, text_prefix_size, "\xde\xc0\xad\x0b", 4);
		if (patch)
			*((uint32*)patch) = guest_mem + ADDR_TEXT + ((char*)patch - host_text) + 6;
		uint16 magic = PREFIX_SIZE;
		patch = memmem(host_text, text_prefix_size, &magic, sizeof(magic));
		if (patch)
			*((uint16*)patch) = guest_mem + ADDR_TEXT + text_prefix_size;
	}
	memcpy((void*)(host_text + text_prefix_size), text, text_size);
	*(host_text + text_prefix_size + text_size) = 0xf4; // hlt

	memcpy(host_mem + ADDR_VAR_USER_CODE, text, text_size);
	*(host_mem + ADDR_VAR_USER_CODE + text_size) = 0xf4; // hlt

	*(host_mem + ADDR_VAR_HLT) = 0xf4; // hlt
	memcpy(host_mem + ADDR_VAR_SYSRET, "\x0f\x07\xf4", 3);
	memcpy(host_mem + ADDR_VAR_SYSEXIT, "\x0f\x35\xf4", 3);

	*(uint64*)(host_mem + ADDR_VAR_VMWRITE_FLD) = 0;
	*(uint64*)(host_mem + ADDR_VAR_VMWRITE_VAL) = 0;

	if (opt_count > 2)
		opt_count = 2;
	for (uintptr_t i = 0; i < opt_count; i++) {
		uint64 typ = opt_array_ptr[i].typ;
		uint64 val = opt_array_ptr[i].val;
		switch (typ % 9) {
		case 0:
			sregs.cr0 ^= val & (CR0_MP | CR0_EM | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_NW | CR0_CD);
			break;
		case 1:
			sregs.cr4 ^= val & (CR4_VME | CR4_PVI | CR4_TSD | CR4_DE | CR4_MCE | CR4_PGE | CR4_PCE |
					    CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_UMIP | CR4_VMXE | CR4_SMXE | CR4_FSGSBASE | CR4_PCIDE |
					    CR4_OSXSAVE | CR4_SMEP | CR4_SMAP | CR4_PKE);
			break;
		case 2:
			sregs.efer ^= val & (EFER_SCE | EFER_NXE | EFER_SVME | EFER_LMSLE | EFER_FFXSR | EFER_TCE);
			break;
		case 3:
			val &= ((1 << 8) | (1 << 9) | (1 << 10) | (1 << 12) | (1 << 13) | (1 << 14) |
				(1 << 15) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21));
			regs.rflags ^= val;
			tss16_addr->flags ^= val;
			tss16_cpl3_addr->flags ^= val;
			tss32_addr->flags ^= val;
			tss32_cpl3_addr->flags ^= val;
			break;
		case 4:
			seg_cs16.type = val & 0xf;
			seg_cs32.type = val & 0xf;
			seg_cs64.type = val & 0xf;
			break;
		case 5:
			seg_cs16_cpl3.type = val & 0xf;
			seg_cs32_cpl3.type = val & 0xf;
			seg_cs64_cpl3.type = val & 0xf;
			break;
		case 6:
			seg_ds16.type = val & 0xf;
			seg_ds32.type = val & 0xf;
			seg_ds64.type = val & 0xf;
			break;
		case 7:
			seg_ds16_cpl3.type = val & 0xf;
			seg_ds32_cpl3.type = val & 0xf;
			seg_ds64_cpl3.type = val & 0xf;
			break;
		case 8:
			*(uint64*)(host_mem + ADDR_VAR_VMWRITE_FLD) = (val & 0xffff);
			*(uint64*)(host_mem + ADDR_VAR_VMWRITE_VAL) = (val >> 16);
			break;
		default:
			fail("bad kvm setup opt");
		}
	}
	regs.rflags |= 2; // bit 1 is always set

	fill_segment_descriptor(gdt, ldt, &seg_ldt);
	fill_segment_descriptor(gdt, ldt, &seg_cs16);
	fill_segment_descriptor(gdt, ldt, &seg_ds16);
	fill_segment_descriptor(gdt, ldt, &seg_cs16_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_ds16_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_cs32);
	fill_segment_descriptor(gdt, ldt, &seg_ds32);
	fill_segment_descriptor(gdt, ldt, &seg_cs32_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_ds32_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_cs64);
	fill_segment_descriptor(gdt, ldt, &seg_ds64);
	fill_segment_descriptor(gdt, ldt, &seg_cs64_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_ds64_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_tss32);
	fill_segment_descriptor(gdt, ldt, &seg_tss32_2);
	fill_segment_descriptor(gdt, ldt, &seg_tss32_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_tss32_vm86);
	fill_segment_descriptor(gdt, ldt, &seg_tss16);
	fill_segment_descriptor(gdt, ldt, &seg_tss16_2);
	fill_segment_descriptor(gdt, ldt, &seg_tss16_cpl3);
	fill_segment_descriptor_dword(gdt, ldt, &seg_tss64);
	fill_segment_descriptor_dword(gdt, ldt, &seg_tss64_cpl3);
	fill_segment_descriptor(gdt, ldt, &seg_cgate16);
	fill_segment_descriptor(gdt, ldt, &seg_tgate16);
	fill_segment_descriptor(gdt, ldt, &seg_cgate32);
	fill_segment_descriptor(gdt, ldt, &seg_tgate32);
	fill_segment_descriptor_dword(gdt, ldt, &seg_cgate64);

	if (ioctl(cpufd, KVM_SET_SREGS, &sregs))
		return -1;
	if (ioctl(cpufd, KVM_SET_REGS, &regs))
		return -1;
	return 0;
}
