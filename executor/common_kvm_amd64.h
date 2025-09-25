// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.
// See Intel Software Developer’s Manual Volume 3: System Programming Guide
// for details on what happens here.

#include "common_kvm.h"
#include "common_kvm_amd64_syzos.h"
#include "kvm.h"
#include "kvm_amd64.S.h"

#ifndef KVM_SMI
#define KVM_SMI _IO(KVMIO, 0xb7)
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
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
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
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
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
static void setup_syscall_msrs(int cpufd, uint16 sel_cs, uint16 sel_cs_cpl3)
{
	char buf[sizeof(struct kvm_msrs) + 5 * sizeof(struct kvm_msr_entry)];
	memset(buf, 0, sizeof(buf));
	struct kvm_msrs* msrs = (struct kvm_msrs*)buf;
	struct kvm_msr_entry* entries = msrs->entries;
	msrs->nmsrs = 5;
	entries[0].index = X86_MSR_IA32_SYSENTER_CS;
	entries[0].data = sel_cs;
	entries[1].index = X86_MSR_IA32_SYSENTER_ESP;
	entries[1].data = X86_ADDR_STACK0;
	entries[2].index = X86_MSR_IA32_SYSENTER_EIP;
	entries[2].data = X86_ADDR_VAR_SYSEXIT;
	entries[3].index = X86_MSR_IA32_STAR;
	entries[3].data = ((uint64)sel_cs << 32) | ((uint64)sel_cs_cpl3 << 48);
	entries[4].index = X86_MSR_IA32_LSTAR;
	entries[4].data = X86_ADDR_VAR_SYSRET;
	ioctl(cpufd, KVM_SET_MSRS, msrs);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
static void setup_32bit_idt(struct kvm_sregs* sregs, char* host_mem, uintptr_t guest_mem)
{
	sregs->idt.base = guest_mem + X86_ADDR_VAR_IDT;
	sregs->idt.limit = 0x1ff;
	uint64* idt = (uint64*)(host_mem + sregs->idt.base);
	for (int i = 0; i < 32; i++) {
		struct kvm_segment gate;
		gate.selector = i << 3;
		switch (i % 6) {
		case 0:
			// 16-bit interrupt gate
			gate.type = 6;
			gate.base = X86_SEL_CS16;
			break;
		case 1:
			// 16-bit trap gate
			gate.type = 7;
			gate.base = X86_SEL_CS16;
			break;
		case 2:
			// 16-bit task gate
			gate.type = 3;
			gate.base = X86_SEL_TGATE16;
			break;
		case 3:
			// 32-bit interrupt gate
			gate.type = 14;
			gate.base = X86_SEL_CS32;
			break;
		case 4:
			// 32-bit trap gate
			gate.type = 15;
			gate.base = X86_SEL_CS32;
			break;
		case 5:
			// 32-bit task gate
			gate.type = 11;
			gate.base = X86_SEL_TGATE32;
			break;
		}
		gate.limit = guest_mem + X86_ADDR_VAR_USER_CODE2; // entry offset
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
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
static void setup_64bit_idt(struct kvm_sregs* sregs, char* host_mem, uintptr_t guest_mem)
{
	sregs->idt.base = guest_mem + X86_ADDR_VAR_IDT;
	sregs->idt.limit = 0x1ff;
	uint64* idt = (uint64*)(host_mem + sregs->idt.base);
	for (int i = 0; i < 32; i++) {
		struct kvm_segment gate;
		gate.selector = (i * 2) << 3;
		gate.type = (i & 1) ? 14 : 15; // interrupt or trap gate
		gate.base = X86_SEL_CS64;
		gate.limit = guest_mem + X86_ADDR_VAR_USER_CODE2; // entry offset
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
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
struct kvm_opt {
	uint64 typ;
	uint64 val;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
#define PAGE_MASK GENMASK_ULL(51, 12)

// We assume a 4-level page table, in the future we could add support for
// n-level if needed.
static void setup_pg_table(void* host_mem)
{
	uint64* pml4 = (uint64*)((uint64)host_mem + X86_ADDR_PML4);
	uint64* pdp = (uint64*)((uint64)host_mem + X86_ADDR_PDP);
	uint64* pd = (uint64*)((uint64)host_mem + X86_ADDR_PD);
	uint64* pd_ioapic = (uint64*)((uint64)host_mem + X86_ADDR_PD_IOAPIC);

	pml4[0] = X86_PDE64_PRESENT | X86_PDE64_RW | (X86_ADDR_PDP & PAGE_MASK);
	pdp[0] = X86_PDE64_PRESENT | X86_PDE64_RW | (X86_ADDR_PD & PAGE_MASK);
	pdp[3] = X86_PDE64_PRESENT | X86_PDE64_RW | (X86_ADDR_PD_IOAPIC & PAGE_MASK);

	pd[0] = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_PS;
	pd_ioapic[502] = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_PS;
}

// This only sets up a 64-bit VCPU.
// TODO: Should add support for other modes.
static void setup_gdt_ldt_pg(int cpufd, void* host_mem)
{
	struct kvm_sregs sregs;
	ioctl(cpufd, KVM_GET_SREGS, &sregs);

	sregs.gdt.base = X86_ADDR_GDT;
	sregs.gdt.limit = 256 * sizeof(uint64) - 1;
	uint64* gdt = (uint64*)((uint64)host_mem + sregs.gdt.base);

	struct kvm_segment seg_ldt;
	memset(&seg_ldt, 0, sizeof(seg_ldt));
	seg_ldt.selector = X86_SEL_LDT;
	seg_ldt.type = 2;
	seg_ldt.base = X86_ADDR_LDT;
	seg_ldt.limit = 256 * sizeof(uint64) - 1;
	seg_ldt.present = 1;
	seg_ldt.dpl = 0;
	seg_ldt.s = 0;
	seg_ldt.g = 0;
	seg_ldt.db = 1;
	seg_ldt.l = 0;
	sregs.ldt = seg_ldt;
	uint64* ldt = (uint64*)((uint64)host_mem + sregs.ldt.base);

	struct kvm_segment seg_cs64;
	memset(&seg_cs64, 0, sizeof(seg_cs64));
	seg_cs64.selector = X86_SEL_CS64;
	seg_cs64.type = 11;
	seg_cs64.base = 0;
	seg_cs64.limit = 0xFFFFFFFFu;
	seg_cs64.present = 1;
	seg_cs64.s = 1;
	seg_cs64.g = 1;
	seg_cs64.l = 1;

	sregs.cs = seg_cs64;

	struct kvm_segment seg_ds64;
	memset(&seg_ds64, 0, sizeof(struct kvm_segment));
	seg_ds64.selector = X86_SEL_DS64;
	seg_ds64.type = 3;
	seg_ds64.limit = 0xFFFFFFFFu;
	seg_ds64.present = 1;
	seg_ds64.s = 1;
	seg_ds64.g = 1;

	sregs.ds = seg_ds64;
	sregs.es = seg_ds64;

	struct kvm_segment seg_tss64;
	memset(&seg_tss64, 0, sizeof(seg_tss64));
	seg_tss64.selector = X86_SEL_TSS64;
	seg_tss64.base = X86_ADDR_VAR_TSS64;
	seg_tss64.limit = 0x1ff;
	seg_tss64.type = 9;
	seg_tss64.present = 1;

	struct tss64 tss64;
	memset(&tss64, 0, sizeof(tss64));
	tss64.rsp[0] = X86_ADDR_STACK0;
	tss64.rsp[1] = X86_ADDR_STACK0;
	tss64.rsp[2] = X86_ADDR_STACK0;
	tss64.io_bitmap = offsetof(struct tss64, io_bitmap);
	struct tss64* tss64_addr = (struct tss64*)((uint64)host_mem + seg_tss64.base);
	memcpy(tss64_addr, &tss64, sizeof(tss64));

	fill_segment_descriptor(gdt, ldt, &seg_ldt);
	fill_segment_descriptor(gdt, ldt, &seg_cs64);
	fill_segment_descriptor(gdt, ldt, &seg_ds64);
	fill_segment_descriptor_dword(gdt, ldt, &seg_tss64);

	setup_pg_table(host_mem);

	sregs.cr0 = X86_CR0_PE | X86_CR0_NE | X86_CR0_PG;
	sregs.cr4 |= X86_CR4_PAE | X86_CR4_OSFXSR;
	sregs.efer |= (X86_EFER_LME | X86_EFER_LMA | X86_EFER_NXE);
	sregs.cr3 = X86_ADDR_PML4;

	ioctl(cpufd, KVM_SET_SREGS, &sregs);
}

static void setup_cpuid(int cpufd)
{
	int kvmfd = open("/dev/kvm", O_RDWR);
	char buf[sizeof(struct kvm_cpuid2) + 128 * sizeof(struct kvm_cpuid_entry2)];
	memset(buf, 0, sizeof(buf));
	struct kvm_cpuid2* cpuid = (struct kvm_cpuid2*)buf;
	cpuid->nent = 128;
	ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid);
	ioctl(cpufd, KVM_SET_CPUID2, cpuid);
	close(kvmfd);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
#define KVM_SETUP_PAGING (1 << 0)
#define KVM_SETUP_PAE (1 << 1)
#define KVM_SETUP_PROTECTED (1 << 2)
#define KVM_SETUP_CPL3 (1 << 3)
#define KVM_SETUP_VIRT86 (1 << 4)
#define KVM_SETUP_SMM (1 << 5)
#define KVM_SETUP_VM (1 << 6)

// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
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
	regs.rip = guest_mem + X86_ADDR_TEXT;
	regs.rsp = X86_ADDR_STACK0;

	sregs.gdt.base = guest_mem + X86_ADDR_GDT;
	sregs.gdt.limit = 256 * sizeof(uint64) - 1;
	uint64* gdt = (uint64*)(host_mem + sregs.gdt.base);

	struct kvm_segment seg_ldt;
	memset(&seg_ldt, 0, sizeof(seg_ldt));
	seg_ldt.selector = X86_SEL_LDT;
	seg_ldt.type = 2;
	seg_ldt.base = guest_mem + X86_ADDR_LDT;
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
	memset(&seg_cs16, 0, sizeof(seg_cs16));
	seg_cs16.selector = X86_SEL_CS16;
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
	seg_ds16.selector = X86_SEL_DS16;
	seg_ds16.type = 3;

	struct kvm_segment seg_cs16_cpl3 = seg_cs16;
	seg_cs16_cpl3.selector = X86_SEL_CS16_CPL3;
	seg_cs16_cpl3.dpl = 3;

	struct kvm_segment seg_ds16_cpl3 = seg_ds16;
	seg_ds16_cpl3.selector = X86_SEL_DS16_CPL3;
	seg_ds16_cpl3.dpl = 3;

	struct kvm_segment seg_cs32 = seg_cs16;
	seg_cs32.selector = X86_SEL_CS32;
	seg_cs32.db = 1;

	struct kvm_segment seg_ds32 = seg_ds16;
	seg_ds32.selector = X86_SEL_DS32;
	seg_ds32.db = 1;

	struct kvm_segment seg_cs32_cpl3 = seg_cs32;
	seg_cs32_cpl3.selector = X86_SEL_CS32_CPL3;
	seg_cs32_cpl3.dpl = 3;

	struct kvm_segment seg_ds32_cpl3 = seg_ds32;
	seg_ds32_cpl3.selector = X86_SEL_DS32_CPL3;
	seg_ds32_cpl3.dpl = 3;

	struct kvm_segment seg_cs64 = seg_cs16;
	seg_cs64.selector = X86_SEL_CS64;
	seg_cs64.l = 1;

	struct kvm_segment seg_ds64 = seg_ds32;
	seg_ds64.selector = X86_SEL_DS64;

	struct kvm_segment seg_cs64_cpl3 = seg_cs64;
	seg_cs64_cpl3.selector = X86_SEL_CS64_CPL3;
	seg_cs64_cpl3.dpl = 3;

	struct kvm_segment seg_ds64_cpl3 = seg_ds64;
	seg_ds64_cpl3.selector = X86_SEL_DS64_CPL3;
	seg_ds64_cpl3.dpl = 3;

	struct kvm_segment seg_tss32;
	memset(&seg_tss32, 0, sizeof(seg_tss32));
	seg_tss32.selector = X86_SEL_TSS32;
	seg_tss32.type = 9;
	seg_tss32.base = X86_ADDR_VAR_TSS32;
	seg_tss32.limit = 0x1ff;
	seg_tss32.present = 1;
	seg_tss32.dpl = 0;
	seg_tss32.s = 0;
	seg_tss32.g = 0;
	seg_tss32.db = 0;
	seg_tss32.l = 0;

	struct kvm_segment seg_tss32_2 = seg_tss32;
	seg_tss32_2.selector = X86_SEL_TSS32_2;
	seg_tss32_2.base = X86_ADDR_VAR_TSS32_2;

	struct kvm_segment seg_tss32_cpl3 = seg_tss32;
	seg_tss32_cpl3.selector = X86_SEL_TSS32_CPL3;
	seg_tss32_cpl3.base = X86_ADDR_VAR_TSS32_CPL3;

	struct kvm_segment seg_tss32_vm86 = seg_tss32;
	seg_tss32_vm86.selector = X86_SEL_TSS32_VM86;
	seg_tss32_vm86.base = X86_ADDR_VAR_TSS32_VM86;

	struct kvm_segment seg_tss16 = seg_tss32;
	seg_tss16.selector = X86_SEL_TSS16;
	seg_tss16.base = X86_ADDR_VAR_TSS16;
	seg_tss16.limit = 0xff;
	seg_tss16.type = 1;

	struct kvm_segment seg_tss16_2 = seg_tss16;
	seg_tss16_2.selector = X86_SEL_TSS16_2;
	seg_tss16_2.base = X86_ADDR_VAR_TSS16_2;
	seg_tss16_2.dpl = 0;

	struct kvm_segment seg_tss16_cpl3 = seg_tss16;
	seg_tss16_cpl3.selector = X86_SEL_TSS16_CPL3;
	seg_tss16_cpl3.base = X86_ADDR_VAR_TSS16_CPL3;
	seg_tss16_cpl3.dpl = 3;

	struct kvm_segment seg_tss64 = seg_tss32;
	seg_tss64.selector = X86_SEL_TSS64;
	seg_tss64.base = X86_ADDR_VAR_TSS64;
	seg_tss64.limit = 0x1ff;

	struct kvm_segment seg_tss64_cpl3 = seg_tss64;
	seg_tss64_cpl3.selector = X86_SEL_TSS64_CPL3;
	seg_tss64_cpl3.base = X86_ADDR_VAR_TSS64_CPL3;
	seg_tss64_cpl3.dpl = 3;

	struct kvm_segment seg_cgate16;
	memset(&seg_cgate16, 0, sizeof(seg_cgate16));
	seg_cgate16.selector = X86_SEL_CGATE16;
	seg_cgate16.type = 4;
	seg_cgate16.base = X86_SEL_CS16 | (2 << 16); // selector + param count
	seg_cgate16.limit = X86_ADDR_VAR_USER_CODE2; // entry offset
	seg_cgate16.present = 1;
	seg_cgate16.dpl = 0;
	seg_cgate16.s = 0;
	seg_cgate16.g = 0;
	seg_cgate16.db = 0;
	seg_cgate16.l = 0;
	seg_cgate16.avl = 0;

	struct kvm_segment seg_tgate16 = seg_cgate16;
	seg_tgate16.selector = X86_SEL_TGATE16;
	seg_tgate16.type = 3;
	seg_cgate16.base = X86_SEL_TSS16_2;
	seg_tgate16.limit = 0;

	struct kvm_segment seg_cgate32 = seg_cgate16;
	seg_cgate32.selector = X86_SEL_CGATE32;
	seg_cgate32.type = 12;
	seg_cgate32.base = X86_SEL_CS32 | (2 << 16); // selector + param count

	struct kvm_segment seg_tgate32 = seg_cgate32;
	seg_tgate32.selector = X86_SEL_TGATE32;
	seg_tgate32.type = 11;
	seg_tgate32.base = X86_SEL_TSS32_2;
	seg_tgate32.limit = 0;

	struct kvm_segment seg_cgate64 = seg_cgate16;
	seg_cgate64.selector = X86_SEL_CGATE64;
	seg_cgate64.type = 12;
	seg_cgate64.base = X86_SEL_CS64;

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
	char* host_text = host_mem + X86_ADDR_TEXT;

	if (text_type == 8) {
		if (flags & KVM_SETUP_SMM) {
			if (flags & KVM_SETUP_PROTECTED) {
				sregs.cs = seg_cs16;
				sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds16;
				sregs.cr0 |= X86_CR0_PE;
			} else {
				sregs.cs.selector = 0;
				sregs.cs.base = 0;
			}

			*(host_mem + X86_ADDR_TEXT) = 0xf4; // hlt for rsm
			host_text = host_mem + 0x8000;

			ioctl(cpufd, KVM_SMI, 0);
		} else if (flags & KVM_SETUP_VIRT86) {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;
			sregs.cr0 |= X86_CR0_PE;
			sregs.efer |= X86_EFER_SCE;

			setup_syscall_msrs(cpufd, X86_SEL_CS32, X86_SEL_CS32_CPL3);
			setup_32bit_idt(&sregs, host_mem, guest_mem);

			if (flags & KVM_SETUP_PAGING) {
				uint64 pd_addr = guest_mem + X86_ADDR_PD;
				uint64* pd = (uint64*)(host_mem + X86_ADDR_PD);
				// A single 4MB page to cover the memory region
				pd[0] = X86_PDE32_PRESENT | X86_PDE32_RW | X86_PDE32_USER | X86_PDE32_PS;
				sregs.cr3 = pd_addr;
				sregs.cr4 |= X86_CR4_PSE;

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
			sregs.cr0 |= X86_CR0_PE;
			sregs.cs = seg_cs16;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds16;
		}
	} else if (text_type == 32) {
		sregs.cr0 |= X86_CR0_PE;
		sregs.efer |= X86_EFER_SCE;

		setup_syscall_msrs(cpufd, X86_SEL_CS32, X86_SEL_CS32_CPL3);
		setup_32bit_idt(&sregs, host_mem, guest_mem);

		if (flags & KVM_SETUP_SMM) {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;

			*(host_mem + X86_ADDR_TEXT) = 0xf4; // hlt for rsm
			host_text = host_mem + 0x8000;

			ioctl(cpufd, KVM_SMI, 0);
		} else if (flags & KVM_SETUP_PAGING) {
			sregs.cs = seg_cs32;
			sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;

			uint64 pd_addr = guest_mem + X86_ADDR_PD;
			uint64* pd = (uint64*)(host_mem + X86_ADDR_PD);
			// A single 4MB page to cover the memory region
			pd[0] = X86_PDE32_PRESENT | X86_PDE32_RW | X86_PDE32_USER | X86_PDE32_PS;
			sregs.cr3 = pd_addr;
			sregs.cr4 |= X86_CR4_PSE;

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
		sregs.efer |= X86_EFER_LME | X86_EFER_SCE;
		sregs.cr0 |= X86_CR0_PE;

		setup_syscall_msrs(cpufd, X86_SEL_CS64, X86_SEL_CS64_CPL3);
		setup_64bit_idt(&sregs, host_mem, guest_mem);

		sregs.cs = seg_cs32;
		sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg_ds32;

		uint64 pml4_addr = guest_mem + X86_ADDR_PML4;
		uint64* pml4 = (uint64*)(host_mem + X86_ADDR_PML4);
		uint64 pdpt_addr = guest_mem + X86_ADDR_PDP;
		uint64* pdpt = (uint64*)(host_mem + X86_ADDR_PDP);
		uint64 pd_addr = guest_mem + X86_ADDR_PD;
		uint64* pd = (uint64*)(host_mem + X86_ADDR_PD);
		pml4[0] = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER | pdpt_addr;
		pdpt[0] = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER | pd_addr;
		pd[0] = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER | X86_PDE64_PS;
		sregs.cr3 = pml4_addr;
		sregs.cr4 |= X86_CR4_PAE;

		if (flags & KVM_SETUP_VM) {
			sregs.cr0 |= X86_CR0_NE;

			*((uint64*)(host_mem + X86_ADDR_VAR_VMXON_PTR)) = X86_ADDR_VAR_VMXON;
			*((uint64*)(host_mem + X86_ADDR_VAR_VMCS_PTR)) = X86_ADDR_VAR_VMCS;
			memcpy(host_mem + X86_ADDR_VAR_VMEXIT_CODE, kvm_asm64_vm_exit, sizeof(kvm_asm64_vm_exit) - 1);
			*((uint64*)(host_mem + X86_ADDR_VAR_VMEXIT_PTR)) = X86_ADDR_VAR_VMEXIT_CODE;

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
	tss16.ss0 = tss16.ss1 = tss16.ss2 = X86_SEL_DS16;
	tss16.sp0 = tss16.sp1 = tss16.sp2 = X86_ADDR_STACK0;
	tss16.ip = X86_ADDR_VAR_USER_CODE2;
	tss16.flags = (1 << 1);
	tss16.cs = X86_SEL_CS16;
	tss16.es = tss16.ds = tss16.ss = X86_SEL_DS16;
	tss16.ldt = X86_SEL_LDT;
	struct tss16* tss16_addr = (struct tss16*)(host_mem + seg_tss16_2.base);
	memcpy(tss16_addr, &tss16, sizeof(tss16));

	memset(&tss16, 0, sizeof(tss16));
	tss16.ss0 = tss16.ss1 = tss16.ss2 = X86_SEL_DS16;
	tss16.sp0 = tss16.sp1 = tss16.sp2 = X86_ADDR_STACK0;
	tss16.ip = X86_ADDR_VAR_USER_CODE2;
	tss16.flags = (1 << 1);
	tss16.cs = X86_SEL_CS16_CPL3;
	tss16.es = tss16.ds = tss16.ss = X86_SEL_DS16_CPL3;
	tss16.ldt = X86_SEL_LDT;
	struct tss16* tss16_cpl3_addr = (struct tss16*)(host_mem + seg_tss16_cpl3.base);
	memcpy(tss16_cpl3_addr, &tss16, sizeof(tss16));

	struct tss32 tss32;
	memset(&tss32, 0, sizeof(tss32));
	tss32.ss0 = tss32.ss1 = tss32.ss2 = X86_SEL_DS32;
	tss32.sp0 = tss32.sp1 = tss32.sp2 = X86_ADDR_STACK0;
	tss32.ip = X86_ADDR_VAR_USER_CODE;
	tss32.flags = (1 << 1) | (1 << 17);
	tss32.ldt = X86_SEL_LDT;
	tss32.cr3 = sregs.cr3;
	tss32.io_bitmap = offsetof(struct tss32, io_bitmap);
	struct tss32* tss32_addr = (struct tss32*)(host_mem + seg_tss32_vm86.base);
	memcpy(tss32_addr, &tss32, sizeof(tss32));

	memset(&tss32, 0, sizeof(tss32));
	tss32.ss0 = tss32.ss1 = tss32.ss2 = X86_SEL_DS32;
	tss32.sp0 = tss32.sp1 = tss32.sp2 = X86_ADDR_STACK0;
	tss32.ip = X86_ADDR_VAR_USER_CODE;
	tss32.flags = (1 << 1);
	tss32.cr3 = sregs.cr3;
	tss32.es = tss32.ds = tss32.ss = tss32.gs = tss32.fs = X86_SEL_DS32;
	tss32.cs = X86_SEL_CS32;
	tss32.ldt = X86_SEL_LDT;
	tss32.cr3 = sregs.cr3;
	tss32.io_bitmap = offsetof(struct tss32, io_bitmap);
	struct tss32* tss32_cpl3_addr = (struct tss32*)(host_mem + seg_tss32_2.base);
	memcpy(tss32_cpl3_addr, &tss32, sizeof(tss32));

	struct tss64 tss64;
	memset(&tss64, 0, sizeof(tss64));
	tss64.rsp[0] = X86_ADDR_STACK0;
	tss64.rsp[1] = X86_ADDR_STACK0;
	tss64.rsp[2] = X86_ADDR_STACK0;
	tss64.io_bitmap = offsetof(struct tss64, io_bitmap);
	struct tss64* tss64_addr = (struct tss64*)(host_mem + seg_tss64.base);
	memcpy(tss64_addr, &tss64, sizeof(tss64));

	memset(&tss64, 0, sizeof(tss64));
	tss64.rsp[0] = X86_ADDR_STACK0;
	tss64.rsp[1] = X86_ADDR_STACK0;
	tss64.rsp[2] = X86_ADDR_STACK0;
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
			*((uint32*)patch) = guest_mem + X86_ADDR_TEXT + ((char*)patch - host_text) + 6;
		uint16 magic = X86_PREFIX_SIZE;
		patch = memmem(host_text, text_prefix_size, &magic, sizeof(magic));
		if (patch)
			*((uint16*)patch) = guest_mem + X86_ADDR_TEXT + text_prefix_size;
	}
	memcpy((void*)(host_text + text_prefix_size), text, text_size);
	*(host_text + text_prefix_size + text_size) = 0xf4; // hlt

	memcpy(host_mem + X86_ADDR_VAR_USER_CODE, text, text_size);
	*(host_mem + X86_ADDR_VAR_USER_CODE + text_size) = 0xf4; // hlt

	*(host_mem + X86_ADDR_VAR_HLT) = 0xf4; // hlt
	memcpy(host_mem + X86_ADDR_VAR_SYSRET, "\x0f\x07\xf4", 3);
	memcpy(host_mem + X86_ADDR_VAR_SYSEXIT, "\x0f\x35\xf4", 3);

	*(uint64*)(host_mem + X86_ADDR_VAR_VMWRITE_FLD) = 0;
	*(uint64*)(host_mem + X86_ADDR_VAR_VMWRITE_VAL) = 0;

	if (opt_count > 2)
		opt_count = 2;
	for (uintptr_t i = 0; i < opt_count; i++) {
		uint64 typ = opt_array_ptr[i].typ;
		uint64 val = opt_array_ptr[i].val;
		switch (typ % 9) {
		case 0:
			sregs.cr0 ^= val & (X86_CR0_MP | X86_CR0_EM | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | X86_CR0_NW | X86_CR0_CD);
			break;
		case 1:
			sregs.cr4 ^= val & (X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE | X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE |
					    X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT | X86_CR4_UMIP | X86_CR4_VMXE | X86_CR4_SMXE | X86_CR4_FSGSBASE | X86_CR4_PCIDE |
					    X86_CR4_OSXSAVE | X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE);
			break;
		case 2:
			sregs.efer ^= val & (X86_EFER_SCE | X86_EFER_NXE | X86_EFER_SVME | X86_EFER_LMSLE | X86_EFER_FFXSR | X86_EFER_TCE);
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
			*(uint64*)(host_mem + X86_ADDR_VAR_VMWRITE_FLD) = (val & 0xffff);
			*(uint64*)(host_mem + X86_ADDR_VAR_VMWRITE_VAL) = (val >> 16);
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
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
static void reset_cpu_regs(int cpufd, int cpu_id, size_t text_size)
{
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));

	regs.rflags |= 2; // bit 1 is always set
	// PC points to the relative offset of guest_main() within the guest code.
	regs.rip = X86_SYZOS_ADDR_EXECUTOR_CODE + ((uint64)guest_main - (uint64)&__start_guest);
	regs.rsp = X86_SYZOS_ADDR_STACK0;
	// Pass parameters to guest_main().
	regs.rdi = text_size;
	regs.rsi = cpu_id;
	ioctl(cpufd, KVM_SET_REGS, &regs);
}

static void install_user_code(int cpufd, void* user_text_slot, int cpu_id, const void* text, size_t text_size, void* host_mem)
{
	if ((cpu_id < 0) || (cpu_id >= KVM_MAX_VCPU))
		return;
	if (!user_text_slot)
		return;
	if (text_size > KVM_PAGE_SIZE)
		text_size = KVM_PAGE_SIZE;
	void* target = (void*)((uint64)user_text_slot + (KVM_PAGE_SIZE * cpu_id));
	memcpy(target, text, text_size);
	setup_gdt_ldt_pg(cpufd, host_mem);
	setup_cpuid(cpufd);
	reset_cpu_regs(cpufd, cpu_id, text_size);
}
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

static void install_syzos_code(void* host_mem, size_t mem_size)
{
	size_t size = (char*)&__stop_guest - (char*)&__start_guest;
	if (size > mem_size)
		fail("SyzOS size exceeds guest memory");
	memcpy(host_mem, &__start_guest, size);
}

static void setup_vm(int vmfd, void* host_mem, void** text_slot)
{
	// Guest virtual memory layout (must be in sync with executor/kvm.h):
	// 0x00000000 - AMD64 data structures (10 pages, see kvm.h)
	// 0x00030000 - SMRAM (10 pages)
	// 0x00040000 - unmapped region to trigger a page faults for uexits etc. (1 page)
	// 0x00041000 - writable region with KVM_MEM_LOG_DIRTY_PAGES to fuzz dirty ring (2 pages)
	// 0x00050000 - user code (4 pages)
	// 0x00054000 - executor guest code (4 pages)
	// 0000058000 - scratch memory for code generated at runtime (1 page)
	// 0xfec00000 - IOAPIC (1 page)
	struct addr_size allocator = {.addr = host_mem, .size = KVM_GUEST_MEM_SIZE};
	int slot = 0; // Slot numbers do not matter, they just have to be different.

	// This *needs* to be the first allocation to avoid passing pointers
	// around for the gdt/ldt/page table setup.
	struct addr_size next = alloc_guest_mem(&allocator, 10 * KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, 0, 0, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, 10 * KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, 0, X86_SYZOS_ADDR_SMRAM, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, 2 * KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_LOG_DIRTY_PAGES, X86_SYZOS_ADDR_DIRTY_PAGES, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, KVM_MAX_VCPU * KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, X86_SYZOS_ADDR_USER_CODE, next.size, (uintptr_t)next.addr);
	if (text_slot)
		*text_slot = next.addr;

	struct addr_size host_text = alloc_guest_mem(&allocator, 4 * KVM_PAGE_SIZE);
	install_syzos_code(host_text.addr, host_text.size);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, X86_SYZOS_ADDR_EXECUTOR_CODE, host_text.size, (uintptr_t)host_text.addr);

	next = alloc_guest_mem(&allocator, KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, 0, X86_SYZOS_ADDR_SCRATCH_CODE, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, 0, X86_SYZOS_ADDR_IOAPIC, next.size, (uintptr_t)next.addr);

	// Map the remaining pages at an unused address.
	next = alloc_guest_mem(&allocator, allocator.size);
	vm_set_user_memory_region(vmfd, slot++, 0, X86_SYZOS_ADDR_UNUSED, next.size, (uintptr_t)next.addr);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm || __NR_syz_kvm_add_vcpu
struct kvm_syz_vm {
	int vmfd;
	int next_cpu_id;
	void* user_text;
	void* host_mem;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm
static long syz_kvm_setup_syzos_vm(volatile long a0, volatile long a1)
{
	const int vmfd = a0;
	void* host_mem = (void*)a1;

	void* user_text_slot = NULL;
	struct kvm_syz_vm* ret = (struct kvm_syz_vm*)host_mem;
	host_mem = (void*)((uint64)host_mem + KVM_PAGE_SIZE);
	setup_vm(vmfd, host_mem, &user_text_slot);
	ret->vmfd = vmfd;
	ret->next_cpu_id = 0;
	ret->user_text = user_text_slot;
	ret->host_mem = host_mem;
	return (long)ret;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
static long syz_kvm_add_vcpu(volatile long a0, volatile long a1)
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
	install_user_code(cpufd, vm->user_text, cpu_id, text, text_size, vm->host_mem);
	return cpufd;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_syzos_uexit
static long syz_kvm_assert_syzos_uexit(volatile long a0, volatile long a1)
{
	struct kvm_run* run = (struct kvm_run*)a0;
	uint64 expect = a1;

	if (!run || (run->exit_reason != KVM_EXIT_MMIO) || (run->mmio.phys_addr != X86_SYZOS_ADDR_UEXIT)) {
		errno = EINVAL;
		return -1;
	}

	if ((((uint64*)(run->mmio.data))[0]) != expect) {
		errno = EDOM;
		return -1;
	}
	return 0;
}
#endif
