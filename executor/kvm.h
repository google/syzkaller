// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#define X86_ADDR_TEXT 0x0000
#define X86_ADDR_PD_IOAPIC 0x0000
#define X86_ADDR_GDT 0x1000
#define X86_ADDR_LDT 0x1800
#define X86_ADDR_PML4 0x2000
#define X86_ADDR_PDP 0x3000
#define X86_ADDR_PD 0x4000
#define X86_ADDR_STACK0 0x0f80
#define X86_ADDR_VAR_HLT 0x2800
#define X86_ADDR_VAR_SYSRET 0x2808
#define X86_ADDR_VAR_SYSEXIT 0x2810
#define X86_ADDR_VAR_IDT 0x3800
#define X86_ADDR_VAR_TSS64 0x3a00
#define X86_ADDR_VAR_TSS64_CPL3 0x3c00
#define X86_ADDR_VAR_TSS16 0x3d00
#define X86_ADDR_VAR_TSS16_2 0x3e00
#define X86_ADDR_VAR_TSS16_CPL3 0x3f00
#define X86_ADDR_VAR_TSS32 0x4800
#define X86_ADDR_VAR_TSS32_2 0x4a00
#define X86_ADDR_VAR_TSS32_CPL3 0x4c00
#define X86_ADDR_VAR_TSS32_VM86 0x4e00
#define X86_ADDR_VAR_VMXON_PTR 0x5f00
#define X86_ADDR_VAR_VMCS_PTR 0x5f08
#define X86_ADDR_VAR_VMEXIT_PTR 0x5f10
#define X86_ADDR_VAR_VMWRITE_FLD 0x5f18
#define X86_ADDR_VAR_VMWRITE_VAL 0x5f20
#define X86_ADDR_VAR_VMXON 0x6000
#define X86_ADDR_VAR_VMCS 0x7000
#define X86_ADDR_VAR_VMEXIT_CODE 0x9000
#define X86_ADDR_VAR_USER_CODE 0x9100
#define X86_ADDR_VAR_USER_CODE2 0x9120

// x86 SYZOS definitions.
// Zero page (0x0 - 0xfff) is deliberately unused.
#define X86_SYZOS_ADDR_ZERO 0x0
#define X86_SYZOS_ADDR_GDT 0x1000
// PML4 for GPAs 0x0 - 0xffffffffffff.
#define X86_SYZOS_ADDR_PML4 0x2000
// PDP for GPAs 0x0 - 0x7fffffffff.
#define X86_SYZOS_ADDR_PDP 0x3000
// Lowmem PD for GPAs 0x0 - 0x3fffffff.
#define X86_SYZOS_ADDR_PD 0x4000
// IOAPIC PD for GPAs 0xc0000000 - 0xffffffff.
#define X86_SYZOS_ADDR_PD_IOAPIC 0x5000
// Lowmem PT for GPAs 0x000000 - 0x1fffff.
#define X86_SYZOS_ADDR_PT_LOW_MEM 0x6000
// Two PTs for unused memory for GPAs 0x200000 - 0x3fffff.
#define X86_SYZOS_ADDR_PT_UNUSED_MEM 0x7000
// IOAPIC PT for GPAs 0xfed00000 - 0xfedfffff.
#define X86_SYZOS_ADDR_PT_IOAPIC 0x9000

#define X86_SYZOS_ADDR_SMRAM 0x30000
// Write to this page to trigger a page fault and stop KVM_RUN.
#define X86_SYZOS_ADDR_EXIT 0x40000
// Dedicated address within the exit page for the uexit command.
#define X86_SYZOS_ADDR_UEXIT (X86_SYZOS_ADDR_EXIT + 256)
#define X86_SYZOS_ADDR_DIRTY_PAGES 0x41000
#define X86_SYZOS_ADDR_USER_CODE 0x50000
#define X86_SYZOS_ADDR_EXECUTOR_CODE 0x54000
#define X86_SYZOS_ADDR_SCRATCH_CODE 0x58000
#define X86_SYZOS_ADDR_STACK_BOTTOM 0x90000
#define X86_SYZOS_ADDR_STACK0 0x90f80
#define X86_SYZOS_ADDR_UNUSED 0x200000
#define X86_SYZOS_ADDR_IOAPIC 0xfec00000

#define X86_CR0_PE 1ULL
#define X86_CR0_MP (1ULL << 1)
#define X86_CR0_EM (1ULL << 2)
#define X86_CR0_TS (1ULL << 3)
#define X86_CR0_ET (1ULL << 4)
#define X86_CR0_NE (1ULL << 5)
#define X86_CR0_WP (1ULL << 16)
#define X86_CR0_AM (1ULL << 18)
#define X86_CR0_NW (1ULL << 29)
#define X86_CR0_CD (1ULL << 30)
#define X86_CR0_PG (1ULL << 31)

#define X86_CR4_VME 1ULL
#define X86_CR4_PVI (1ULL << 1)
#define X86_CR4_TSD (1ULL << 2)
#define X86_CR4_DE (1ULL << 3)
#define X86_CR4_PSE (1ULL << 4)
#define X86_CR4_PAE (1ULL << 5)
#define X86_CR4_MCE (1ULL << 6)
#define X86_CR4_PGE (1ULL << 7)
#define X86_CR4_PCE (1ULL << 8)
#define X86_CR4_OSFXSR (1ULL << 8)
#define X86_CR4_OSXMMEXCPT (1ULL << 10)
#define X86_CR4_UMIP (1ULL << 11)
#define X86_CR4_VMXE (1ULL << 13)
#define X86_CR4_SMXE (1ULL << 14)
#define X86_CR4_FSGSBASE (1ULL << 16)
#define X86_CR4_PCIDE (1ULL << 17)
#define X86_CR4_OSXSAVE (1ULL << 18)
#define X86_CR4_SMEP (1ULL << 20)
#define X86_CR4_SMAP (1ULL << 21)
#define X86_CR4_PKE (1ULL << 22)

#define X86_EFER_SCE 1ULL
#define X86_EFER_LME (1ULL << 8)
#define X86_EFER_LMA (1ULL << 10)
#define X86_EFER_NXE (1ULL << 11)
#define X86_EFER_SVME (1ULL << 12)
#define X86_EFER_LMSLE (1ULL << 13)
#define X86_EFER_FFXSR (1ULL << 14)
#define X86_EFER_TCE (1ULL << 15)

// 32-bit page directory entry bits
#define X86_PDE32_PRESENT 1UL
#define X86_PDE32_RW (1UL << 1)
#define X86_PDE32_USER (1UL << 2)
#define X86_PDE32_PS (1UL << 7)

// 64-bit page * entry bits
#define X86_PDE64_PRESENT 1
#define X86_PDE64_RW (1ULL << 1)
#define X86_PDE64_USER (1ULL << 2)
#define X86_PDE64_ACCESSED (1ULL << 5)
#define X86_PDE64_DIRTY (1ULL << 6)
#define X86_PDE64_PS (1ULL << 7)
#define X86_PDE64_G (1ULL << 8)

#define X86_SEL_LDT (1 << 3)
#define X86_SEL_CS16 (2 << 3)
#define X86_SEL_DS16 (3 << 3)
#define X86_SEL_CS16_CPL3 ((4 << 3) + 3)
#define X86_SEL_DS16_CPL3 ((5 << 3) + 3)
#define X86_SEL_CS32 (6 << 3)
#define X86_SEL_DS32 (7 << 3)
#define X86_SEL_CS32_CPL3 ((8 << 3) + 3)
#define X86_SEL_DS32_CPL3 ((9 << 3) + 3)
#define X86_SEL_CS64 (10 << 3)
#define X86_SEL_DS64 (11 << 3)
#define X86_SEL_CS64_CPL3 ((12 << 3) + 3)
#define X86_SEL_DS64_CPL3 ((13 << 3) + 3)
#define X86_SEL_CGATE16 (14 << 3)
#define X86_SEL_TGATE16 (15 << 3)
#define X86_SEL_CGATE32 (16 << 3)
#define X86_SEL_TGATE32 (17 << 3)
#define X86_SEL_CGATE64 (18 << 3)
#define X86_SEL_CGATE64_HI (19 << 3)
#define X86_SEL_TSS16 (20 << 3)
#define X86_SEL_TSS16_2 (21 << 3)
#define X86_SEL_TSS16_CPL3 ((22 << 3) + 3)
#define X86_SEL_TSS32 (23 << 3)
#define X86_SEL_TSS32_2 (24 << 3)
#define X86_SEL_TSS32_CPL3 ((25 << 3) + 3)
#define X86_SEL_TSS32_VM86 (26 << 3)
#define X86_SEL_TSS64 (27 << 3)
#define X86_SEL_TSS64_HI (28 << 3)
#define X86_SEL_TSS64_CPL3 ((29 << 3) + 3)
#define X86_SEL_TSS64_CPL3_HI (30 << 3)

#define X86_MSR_IA32_FEATURE_CONTROL 0x3a
#define X86_MSR_IA32_VMX_BASIC 0x480
#define X86_MSR_IA32_SMBASE 0x9e
#define X86_MSR_IA32_SYSENTER_CS 0x174
#define X86_MSR_IA32_SYSENTER_ESP 0x175
#define X86_MSR_IA32_SYSENTER_EIP 0x176
#define X86_MSR_IA32_STAR 0xC0000081
#define X86_MSR_IA32_LSTAR 0xC0000082
#define X86_MSR_IA32_VMX_PROCBASED_CTLS2 0x48B

#define X86_NEXT_INSN $0xbadc0de
#define X86_PREFIX_SIZE 0xba1d

#define KVM_MAX_VCPU 4
#define KVM_PAGE_SIZE (1 << 12)
#define KVM_GUEST_MEM_SIZE (1024 * KVM_PAGE_SIZE)
#define SZ_4K 0x00001000
#define SZ_64K 0x00010000
#define GENMASK_ULL(h, l)                   \
	(((~0ULL) - (1ULL << (l)) + 1ULL) & \
	 (~0ULL >> (63 - (h))))

// GICv3 distributor address.
#define ARM64_ADDR_GICD_BASE 0x08000000
// GICv3 ITS address.
#define ARM64_ADDR_GITS_BASE 0x08080000
// GICv3 redistributor address.
#define ARM64_ADDR_GICR_BASE 0x080a0000
#define ARM64_ADDR_ITS_TABLES 0xc0000000
// Write to this page to trigger a page fault and stop KVM_RUN.
#define ARM64_ADDR_EXIT 0xdddd0000
// Dedicated address within the exit page for the uexit command.
#define ARM64_ADDR_UEXIT (ARM64_ADDR_EXIT + 256)
// Two writable pages with KVM_MEM_LOG_DIRTY_PAGES explicitly set.
#define ARM64_ADDR_DIRTY_PAGES 0xdddd1000
#define ARM64_ADDR_USER_CODE 0xeeee0000
#define ARM64_ADDR_EXECUTOR_CODE 0xeeee8000
#define ARM64_ADDR_SCRATCH_CODE 0xeeef0000
#define ARM64_ADDR_EL1_STACK_BOTTOM 0xffff1000

// GICv3 ITS tables.
#define ITS_MAX_DEVICES 16
#define ARM64_ADDR_ITS_DEVICE_TABLE (ARM64_ADDR_ITS_TABLES)
#define ARM64_ADDR_ITS_COLL_TABLE (ARM64_ADDR_ITS_DEVICE_TABLE + SZ_64K)
#define ARM64_ADDR_ITS_CMDQ_BASE (ARM64_ADDR_ITS_COLL_TABLE + SZ_64K)
// 16 slots for ITT tables, typically used by devices 0-15.
#define ARM64_ADDR_ITS_ITT_TABLES (ARM64_ADDR_ITS_CMDQ_BASE + SZ_64K)
#define ARM64_ADDR_ITS_PROP_TABLE (ARM64_ADDR_ITS_ITT_TABLES + SZ_64K * ITS_MAX_DEVICES)
#define ARM64_ADDR_ITS_PEND_TABLES (ARM64_ADDR_ITS_PROP_TABLE + SZ_64K)
