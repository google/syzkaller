// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// kvm_gen.cc generates machine code from this file and saves it into kvm.S.h.

// +build

#include "kvm.h"

.global kvm_asm64_enable_long, kvm_asm64_enable_long_end
kvm_asm64_enable_long:
.code32
	mov %cr0, %eax
	or $0x80000000, %eax
	mov %eax, %cr0
	ljmp $SEL_CS64, NEXT_INSN
.code64
	mov $SEL_TSS64, %rax
	ltr %ax
kvm_asm64_enable_long_end:
	nop

.global kvm_asm32_paged, kvm_asm32_paged_end
kvm_asm32_paged:
.code32
	mov %cr0, %eax
	or $0x80000000, %eax
	mov %eax, %cr0
kvm_asm32_paged_end:
	nop

.global kvm_asm32_vm86, kvm_asm32_vm86_end
kvm_asm32_vm86:
.code32
	mov $SEL_TSS32, %ax
	ltr %ax
	ljmp $SEL_TSS32_VM86, $0
kvm_asm32_vm86_end:
	nop

.global kvm_asm32_paged_vm86, kvm_asm32_paged_vm86_end
kvm_asm32_paged_vm86:
.code32
	mov %cr0, %eax
	or $0x80000000, %eax
	mov %eax, %cr0
	mov $SEL_TSS32, %ax
	ltr %ax
	ljmp $SEL_TSS32_VM86, $0
kvm_asm32_paged_vm86_end:
	nop

.global kvm_asm16_cpl3, kvm_asm16_cpl3_end
kvm_asm16_cpl3:
.code16
	mov %cr0, %eax
	or $1, %eax
	mov %eax, %cr0
	mov $SEL_TSS16, %ax
	ltr %ax
	mov $SEL_DS16_CPL3, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %fs
	mov %ax, %gs
	mov $0x100, %sp
	movw $PREFIX_SIZE, 0x100
	movw $SEL_CS16_CPL3, 0x102
	movw $0x100, 0x104
	movw $SEL_DS16_CPL3, 0x106
	lret
kvm_asm16_cpl3_end:
	nop

.global kvm_asm64_cpl3, kvm_asm64_cpl3_end
kvm_asm64_cpl3:
.code32
	mov %cr0, %eax
	or $0x80000000, %eax
	mov %eax, %cr0
	ljmp $SEL_CS64, NEXT_INSN
.code64
	mov $SEL_TSS64, %rax
	ltr %ax
	mov $SEL_DS64_CPL3, %rax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %fs
	mov %ax, %gs
	mov $ADDR_STACK0, %rsp
	movq $PREFIX_SIZE, 0(%rsp)
	movq $SEL_CS64_CPL3, 4(%rsp)
	movq $ADDR_STACK0, 8(%rsp)
	movq $SEL_DS64_CPL3, 12(%rsp)
	lret
kvm_asm64_cpl3_end:
	nop

.global kvm_asm64_init_vm, kvm_asm64_init_vm_end
kvm_asm64_init_vm:
.code32
	// CR0.PG = 1
	mov %cr0, %eax
	or $0x80000000, %eax
	mov %eax, %cr0
	ljmp $SEL_CS64, NEXT_INSN
.code64
	mov $SEL_TSS64, %rax
	ltr %ax

	// Enable and lock non-SMM VM
	mov $MSR_IA32_FEATURE_CONTROL, %rcx
	rdmsr
	or $0x5, %rax
	wrmsr

	// CR4.VMXE = 1
	mov %cr4, %rax
	or $0x2000, %rax
	mov %rax, %cr4

	// Write VMCS revision into VMXON and VMCS regions
	mov $MSR_IA32_VMX_BASIC, %rcx
	rdmsr
	mov $ADDR_VAR_VMXON, %rdx
	mov %eax, (%rdx)
	mov $ADDR_VAR_VMCS, %rdx
	mov %eax, (%rdx)

	mov $ADDR_VAR_VMXON_PTR, %rax
	vmxon (%rax)
	mov $ADDR_VAR_VMCS_PTR, %rax
	vmclear (%rax)
	vmptrld (%rax)

#define VMSET(FIELD, VAL)	\
	mov $FIELD, %rdx;	\
	mov VAL, %rax;		\
	vmwrite %rax, %rdx;	\
	/**/

#define VMSET_LIMITED(FIELD, VAL, MSR)	\
	mov $MSR, %rcx;		\
	rdmsr;			\
	or VAL, %rax;		\
	and %rdx, %rax;		\
	mov $FIELD, %rdx;	\
	vmwrite %rax, %rdx;	\
	/**/

	VMSET_LIMITED(0x00004000, $0x3f, 0x481) // Pin-based VM-execution controls
	//VMSET_LIMITED(0x00004002, $0x61999e84, 0x482) // Primary processor-based VM-execution controls
	VMSET(0x00004002, $0xf3999e84)
	VMSET(0x0000401E, $((1<<0) | (1<<7))) // Secondary processor-based VM-execution controls
	VMSET_LIMITED(0x0000400C, $0x36fff, 0x483) // VM-exit controls (F6FFF)
	VMSET_LIMITED(0x00004012, $0x17ff, 0x484) // VM-entry controls (51FF)

	VMSET(0x00002C04, $0) // Host IA32_PERF_GLOBAL_CTR
	VMSET(0x00002800, $0xffffffffffffffff) // VMCS link pointer

	VMSET(0x00000C02, $SEL_CS64) // host CS

	mov $SEL_DS64, %rax
	mov $0x00000C00, %rdx // host ES
	vmwrite %rax, %rdx
	mov $0x00000C04, %rdx // host SS
	vmwrite %rax, %rdx
	mov $0x00000C06, %rdx // host DS
	vmwrite %rax, %rdx
	mov $0x00000C08, %rdx // host FS
	vmwrite %rax, %rdx
	mov $0x00000C0A, %rdx // host GS
	vmwrite %rax, %rdx
	mov $SEL_TSS64, %rax
	mov $0x00000C0C, %rdx // host TR
	vmwrite %rax, %rdx

	VMSET(0x00002C02, $0x500) // host EFER

	VMSET(0x00004C00, $SEL_CS64) // Host IA32_SYSENTER_CS
	VMSET(0x00006C10, $0) // Host IA32_SYSENTER_ESP
	VMSET(0x00006C12, $0) // Host IA32_SYSENTER_EIP

	mov %cr0, %rax
	VMSET(0x00006C00, %rax) // host CR0
	mov %cr3, %rax
	VMSET(0x00006C02, %rax) // host CR3
	mov %cr4, %rax
	VMSET(0x00006C04, %rax) // host CR4

	VMSET(0x00006C06, $0) // host FS base
	VMSET(0x00006C08, $0) // host GS base
	VMSET(0x00006C0A, $ADDR_VAR_TSS64) // host TR base

	VMSET(0x00006C0C, $ADDR_GDT) // host GDTR base
	VMSET(0x00006C0E, $ADDR_VAR_IDT) // host IDTR base

	VMSET(0x00006C14, $0) // host RSP
	VMSET(0x00006C16, ADDR_VAR_VMEXIT_PTR) // host RIP

	VMSET(0x00000000, $1) // VPID
	VMSET(0x00000002, $0) // Posted-interrupt notification vector
	//VMSET(0x00000004, $0) // EPTP index

	VMSET(0x00002000, $0) // Address of I/O bitmap A
	VMSET(0x00002002, $0) // Address of I/O bitmap B
	VMSET(0x00002004, $0) // Address of MSR bitmaps
	VMSET(0x00002006, $0) // VM-exit MSR-store address

	mov $0x277, %rcx
	rdmsr
	shl $32, %rdx
	or %rdx, %rax
	VMSET(0x00002C00, %rax) // Host IA32_PAT

	VMSET(0x00004004, $0) // Exception bitmap
	VMSET(0x0000400A, $0) // CR3-target count
	VMSET(0x0000400E, $0) // VM-exit MSR-store count
	VMSET(0x00004010, $0) // VM-exit MSR-load count
	VMSET(0x00004016, $0) // VM-entry interruption-information field
	VMSET(0x00004014, $0) // VM-entry MSR-load count

	VMSET(0x00006000, $0xffffffffffffffff) // CR0 guest/host mask
	VMSET(0x00006002, $0xffffffffffffffff) // CR4 guest/host mask

	VMSET(0x0000201C, $0) // EOI-exit bitmap 0
	VMSET(0x0000201E, $0) // EOI-exit bitmap 1
	VMSET(0x00002020, $0) // EOI-exit bitmap 2
	VMSET(0x00002022, $0) // EOI-exit bitmap 3

	VMSET(0x00000800, $SEL_DS64) // Guest ES selector
	VMSET(0x00000802, $SEL_CS64) // Guest CS selector
	VMSET(0x00000804, $SEL_DS64) // Guest SS selector
	VMSET(0x00000806, $SEL_DS64) // Guest DS selector
	VMSET(0x00000808, $SEL_DS64) // Guest FS selector
	VMSET(0x0000080A, $SEL_DS64) // Guest GS selector
	VMSET(0x0000080C, $0) // Guest LDTR selector
	VMSET(0x0000080E, $SEL_TSS64) // Guest TR selector

	VMSET(0x00006812, $0) // Guest LDTR base
	VMSET(0x00006814, $ADDR_VAR_TSS64) // Guest TR base
	VMSET(0x00006816, $ADDR_GDT) // Guest GDTR base
	VMSET(0x00006818, $ADDR_VAR_IDT) // Guest IDTR base

	VMSET(0x00004800, $0xfffff) // Guest ES limit
	VMSET(0x00004802, $0xfffff) // Guest CS limit
	VMSET(0x00004804, $0xfffff) // Guest SS limit
	VMSET(0x00004806, $0xfffff) // Guest DS limit
	VMSET(0x00004808, $0xfffff) // Guest FS limit
	VMSET(0x0000480A, $0xfffff) // Guest GS limit
	VMSET(0x0000480C, $0) // Guest LDTR limit
	VMSET(0x0000480E, $0x1fff) // Guest TR limit
	VMSET(0x00004810, $0x1fff) // Guest GDTR limit
	VMSET(0x00004812, $0x1fff) // Guest IDTR limit

	VMSET(0x00004814, $0x4093) // Guest ES access rights
	VMSET(0x00004816, $0x209b) // Guest CS access rights
	VMSET(0x00004818, $0x4093) // Guest SS access rights
	VMSET(0x0000481A, $0x4093) // Guest DS access rights
	VMSET(0x0000481C, $0x4093) // Guest FS access rights
	VMSET(0x0000481E, $0x4093) // Guest GS access rights
	VMSET(0x00004820, $0x82) // Guest LDTR access rights
	VMSET(0x00004822, $0x8b) // Guest TR access rights

	VMSET(0x0000681C, $0) // Guest RSP
	VMSET(0x0000681E, $ADDR_VAR_USER_CODE) // Guest RIP
	VMSET(0x00006820, $((1<<1))) // Guest RFLAGS
	VMSET(0x00002806, $0x500) // Guest IA32_EFER
	VMSET(0x0000280A, $0) // Guest PDPTE0
	VMSET(0x0000280C, $0) // Guest PDPTE1
	VMSET(0x0000280E, $0) // Guest PDPTE2
	VMSET(0x00002810, $0) // Guest PDPTE3

	mov %cr0, %rax
	VMSET(0x00006800, %rax) // Guest CR0
	mov %cr3, %rax
	VMSET(0x00006802, %rax) // Guest CR3
	mov %cr4, %rax
	VMSET(0x00006804, %rax) // Guest CR4

	// Write 1 additional random field.
	mov $ADDR_VAR_VMWRITE_FLD, %rax
	mov (%rax), %rdx
	mov $ADDR_VAR_VMWRITE_VAL, %rax
	mov (%rax), %rcx
	xor %rax, %rax
	vmread %rdx, %rax
	xor %rcx, %rax
	vmwrite %rax, %rdx

	vmlaunch

	mov $0x00004400, %rdx
	vmread %rdx, %rax
	hlt
kvm_asm64_init_vm_end:
	nop

.global kvm_asm64_vm_exit, kvm_asm64_vm_exit_end
kvm_asm64_vm_exit:
.code64
	//vmresume
	mov $0x00004400, %rbx // VM-instruction error
	vmread %rbx, %rdx
	mov $0x00004402, %rbx // Exit reason
	vmread %rbx, %rcx
	mov $0x00006400, %rax // Exit qualification
	vmread %rax, %rax
	mov $0x0000681E, %rbx // Guest RIP
	vmread %rbx, %rbx
	hlt
kvm_asm64_vm_exit_end:
	nop
