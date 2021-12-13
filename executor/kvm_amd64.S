// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// kvm_gen.cc generates machine code from this file and saves it into kvm_amd64.S.h.

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

	VMSET_LIMITED(PIN_BASED_VM_EXECUTION_CONTROLS, $0, IA32_VMX_PINBASED_CTLS)
	VMSET_LIMITED(PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, $0, IA32_VMX_PROCBASED_CTLS)

	VMSET(SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, $((1<<0) | (1<<7)))
	VMSET_LIMITED(VM_EXIT_CONTROLS, $0x36fff, IA32_VMX_EXIT_CTLS) // VM-exit controls (F6FFF)
	VMSET_LIMITED(VM_ENTRY_CONTROLS, $0x17ff, IA32_VMX_ENTRY_CTLS) // VM-entry controls (51FF)

	VMSET(HOST_IA32_PERF_GLOBAL_CTRL_FULL, $0)
	VMSET(VMCS_LINK_POINTER_FULL, $0xffffffffffffffff)

	VMSET(HOST_CS_SELECTOR, $SEL_CS64)

	mov $SEL_DS64, %rax
	mov $HOST_ES_SELECTOR, %rdx
	vmwrite %rax, %rdx
	mov $HOST_SS_SELECTOR, %rdx
	vmwrite %rax, %rdx
	mov $HOST_DS_SELECTOR, %rdx
	vmwrite %rax, %rdx
	mov $HOST_FS_SELECTOR, %rdx
	vmwrite %rax, %rdx
	mov $HOST_GS_SELECTOR, %rdx
	vmwrite %rax, %rdx
	mov $SEL_TSS64, %rax
	mov $HOST_TR_SELECTOR, %rdx
	vmwrite %rax, %rdx

	VMSET(HOST_IA32_EFER_FULL, $0x500)

	VMSET(HOST_IA32_SYSENTER_CS, $SEL_CS64)
	VMSET(HOST_IA32_SYSENTER_ESP, $0)
	VMSET(HOST_IA32_SYSENTER_EIP, $0)

	mov %cr0, %rax
	VMSET(HOST_CR0, %rax)
	mov %cr3, %rax
	VMSET(HOST_CR3, %rax)
	mov %cr4, %rax
	VMSET(HOST_CR4, %rax)

	VMSET(HOST_FS_BASE, $0)
	VMSET(HOST_GS_BASE, $0)
	VMSET(HOST_TR_BASE, $ADDR_VAR_TSS64)

	VMSET(HOST_GDTR_BASE, $ADDR_GDT)
	VMSET(HOST_IDTR_BASE, $ADDR_VAR_IDT)

	VMSET(HOST_RSP, $0)
	VMSET(HOST_RIP, ADDR_VAR_VMEXIT_PTR)

	VMSET(VPID, $1)
	VMSET(POSTED_INTERRUPT_NOTIFICATION_VECTOR, $0)
	//VMSET(EPTP_INDEX, $0)

	VMSET(ADDRESS_OF_IO_BITMAP_A_FULL, $0)
	VMSET(ADDRESS_OF_IO_BITMAP_B_FULL, $0)
	VMSET(ADDRESS_OF_MSR_BITMAPS_FULL, $0)
	VMSET(VM_EXIT_MSR_STORE_ADDRESS_FULL, $0)

	mov $0x277, %rcx
	rdmsr
	shl $32, %rdx
	or %rdx, %rax
	VMSET(HOST_IA32_PAT_FULL, %rax)

	VMSET(EXCEPTION_BITMAP, $0)
	VMSET(CR3_TARGET_COUNT, $0)
	VMSET(VM_EXIT_MSR_STORE_COUNT, $0)
	VMSET(VM_EXIT_MSR_LOAD_COUNT, $0)
	VMSET(VM_ENTRY_INTERRUPTION_INFORMATION_FIELD, $0)
	VMSET(VM_ENTRY_MSR_LOAD_COUNT, $0)

	VMSET(CR0_GUEST_HOST_MASK, $0xffffffffffffffff)
	VMSET(CR4_GUEST_HOST_MASK, $0xffffffffffffffff)

	VMSET(EOI_EXIT_BITMAP_0, $0)
	VMSET(EOI_EXIT_BITMAP_1, $0)
	VMSET(EOI_EXIT_BITMAP_2, $0)
	VMSET(EOI_EXIT_BITMAP_3, $0)

	VMSET(GUEST_ES_SELECTOR, $SEL_DS64)
	VMSET(GUEST_CS_SELECTOR, $SEL_CS64)
	VMSET(GUEST_SS_SELECTOR, $SEL_DS64)
	VMSET(GUEST_DS_SELECTOR, $SEL_DS64)
	VMSET(GUEST_FS_SELECTOR, $SEL_DS64)
	VMSET(GUEST_GS_SELECTOR, $SEL_DS64)
	VMSET(GUEST_LDTR_SELECTOR, $0)
	VMSET(GUEST_TR_SELECTOR, $SEL_TSS64)

	VMSET(GUEST_LDTR_BASE, $0)
	VMSET(GUEST_TR_BASE, $ADDR_VAR_TSS64)
	VMSET(GUEST_GDTR_BASE, $ADDR_GDT)
	VMSET(GUEST_IDTR_BASE, $ADDR_VAR_IDT)

	VMSET(GUEST_ES_LIMIT, $0xfffff)
	VMSET(GUEST_CS_LIMIT, $0xfffff)
	VMSET(GUEST_SS_LIMIT, $0xfffff)
	VMSET(GUEST_DS_LIMIT, $0xfffff)
	VMSET(GUEST_FS_LIMIT, $0xfffff)
	VMSET(GUEST_GS_LIMIT, $0xfffff)
	VMSET(GUEST_LDTR_LIMIT, $0)
	VMSET(GUEST_TR_LIMIT, $0x1fff)
	VMSET(GUEST_GDTR_LIMIT, $0x1fff)
	VMSET(GUEST_IDTR_LIMIT, $0x1fff)

	VMSET(GUEST_ES_ACCESS_RIGHTS, $0x4093)
	VMSET(GUEST_CS_ACCESS_RIGHTS, $0x209b)
	VMSET(GUEST_SS_ACCESS_RIGHTS, $0x4093)
	VMSET(GUEST_DS_ACCESS_RIGHTS, $0x4093)
	VMSET(GUEST_FS_ACCESS_RIGHTS, $0x4093)
	VMSET(GUEST_GS_ACCESS_RIGHTS, $0x4093)
	VMSET(GUEST_LDTR_ACCESS_RIGHTS, $0x82)
	VMSET(GUEST_TR_ACCESS_RIGHTS, $0x8b)

	VMSET(GUEST_RSP, $0)
	VMSET(GUEST_RIP, $ADDR_VAR_USER_CODE)
	VMSET(GUEST_RFLAGS, $((1<<1)))
	VMSET(GUEST_IA32_EFER_FULL, $0x500)
	VMSET(GUEST_PDPTE0_FULL, $0)
	VMSET(GUEST_PDPTE1_FULL, $0)
	VMSET(GUEST_PDPTE2_FULL, $0)
	VMSET(GUEST_PDPTE3_FULL, $0)

	mov %cr0, %rax
	VMSET(GUEST_CR0, %rax) // Guest CR0
	mov %cr3, %rax
	VMSET(GUEST_CR3, %rax) // Guest CR3
	mov %cr4, %rax
	VMSET(GUEST_CR4, %rax) // Guest CR4

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
	mov $VM_INSTRUCTION_ERROR, %rbx
	vmread %rbx, %rdx
	mov $EXIT_REASON, %rbx
	vmread %rbx, %rcx
	mov $EXIT_QUALIFICATION, %rax
	vmread %rax, %rax
	mov $GUEST_RIP, %rbx
	vmread %rbx, %rbx
	hlt
kvm_asm64_vm_exit_end:
	nop
