// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_AMD64_SYZOS_H
#define EXECUTOR_COMMON_KVM_AMD64_SYZOS_H

// This file provides guest code running inside the AMD64 KVM.

#include "common_kvm_syzos.h"
#include "kvm.h"
#include <linux/kvm.h>
#include <stdbool.h>

// There are no particular rules to assign numbers here, but changing them will
// result in losing some existing reproducers. Therefore, we try to leave spaces
// between unrelated IDs.
// Remember these constants must match those in sys/linux/dev_kvm_amd64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_CODE = 10,
	SYZOS_API_CPUID = 100,
	SYZOS_API_WRMSR = 101,
	SYZOS_API_RDMSR = 102,
	SYZOS_API_WR_CRN = 103,
	SYZOS_API_WR_DRN = 104,
	SYZOS_API_IN_DX = 105,
	SYZOS_API_OUT_DX = 106,
	SYZOS_API_SET_IRQ_HANDLER = 200,
	SYZOS_API_ENABLE_NESTED = 300,
	SYZOS_API_NESTED_CREATE_VM = 301,
	SYZOS_API_NESTED_LOAD_CODE = 302,
	SYZOS_API_STOP, // Must be the last one
} syzos_api_id;

struct api_call_header {
	uint64 call;
	uint64 size;
};

struct api_call_uexit {
	struct api_call_header header;
	uint64 exit_code;
};

struct api_call_code {
	struct api_call_header header;
	uint8 insns[];
};

struct api_call_nested_load_code {
	struct api_call_header header;
	uint64 vm_id;
	uint8 insns[];
};

struct api_call_cpuid {
	struct api_call_header header;
	uint32 eax;
	uint32 ecx;
};

struct api_call_1 {
	struct api_call_header header;
	uint64 arg;
};

struct api_call_2 {
	struct api_call_header header;
	uint64 args[2];
};

struct api_call_3 {
	struct api_call_header header;
	uint64 args[3];
};

#ifdef __cplusplus
extern "C" {
#endif
GUEST_CODE static void guest_uexit(uint64 exit_code);
#ifdef __cplusplus
}
#endif
GUEST_CODE static void guest_execute_code(uint8* insns, uint64 size);
GUEST_CODE static void guest_handle_cpuid(uint32 eax, uint32 ecx);
GUEST_CODE static void guest_handle_wrmsr(uint64 reg, uint64 val);
GUEST_CODE static void guest_handle_rdmsr(uint64 reg);
GUEST_CODE static void guest_handle_wr_crn(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_wr_drn(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_in_dx(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_out_dx(struct api_call_3* cmd);
GUEST_CODE static void guest_handle_set_irq_handler(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_enable_nested(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_create_vm(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_load_code(struct api_call_nested_load_code* cmd, uint64 cpu_id);

typedef enum {
	UEXIT_END = (uint64)-1,
	UEXIT_IRQ = (uint64)-2,
	UEXIT_ASSERT = (uint64)-3,
} uexit_code;

typedef enum {
	CPU_VENDOR_INTEL,
	CPU_VENDOR_AMD,
} cpu_vendor_id;

__attribute__((naked))
GUEST_CODE static void
dummy_null_handler()
{
	asm("iretq");
}

__attribute__((naked)) GUEST_CODE static void uexit_irq_handler()
{
	asm volatile(R"(
	    // Call guest_uexit(UEXIT_IRQ).
	    movq $-2, %rdi
	    call guest_uexit

	    iretq
	)");
}

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
// The inner loop uses a complex if-statement, because Clang is eager to insert a jump table into
// a switch statement.

// TODO(glider): executor/style_test.go insists that single-line compound statements should not
// be used e.g. in the following case:
//   if (call == SYZOS_API_UEXIT) {
//     struct api_call_uexit* ucmd = (struct api_call_uexit*)cmd;
//     guest_uexit(ucmd->exit_code);
//   } else if (call == SYZOS_API_WR_CRN) {
//     guest_handle_wr_crn((struct api_call_2*)cmd);  // Style check fails here
//   }
// , i.e. when the braces are consistent with the rest of the code, even despite this violates the
// Google C++ style guide.
// We add single-line comments to justify having the compound statements below.
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 size, uint64 cpu)
{
	uint64 addr = X86_SYZOS_ADDR_USER_CODE + cpu * KVM_PAGE_SIZE;

	while (size >= sizeof(struct api_call_header)) {
		struct api_call_header* cmd = (struct api_call_header*)addr;
		if (cmd->call >= SYZOS_API_STOP)
			return;
		if (cmd->size > size)
			return;
		volatile uint64 call = cmd->call;
		if (call == SYZOS_API_UEXIT) {
			// Issue a user exit.
			struct api_call_uexit* ucmd = (struct api_call_uexit*)cmd;
			guest_uexit(ucmd->exit_code);
		} else if (call == SYZOS_API_CODE) {
			// Execute an instruction blob.
			struct api_call_code* ccmd = (struct api_call_code*)cmd;
			guest_execute_code(ccmd->insns, cmd->size - sizeof(struct api_call_header));
		} else if (call == SYZOS_API_CPUID) {
			// Issue CPUID.
			struct api_call_cpuid* ccmd = (struct api_call_cpuid*)cmd;
			guest_handle_cpuid(ccmd->eax, ccmd->ecx);
		} else if (call == SYZOS_API_WRMSR) {
			// Write an MSR register.
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_wrmsr(ccmd->args[0], ccmd->args[1]);
		} else if (call == SYZOS_API_RDMSR) {
			// Read an MSR register.
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_rdmsr(ccmd->arg);
		} else if (call == SYZOS_API_WR_CRN) {
			// Write value to a control register.
			guest_handle_wr_crn((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_WR_DRN) {
			// Write value to a debug register.
			guest_handle_wr_drn((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_IN_DX) {
			// Read data from an I/O port.
			guest_handle_in_dx((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_OUT_DX) {
			// Write data to an I/O port.
			guest_handle_out_dx((struct api_call_3*)cmd);
		} else if (call == SYZOS_API_SET_IRQ_HANDLER) {
			// Set the handler for a particular IRQ.
			guest_handle_set_irq_handler((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_ENABLE_NESTED) {
			// Enable nested virtualization.
			guest_handle_enable_nested((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_CREATE_VM) {
			// Create a nested VM.
			guest_handle_nested_create_vm((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_LOAD_CODE) {
			// Load code into the nested VM.
			guest_handle_nested_load_code((struct api_call_nested_load_code*)cmd, cpu);
		}
		addr += cmd->size;
		size -= cmd->size;
	};
	guest_uexit((uint64)-1);
}

GUEST_CODE static noinline void guest_execute_code(uint8* insns, uint64 size)
{
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

// Perform a userspace exit that can be handled by the host.
// The host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO,
// and can handle the call depending on the data passed as exit code.

// Make sure the compiler does not optimize this function away, it is called from
// assembly.
__attribute__((used))
GUEST_CODE static noinline void
guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)X86_SYZOS_ADDR_UEXIT;
	*ptr = exit_code;
}

GUEST_CODE static noinline void guest_handle_cpuid(uint32 eax, uint32 ecx)
{
	asm volatile(
	    "cpuid\n"
	    : // Currently ignore outputs
	    : "a"(eax), "c"(ecx)
	    : "rbx", "rdx");
}

// Write val into an MSR register reg.
GUEST_CODE static noinline void guest_handle_wrmsr(uint64 reg, uint64 val)
{
	// The wrmsr instruction takes its arguments in specific registers:
	// edx:eax contains the 64-bit value to write, ecx contains the MSR address.
	asm volatile(
	    "wrmsr"
	    :
	    : "c"(reg),
	      "a"((uint32)val),
	      "d"((uint32)(val >> 32))
	    : "memory");
}

// Read an MSR register, ignore the result.
GUEST_CODE static noinline void guest_handle_rdmsr(uint64 reg)
{
	uint32 low = 0, high = 0;
	// The rdmsr instruction takes the MSR address in ecx.
	// It puts the lower 32 bits of the MSR value into eax, and the upper.
	// 32 bits of the MSR value into edx.
	asm volatile(
	    "rdmsr"
	    : "=a"(low),
	      "=d"(high)
	    : "c"(reg)
	    : // No explicit clobbers.
	);
}

// Write to CRn control register.
GUEST_CODE static noinline void guest_handle_wr_crn(struct api_call_2* cmd)
{
	uint64 value = cmd->args[1];
	// Prevent the compiler from generating a switch table.
	volatile uint64 reg = cmd->args[0];
	if (reg == 0) {
		// Move value to CR0.
		asm volatile("movq %0, %%cr0" ::"r"(value) : "memory");
		return;
	}
	if (reg == 2) {
		// Move value to CR2.
		asm volatile("movq %0, %%cr2" ::"r"(value) : "memory");
		return;
	}
	if (reg == 3) {
		// Move value to CR3.
		asm volatile("movq %0, %%cr3" ::"r"(value) : "memory");
		return;
	}
	if (reg == 4) {
		// Move value to CR4.
		asm volatile("movq %0, %%cr4" ::"r"(value) : "memory");
		return;
	}
	if (reg == 8) {
		// Move value to CR8 (TPR - Task Priority Register).
		asm volatile("movq %0, %%cr8" ::"r"(value) : "memory");
		return;
	}
}

// Write to DRn debug register.
GUEST_CODE static noinline void guest_handle_wr_drn(struct api_call_2* cmd)
{
	uint64 value = cmd->args[1];
	volatile uint64 reg = cmd->args[0];
	if (reg == 0) {
		asm volatile("movq %0, %%dr0" ::"r"(value) : "memory");
		return;
	}
	if (reg == 1) {
		asm volatile("movq %0, %%dr1" ::"r"(value) : "memory");
		return;
	}
	if (reg == 2) {
		asm volatile("movq %0, %%dr2" ::"r"(value) : "memory");
		return;
	}
	if (reg == 3) {
		asm volatile("movq %0, %%dr3" ::"r"(value) : "memory");
		return;
	}
	if (reg == 4) {
		asm volatile("movq %0, %%dr4" ::"r"(value) : "memory");
		return;
	}
	if (reg == 5) {
		asm volatile("movq %0, %%dr5" ::"r"(value) : "memory");
		return;
	}
	if (reg == 6) {
		asm volatile("movq %0, %%dr6" ::"r"(value) : "memory");
		return;
	}
	if (reg == 7) {
		asm volatile("movq %0, %%dr7" ::"r"(value) : "memory");
		return;
	}
}

// Read data from an I/O port, should result in KVM_EXIT_IO.
GUEST_CODE static noinline void guest_handle_in_dx(struct api_call_2* cmd)
{
	uint16 port = cmd->args[0];
	volatile int size = cmd->args[1];

	if (size == 1) {
		uint8 unused;
		// Reads 1 byte from the port in DX into AL.
		asm volatile("inb %1, %0" : "=a"(unused) : "d"(port));
		return;
	}
	if (size == 2) {
		uint16 unused;
		// Reads 2 bytes from the port in DX into AX.
		asm volatile("inw %1, %0" : "=a"(unused) : "d"(port));
		return;
	}
	if (size == 4) {
		uint32 unused;
		// Reads 4 bytes from the port in DX into EAX.
		asm volatile("inl %1, %0" : "=a"(unused) : "d"(port));
	}
	return;
}

// Write data to an I/O port, should result in KVM_EXIT_IO.
GUEST_CODE static noinline void guest_handle_out_dx(struct api_call_3* cmd)
{
	uint16 port = cmd->args[0];
	volatile int size = cmd->args[1];
	uint32 data = (uint32)cmd->args[2];

	if (size == 1) {
		// Writes 1 byte from AL to the port in DX.
		asm volatile("outb %b0, %w1" ::"a"(data), "d"(port));
		return;
	}
	if (size == 2) {
		// Writes 2 bytes from AX to the port in DX.
		asm volatile("outw %w0, %w1" ::"a"(data), "d"(port));
		return;
	}
	if (size == 4) {
		// Writes 4 bytes from EAX to the port in DX.
		asm volatile("outl %k0, %w1" ::"a"(data), "d"(port));
		return;
	}
}

// See https://wiki.osdev.org/Interrupt_Descriptor_Table#Gate_Descriptor_2.
struct idt_entry_64 {
	uint16 offset_low;
	uint16 selector;
	// Interrupt Stack Table offset in bits 0..2
	uint8 ist;
	// Gate Type, P and DPL.
	uint8 type_attr;
	uint16 offset_mid;
	uint32 offset_high;
	uint32 reserved;
} __attribute__((packed));

// IDT gate setup should be similar to syzos_setup_idt() in the host code.
GUEST_CODE static void set_idt_gate(uint8 vector, uint64 handler)
{
	volatile struct idt_entry_64* idt =
	    (volatile struct idt_entry_64*)(X86_SYZOS_ADDR_VAR_IDT);
	volatile struct idt_entry_64* idt_entry = &idt[vector];
	idt_entry->offset_low = (uint16)handler;
	idt_entry->offset_mid = (uint16)(handler >> 16);
	idt_entry->offset_high = (uint32)(handler >> 32);
	idt_entry->selector = X86_SYZOS_SEL_CODE;
	idt_entry->type_attr = 0x8E;
	idt_entry->ist = 0;
	idt_entry->reserved = 0;
}

GUEST_CODE static noinline void guest_handle_set_irq_handler(struct api_call_2* cmd)
{
	uint8 vector = (uint8)cmd->args[0];
	uint64 type = cmd->args[1];
	volatile uint64 handler_addr = 0;
	if (type == 1)
		handler_addr = executor_fn_guest_addr(dummy_null_handler);
	else if (type == 2)
		handler_addr = executor_fn_guest_addr(uexit_irq_handler);
	set_idt_gate(vector, handler_addr);
}

GUEST_CODE static cpu_vendor_id get_cpu_vendor(void)
{
	uint32 ebx, eax = 0;

	asm volatile(
	    "cpuid"
	    : "+a"(eax), "=b"(ebx)
	    : // No explicit inputs, EAX is handled by +a.
	    : "ecx", "edx");

	if (ebx == 0x756e6547) { // "Genu[ineIntel]".
		return CPU_VENDOR_INTEL;
	} else if (ebx == 0x68747541) { // "Auth[enticAMD]".
		return CPU_VENDOR_AMD;
	} else {
		// Should not happen on AMD64, but for completeness.
		guest_uexit(UEXIT_ASSERT);
		return CPU_VENDOR_INTEL; // Default to Intel if unknown.
	}
}

GUEST_CODE static inline uint64 read_cr0(void)
{
	uint64 val;
	asm volatile("mov %%cr0, %0" : "=r"(val));
	return val;
}

GUEST_CODE static inline uint64 read_cr3(void)
{
	uint64 val;
	asm volatile("mov %%cr3, %0" : "=r"(val));
	return val;
}

GUEST_CODE static inline uint64 read_cr4(void)
{
	uint64 val;
	asm volatile("mov %%cr4, %0" : "=r"(val));
	return val;
}

GUEST_CODE static inline void write_cr4(uint64 val)
{
	asm volatile("mov %0, %%cr4" : : "r"(val));
}

GUEST_CODE static noinline void wrmsr(uint64 reg, uint64 val)
{
	asm volatile(
	    "wrmsr"
	    :
	    : "c"(reg),
	      "a"((uint32)val),
	      "d"((uint32)(val >> 32))
	    : "memory");
}

GUEST_CODE static noinline uint64 rdmsr(uint32 msr_id)
{
	uint64 msr_value;
	asm volatile("rdmsr" : "=A"(msr_value) : "c"(msr_id));
	return msr_value;
}

GUEST_CODE static noinline void vmwrite(uint64 field, uint64 value)
{
	uint8 error = 0; // nolint
	// 'setna' sets the byte to 1 if CF=1 or ZF=1 (VMfail)
	asm volatile("vmwrite %%rax, %%rbx; setna %0"
		     : "=q"(error)
		     : "a"(value), "b"(field)
		     : "cc", "memory");
	if (error)
		guest_uexit(UEXIT_ASSERT);
}

GUEST_CODE static noinline uint64 vmread(uint64 field)
{
	uint64 value;
	asm volatile("vmread %%rbx, %%rax"
		     : "=a"(value)
		     : "b"(field)
		     : "cc");
	return value;
}

GUEST_CODE static inline void nested_vmptrld(uint64 cpu_id, uint64 vm_id)
{
	uint64 vmcs_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint8 error = 0; // nolint
	asm volatile("vmptrld %1; setna %0"
		     : "=q"(error)
		     : "m"(vmcs_addr)
		     : "memory", "cc");
	if (error)
		guest_uexit(0xE2BAD2);
}

GUEST_CODE static noinline void vmcb_write16(uint64 vmcb, uint16 offset, uint16 val)
{
	*((volatile uint16*)(vmcb + offset)) = val;
}

GUEST_CODE static noinline void vmcb_write32(uint64 vmcb, uint16 offset, uint32 val)
{
	*((volatile uint32*)(vmcb + offset)) = val;
}

GUEST_CODE static noinline void vmcb_write64(uint64 vmcb, uint16 offset, uint64 val)
{
	*((volatile uint64*)(vmcb + offset)) = val;
}

GUEST_CODE static void guest_memset(void* s, uint8 c, int size)
{
	volatile uint8* p = (volatile uint8*)s;
	for (int i = 0; i < size; i++)
		p[i] = c;
}

GUEST_CODE static void guest_memcpy(void* dst, void* src, int size)
{
	volatile uint8* d = (volatile uint8*)dst;
	volatile uint8* s = (volatile uint8*)src;
	for (int i = 0; i < size; i++)
		d[i] = s[i];
}

GUEST_CODE static noinline void
nested_enable_vmx_intel(uint64 cpu_id)
{
	uint64 vmxon_addr = X86_SYZOS_ADDR_VM_ARCH_SPECIFIC(cpu_id);
	uint64 cr4 = read_cr4();
	cr4 |= X86_CR4_VMXE;
	write_cr4(cr4);

	uint64 feature_control = rdmsr(X86_MSR_IA32_FEATURE_CONTROL);
	// Check if Lock bit (bit 0) is clear.
	if ((feature_control & 1) == 0) {
		// If unlocked, set Lock bit (bit 0) and Enable VMX outside SMX bit (bit 2).
		feature_control |= 0b101;
		asm volatile("wrmsr" : : "d"(0x0), "c"(X86_MSR_IA32_FEATURE_CONTROL), "A"(feature_control));
	}

	// Store revision ID at the beginning of VMXON.
	*(uint32*)vmxon_addr = rdmsr(X86_MSR_IA32_VMX_BASIC);
	uint8 error;
	// Can't use enter_vmx_operation() yet, because VMCS is not valid.
	asm volatile("vmxon %1; setna %0"
		     : "=q"(error)
		     : "m"(vmxon_addr)
		     : "memory", "cc");
	if (error) {
		guest_uexit(0xE2BAD0);
		return;
	}
}

GUEST_CODE static noinline void
nested_enable_svm_amd(uint64 cpu_id)
{
	// Get the Host Save Area (HSAVE) physical address for this CPU.
	// The HSAVE area stores the host processor's state on VMRUN and is restored on VMEXIT.
	uint64 hsave_addr = X86_SYZOS_ADDR_VM_ARCH_SPECIFIC(cpu_id);

	// Set the SVM Enable (SVME) bit in EFER. This enables SVM operations.
	uint64 efer = rdmsr(X86_MSR_IA32_EFER);
	efer |= X86_EFER_SVME;
	wrmsr(X86_MSR_IA32_EFER, efer);

	// Write the physical address of the HSAVE area to the VM_HSAVE_PA MSR.
	// This MSR tells the CPU where to save/restore host state during VMRUN/VMEXIT.
	wrmsr(X86_MSR_VM_HSAVE_PA, hsave_addr);
}

GUEST_CODE static noinline void
guest_handle_enable_nested(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		nested_enable_vmx_intel(cpu_id);
	} else {
		nested_enable_svm_amd(cpu_id);
	}
}

GUEST_CODE static noinline void setup_l2_page_tables(cpu_vendor_id vendor, uint64 cpu_id, uint64 vm_id)
{
	uint64 l2_pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	uint64 l2_pdpt_addr = l2_pml4_addr + KVM_PAGE_SIZE;
	uint64 l2_pd_addr = l2_pml4_addr + 2 * KVM_PAGE_SIZE;
	uint64 l2_pt_addr = l2_pml4_addr + 3 * KVM_PAGE_SIZE;

	volatile uint64* pml4 = (volatile uint64*)l2_pml4_addr;
	volatile uint64* pdpt = (volatile uint64*)l2_pdpt_addr;
	volatile uint64* pd = (volatile uint64*)l2_pd_addr;
	volatile uint64* pt = (volatile uint64*)l2_pt_addr;

	guest_memset((void*)l2_pml4_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_pdpt_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_pd_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_pt_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)X86_SYZOS_ADDR_MSR_BITMAP(cpu_id, vm_id), 0, KVM_PAGE_SIZE);

	// Intel EPT: set Read, Write, Execute.
	// AMD NPT: set Present, Write, User.
	uint64 flags = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER;
	// Create the 4-level page table entries using 4KB pages:
	//    PML4[0] -> points to PDPT
	pml4[0] = l2_pdpt_addr | flags;
	//    PDPT[0] -> points to Page Directory (PD)
	pdpt[0] = l2_pd_addr | flags;
	//    PD[0]   -> points to Page Table (PT) (NO X86_PDE64_PS)
	pd[0] = l2_pt_addr | flags;
	//    PT[0..511] -> maps 512 4KB pages (2MB total) identity
	uint64 pt_flags = flags;
	if (vendor == CPU_VENDOR_INTEL) {
		pt_flags |= EPT_MEMTYPE_WB | EPT_ACCESSED | EPT_DIRTY;
	} else {
		pt_flags |= X86_PDE64_ACCESSED | X86_PDE64_DIRTY;
	}
	for (int i = 0; i < 512; i++)
		pt[i] = (i * KVM_PAGE_SIZE) | pt_flags;
}

GUEST_CODE static noinline void init_vmcs_control_fields(uint64 cpu_id, uint64 vm_id)
{
	// Read and write Pin-Based controls from TRUE MSR.
	uint64 vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS);
	vmwrite(VMCS_PIN_BASED_VM_EXEC_CONTROL, (uint32)vmx_msr);

	// Setup Secondary Processor-Based controls: enable EPT.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_PROCBASED_CTLS2);
	uint32 sec_exec_ctl = (uint32)(vmx_msr >> 32); // Must-be-1 bits.
	sec_exec_ctl |= ((uint32)vmx_msr & SECONDARY_EXEC_ENABLE_EPT); // Allowed bits.
	vmwrite(VMCS_SECONDARY_VM_EXEC_CONTROL, sec_exec_ctl);

	// Read and write Primary Processor-Based controls from TRUE MSR.
	// We also add the bit to enable the secondary controls.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, (uint32)vmx_msr | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_HLT_EXITING);

	// Set up VM-Exit controls via TRUE MSR: indicate a 64-bit host.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS);
	vmwrite(VMCS_VM_EXIT_CONTROLS, (uint32)vmx_msr | VM_EXIT_HOST_ADDR_SPACE_SIZE);
	// Read and write VM-Entry controls from TRUE MSR
	// We add the bit to indicate a 64-bit guest.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS);
	vmwrite(VMCS_VM_ENTRY_CONTROLS, (uint32)vmx_msr | VM_ENTRY_IA32E_MODE);

	// Set up the EPT Pointer.
	// We use the L2 PML4 address we calculate in guest_handle_create_nested_vm.
	// The EPT Pointer has:
	// - Memory Type = 6 (Write-Back)
	// - Page-Walk Length = 3 (meaning 4 levels: PML4, PDPT, PD, PT)
	// - Address of the PML4 table
	uint64 eptp = (X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id) & ~0xFFF) | (6 << 0) | (3 << 3);
	vmwrite(VMCS_EPT_POINTER, eptp);

	// Set CR0/CR4 masks and shadows.
	// This simple setup (masks=0) means any guest CR0/CR4 write is allowed
	// and won't cause a VM-Exit.
	vmwrite(VMCS_CR0_GUEST_HOST_MASK, 0);
	vmwrite(VMCS_CR4_GUEST_HOST_MASK, 0);
	vmwrite(VMCS_CR0_READ_SHADOW, read_cr0());
	vmwrite(VMCS_CR4_READ_SHADOW, read_cr4());

	// Disable the bitmaps which we do not use.
	vmwrite(VMCS_MSR_BITMAP, 0);
	vmwrite(VMCS_VMREAD_BITMAP, 0);
	vmwrite(VMCS_VMWRITE_BITMAP, 0);

	// Intercept #UD (Invalid Opcode)
	vmwrite(VMCS_EXCEPTION_BITMAP, (1 << 6));

	// Clear unused/unsupported fields.
	// TODO(glider): do we need these?
	vmwrite(VMCS_VIRTUAL_PROCESSOR_ID, 0);
	vmwrite(VMCS_POSTED_INTR_NV, 0);
	vmwrite(VMCS_PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmwrite(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, -1);
	vmwrite(VMCS_CR3_TARGET_COUNT, 0);
	vmwrite(VMCS_VM_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VMCS_VM_EXIT_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, 0);
	vmwrite(VMCS_TPR_THRESHOLD, 0);
}

// Empty for now.
__attribute__((naked)) GUEST_CODE static void nested_vm_exit_handler_intel_asm(void)
{
}

GUEST_CODE static noinline void init_vmcs_host_state(void)
{
	// Segment Selectors.
	vmwrite(VMCS_HOST_CS_SELECTOR, X86_SYZOS_SEL_CODE);
	vmwrite(VMCS_HOST_DS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_ES_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_SS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_FS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_GS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_TR_SELECTOR, X86_SYZOS_SEL_TSS64);

	// Base addresses.
	vmwrite(VMCS_HOST_TR_BASE, 0);
	vmwrite(VMCS_HOST_GDTR_BASE, X86_SYZOS_ADDR_GDT);
	vmwrite(VMCS_HOST_IDTR_BASE, X86_SYZOS_ADDR_VAR_IDT);
	vmwrite(VMCS_HOST_FS_BASE, rdmsr(X86_MSR_FS_BASE));
	vmwrite(VMCS_HOST_GS_BASE, rdmsr(X86_MSR_GS_BASE));

	// RIP and RSP.
	uint64 tmpreg = 0; // nolint
	asm volatile("mov %%rsp, %0" : "=r"(tmpreg));
	vmwrite(VMCS_HOST_RSP, tmpreg);
	vmwrite(VMCS_HOST_RIP, (uintptr_t)nested_vm_exit_handler_intel_asm);

	// Control Registers.
	vmwrite(VMCS_HOST_CR0, read_cr0());
	vmwrite(VMCS_HOST_CR3, read_cr3());
	vmwrite(VMCS_HOST_CR4, read_cr4());

	// MSRs.
	vmwrite(VMCS_HOST_IA32_PAT, rdmsr(X86_MSR_IA32_CR_PAT));
	vmwrite(VMCS_HOST_IA32_EFER, rdmsr(X86_MSR_IA32_EFER));
	vmwrite(VMCS_HOST_IA32_PERF_GLOBAL_CTRL, rdmsr(X86_MSR_CORE_PERF_GLOBAL_CTRL));
	vmwrite(VMCS_HOST_IA32_SYSENTER_CS, rdmsr(X86_MSR_IA32_SYSENTER_CS));
	vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, rdmsr(X86_MSR_IA32_SYSENTER_ESP));
	vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, rdmsr(X86_MSR_IA32_SYSENTER_EIP));
}

#define COPY_VMCS_FIELD(GUEST_FIELD, HOST_FIELD) \
	vmwrite(GUEST_FIELD, vmread(HOST_FIELD))

#define SETUP_L2_SEGMENT(SEG, SELECTOR, BASE, LIMIT, AR) \
	vmwrite(VMCS_GUEST_##SEG##_SELECTOR, SELECTOR);  \
	vmwrite(VMCS_GUEST_##SEG##_BASE, BASE);          \
	vmwrite(VMCS_GUEST_##SEG##_LIMIT, LIMIT);        \
	vmwrite(VMCS_GUEST_##SEG##_ACCESS_RIGHTS, AR);

GUEST_CODE static noinline void init_vmcs_guest_state(uint64 cpu_id, uint64 vm_id)
{
	uint64 l2_code_addr = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
	uint64 l2_stack_addr = X86_SYZOS_ADDR_VM_STACK(cpu_id, vm_id);
	// Segment Registers.
	SETUP_L2_SEGMENT(CS, vmread(VMCS_HOST_CS_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_CODE);
	SETUP_L2_SEGMENT(DS, vmread(VMCS_HOST_DS_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(ES, vmread(VMCS_HOST_ES_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(SS, vmread(VMCS_HOST_SS_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(FS, vmread(VMCS_HOST_FS_SELECTOR), vmread(VMCS_HOST_FS_BASE), 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(GS, vmread(VMCS_HOST_GS_SELECTOR), vmread(VMCS_HOST_GS_BASE), 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);

	// Task and LDT Registers.
	SETUP_L2_SEGMENT(TR, vmread(VMCS_HOST_TR_SELECTOR), vmread(VMCS_HOST_TR_BASE), 0x67, VMX_AR_TSS_BUSY);
	SETUP_L2_SEGMENT(LDTR, 0, 0, 0, VMX_AR_LDTR_UNUSABLE);

	// Control Registers & CPU State.
	vmwrite(VMCS_GUEST_CR0, vmread(VMCS_HOST_CR0));
	vmwrite(VMCS_GUEST_CR3, vmread(VMCS_HOST_CR3));
	vmwrite(VMCS_GUEST_CR4, vmread(VMCS_HOST_CR4));
	vmwrite(VMCS_GUEST_RIP, l2_code_addr);
	vmwrite(VMCS_GUEST_RSP, l2_stack_addr + KVM_PAGE_SIZE - 8);
	vmwrite(VMCS_GUEST_RFLAGS, RFLAGS_1_BIT);
	// TODO
	vmwrite(VMCS_GUEST_DR7, 0x400);

	// MSRs - Copy from host or set to default.
	COPY_VMCS_FIELD(VMCS_GUEST_IA32_EFER, VMCS_HOST_IA32_EFER);
	COPY_VMCS_FIELD(VMCS_GUEST_IA32_PAT, VMCS_HOST_IA32_PAT);
	COPY_VMCS_FIELD(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, VMCS_HOST_IA32_PERF_GLOBAL_CTRL);
	COPY_VMCS_FIELD(VMCS_GUEST_SYSENTER_CS, VMCS_HOST_IA32_SYSENTER_CS);
	COPY_VMCS_FIELD(VMCS_GUEST_SYSENTER_ESP, VMCS_HOST_IA32_SYSENTER_ESP);
	COPY_VMCS_FIELD(VMCS_GUEST_SYSENTER_EIP, VMCS_HOST_IA32_SYSENTER_EIP);
	vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);

	// Descriptor Tables.
	vmwrite(VMCS_GUEST_GDTR_BASE, vmread(VMCS_HOST_GDTR_BASE));
	vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_IDTR_BASE, vmread(VMCS_HOST_IDTR_BASE));
	vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);

	// Miscellaneous Fields.
	vmwrite(VMCS_LINK_POINTER, 0xffffffffffffffff);
	// 0 = Active.
	vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);
	vmwrite(VMCS_GUEST_INTERRUPTIBILITY_INFO, 0);
	vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmwrite(VMCS_VMX_PREEMPTION_TIMER_VALUE, 0);
	vmwrite(VMCS_GUEST_INTR_STATUS, 0);
	vmwrite(VMCS_GUEST_PML_INDEX, 0);
}

GUEST_CODE static noinline void
nested_create_vm_intel(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	uint64 vmcs_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint8 error = 0; // nolint

	*(uint32*)vmcs_addr = rdmsr(X86_MSR_IA32_VMX_BASIC);
	asm volatile("vmclear %1; setna %0"
		     : "=q"(error)
		     : "m"(vmcs_addr)
		     : "memory", "cc");
	if (error) {
		guest_uexit(0xE2BAD1);
		return;
	}
	nested_vmptrld(cpu_id, vm_id);

	setup_l2_page_tables(CPU_VENDOR_INTEL, cpu_id, vm_id);
	init_vmcs_control_fields(cpu_id, vm_id);
	init_vmcs_host_state();
	init_vmcs_guest_state(cpu_id, vm_id);
}

// Helper for setting up a segment in the VMCB
#define SETUP_L2_SEGMENT_SVM(VMBC_PTR, SEG_NAME, SELECTOR, BASE, LIMIT, ATTR) \
	vmcb_write16(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_SEL, SELECTOR);        \
	vmcb_write16(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_ATTR, ATTR);           \
	vmcb_write32(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_LIM, LIMIT);           \
	vmcb_write64(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_BASE, BASE);

GUEST_CODE static noinline void init_vmcb_guest_state(uint64 cpu_id, uint64 vm_id)
{
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 l2_code_addr = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
	uint64 l2_stack_addr = X86_SYZOS_ADDR_VM_STACK(cpu_id, vm_id);
	uint64 npt_pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	// Setup Guest Segment Registers.
	// We copy the L1 guest's segment setup, as it's a good 64-bit environment.
	SETUP_L2_SEGMENT_SVM(vmcb_addr, CS, X86_SYZOS_SEL_CODE, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_CODE);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, DS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, ES, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, SS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, FS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, GS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);

	// Task Register (TR). Must point to a valid, present, 64-bit TSS.
	SETUP_L2_SEGMENT_SVM(vmcb_addr, TR, X86_SYZOS_SEL_TSS64, X86_SYZOS_ADDR_VAR_TSS, 0x67, VMX_AR_TSS_AVAILABLE);

	// LDT Register (LDTR) - Mark as unusable.
	// A null selector and attribute is the correct way to disable LDTR.
	SETUP_L2_SEGMENT_SVM(vmcb_addr, LDTR, 0, 0, 0, SVM_ATTR_LDTR_UNUSABLE);

	// Setup Guest Control Registers & CPU State.
	uint64 efer = rdmsr(X86_MSR_IA32_EFER);
	vmcb_write64(vmcb_addr, VMCB_GUEST_CR0, read_cr0() | X86_CR0_WP);
	// L2 will use L1's page tables.
	vmcb_write64(vmcb_addr, VMCB_GUEST_CR3, read_cr3());
	vmcb_write64(vmcb_addr, VMCB_GUEST_CR4, read_cr4());
	vmcb_write64(vmcb_addr, VMCB_GUEST_RIP, l2_code_addr);
	vmcb_write64(vmcb_addr, VMCB_GUEST_RSP, l2_stack_addr + KVM_PAGE_SIZE - 8);
	vmcb_write64(vmcb_addr, VMCB_GUEST_RFLAGS, RFLAGS_1_BIT);

	// Setup Guest MSRs.

	// SYSCALL/SYSRET MSRs.
	vmcb_write64(vmcb_addr, VMCB_GUEST_DEBUGCTL, 0);
	vmcb_write64(vmcb_addr, VMCB_GUEST_DR6, 0x0);
	vmcb_write64(vmcb_addr, VMCB_GUEST_DR7, 0x0);

	vmcb_write64(vmcb_addr, VMCB_GUEST_EFER, efer & ~X86_EFER_SCE);
	vmcb_write64(vmcb_addr, VMCB_GUEST_PAT, rdmsr(X86_MSR_IA32_CR_PAT));

	// Setup Guest Descriptor Tables.
	struct {
		uint16 limit;
		uint64 base;
	} __attribute__((packed)) gdtr, idtr;
	asm volatile("sgdt %0" : "=m"(gdtr));
	asm volatile("sidt %0" : "=m"(idtr));
	vmcb_write64(vmcb_addr, VMCB_GUEST_GDTR_BASE, gdtr.base);
	vmcb_write32(vmcb_addr, VMCB_GUEST_GDTR_LIM, gdtr.limit);
	vmcb_write64(vmcb_addr, VMCB_GUEST_IDTR_BASE, idtr.base);
	vmcb_write32(vmcb_addr, VMCB_GUEST_IDTR_LIM, idtr.limit);

	// Setup VMCB Control Fields.
	vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3, VMCB_CTRL_INTERCEPT_HLT);
	vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC4, VMCB_CTRL_INTERCEPT_VEC4_ALL);

	// Enable Nested Paging (NPT):
	// Write '1' to the NPT Enable field (0x090).
	vmcb_write64(vmcb_addr, VMCB_CTRL_NP_ENABLE, (1 << VMCB_CTRL_NPT_ENABLE_BIT));

	// 2Write the NPT root address to N_CR3 (0x098)
	// Unlike Intel's EPTP, AMD's N_CR3 field is *only* the
	// 4K-aligned physical address of the PML4 table.
	// It does not contain any control bits.
	uint64 npt_pointer = (npt_pml4_addr & ~0xFFF);
	vmcb_write64(vmcb_addr, VMCB_CTRL_N_CR3, npt_pointer);

	// Set Guest ASID.
	vmcb_write32(vmcb_addr, VMCB_CTRL_ASID, 1);
}

GUEST_CODE static noinline void
nested_create_vm_amd(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	guest_memset((void*)vmcb_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)X86_SYZOS_ADDR_VM_ARCH_SPECIFIC(cpu_id), 0, KVM_PAGE_SIZE);

	// Setup NPT (Nested Page Tables)
	setup_l2_page_tables(CPU_VENDOR_AMD, cpu_id, vm_id);

	// Initialize VMCB Control and Guest State
	init_vmcb_guest_state(cpu_id, vm_id);
}

GUEST_CODE static noinline void
guest_handle_nested_create_vm(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		nested_create_vm_intel(cmd, cpu_id);
	} else {
		nested_create_vm_amd(cmd, cpu_id);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_load_code(struct api_call_nested_load_code* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->vm_id;
	uint64 l2_code_addr = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
	uint64 l2_stack_addr = X86_SYZOS_ADDR_VM_STACK(cpu_id, vm_id);
	// Code size = command size - header size - vm_id size.
	uint64 l2_code_size = cmd->header.size - sizeof(struct api_call_header) - sizeof(uint64);
	if (l2_code_size > KVM_PAGE_SIZE)
		l2_code_size = KVM_PAGE_SIZE;
	guest_memcpy((void*)l2_code_addr, (void*)cmd->insns,
		     l2_code_size);
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		nested_vmptrld(cpu_id, vm_id);
		vmwrite(VMCS_GUEST_RIP, l2_code_addr);
		vmwrite(VMCS_GUEST_RSP, l2_stack_addr + KVM_PAGE_SIZE - 8);
	} else {
		vmcb_write64(X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id), VMCB_GUEST_RIP, l2_code_addr);
		vmcb_write64(X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id), VMCB_GUEST_RSP, l2_stack_addr + KVM_PAGE_SIZE - 8);
	}
}

#endif // EXECUTOR_COMMON_KVM_AMD64_SYZOS_H
