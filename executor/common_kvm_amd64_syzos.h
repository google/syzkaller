// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_AMD64_SYZOS_H
#define EXECUTOR_COMMON_KVM_AMD64_SYZOS_H

// This file provides guest code running inside the AMD64 KVM.

#include <linux/kvm.h>
#include <stdbool.h>

#include "common_kvm_syzos.h"
#include "kvm.h"

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
	SYZOS_API_NESTED_VMLAUNCH = 303,
	SYZOS_API_NESTED_VMRESUME = 304,
	SYZOS_API_NESTED_INTEL_VMWRITE_MASK = 340,
	SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK = 380,
	SYZOS_API_NESTED_AMD_INVLPGA = 381,
	SYZOS_API_NESTED_AMD_STGI = 382,
	SYZOS_API_NESTED_AMD_CLGI = 383,
	SYZOS_API_NESTED_AMD_INJECT_EVENT = 384,
	SYZOS_API_NESTED_AMD_SET_INTERCEPT = 385,
	SYZOS_API_NESTED_AMD_VMLOAD = 386,
	SYZOS_API_NESTED_AMD_VMSAVE = 387,
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

struct api_call_5 {
	struct api_call_header header;
	uint64 args[5];
};

// This struct must match the push/pop order in nested_vm_exit_handler_intel_asm().
struct l2_guest_regs {
	uint64 rax, rbx, rcx, rdx, rsi, rdi, rbp;
	uint64 r8, r9, r10, r11, r12, r13, r14, r15;
};

struct mem_region {
	uint64 gpa;
	int pages;
	uint32 flags;
};

struct syzos_boot_args {
	uint32 region_count;
	uint32 reserved;
	struct mem_region regions[];
};

struct syzos_globals {
	uint64 alloc_offset;
	uint64 total_size;
};

#ifdef __cplusplus
extern "C" {
#endif
GUEST_CODE static void guest_uexit(uint64 exit_code);
GUEST_CODE static void nested_vm_exit_handler_intel(uint64 exit_reason, struct l2_guest_regs* regs);
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
GUEST_CODE static void guest_handle_nested_vmlaunch(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_vmresume(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_intel_vmwrite_mask(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_vmcb_write_mask(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_invlpga(struct api_call_2* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_stgi();
GUEST_CODE static void guest_handle_nested_amd_clgi();
GUEST_CODE static void guest_handle_nested_amd_inject_event(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_set_intercept(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_vmload(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_vmsave(struct api_call_1* cmd, uint64 cpu_id);

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
		} else if (call == SYZOS_API_NESTED_VMLAUNCH) {
			// Launch the nested VM.
			guest_handle_nested_vmlaunch((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_VMRESUME) {
			// Resume a nested VM.
			guest_handle_nested_vmresume((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_INTEL_VMWRITE_MASK) {
			// Write to a VMCS field using masks.
			guest_handle_nested_intel_vmwrite_mask((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK) {
			// Write to a VMCB field using masks.
			guest_handle_nested_amd_vmcb_write_mask((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_INVLPGA) {
			// Invalidate TLB mappings for the specified address/ASID.
			guest_handle_nested_amd_invlpga((struct api_call_2*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_STGI) {
			// Set Global Interrupt Flag (Enable Interrupts).
			guest_handle_nested_amd_stgi();
		} else if (call == SYZOS_API_NESTED_AMD_CLGI) {
			// Clear Global Interrupt Flag (Disable Interrupts, including NMI).
			guest_handle_nested_amd_clgi();
		} else if (call == SYZOS_API_NESTED_AMD_INJECT_EVENT) {
			// Inject an event (IRQ/Exception) into the L2 guest via VMCB.
			guest_handle_nested_amd_inject_event((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_SET_INTERCEPT) {
			// Set/Clear specific intercept bits in the VMCB.
			guest_handle_nested_amd_set_intercept((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_VMLOAD) {
			// Execute VMLOAD to load state from VMCB.
			guest_handle_nested_amd_vmload((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_VMSAVE) {
			// Execute VMSAVE to save state to VMCB.
			guest_handle_nested_amd_vmsave((struct api_call_1*)cmd, cpu);
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

// Write val into an MSR register reg.
GUEST_CODE static noinline void guest_handle_wrmsr(uint64 reg, uint64 val)
{
	wrmsr(reg, val);
}

GUEST_CODE static noinline uint64 rdmsr(uint64 msr_id)
{
	uint32 low = 0, high = 0; // nolint
	// The RDMSR instruction takes the MSR address in ecx.
	// It puts the lower 32 bits of the MSR value into eax, and the upper.
	// 32 bits of the MSR value into edx.
	asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr_id));
	return ((uint64)high << 32) | low;
}

// Read an MSR register, ignore the result.
GUEST_CODE static noinline void guest_handle_rdmsr(uint64 reg)
{
	(void)rdmsr(reg);
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

GUEST_CODE static noinline uint32 vmcb_read32(uint64 vmcb, uint16 offset)
{
	return *((volatile uint32*)(vmcb + offset));
}

GUEST_CODE static noinline void vmcb_write64(uint64 vmcb, uint16 offset, uint64 val)
{
	*((volatile uint64*)(vmcb + offset)) = val;
}

GUEST_CODE static noinline uint64 vmcb_read64(volatile uint8* vmcb, uint16 offset)
{
	return *((volatile uint64*)(vmcb + offset));
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

// Calculate the size of the unused memory region from the boot arguments.
GUEST_CODE static uint64 get_unused_memory_size()
{
	volatile struct syzos_boot_args* args = (volatile struct syzos_boot_args*)X86_SYZOS_ADDR_BOOT_ARGS;
	for (uint32 i = 0; i < args->region_count; i++) {
		if (args->regions[i].gpa == X86_SYZOS_ADDR_UNUSED)
			return args->regions[i].pages * KVM_PAGE_SIZE;
	}
	return 0;
}

// Allocate a page from the X86_SYZOS_ADDR_UNUSED region using a non-reclaiming bump allocator.
GUEST_CODE static uint64 guest_alloc_page()
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;

	// Lazy initialization of total_size using CAS to prevent races.
	if (globals->total_size == 0) {
		uint64 size = get_unused_memory_size();
		// Attempt to swap 0 with the calculated size.
		// If another CPU beat us to it, this does nothing (which is fine).
		__sync_val_compare_and_swap(&globals->total_size, 0, size);
	}

	// Atomic fetch-and-add to reserve space.
	uint64 offset = __sync_fetch_and_add(&globals->alloc_offset, KVM_PAGE_SIZE);

	if (offset >= globals->total_size)
		guest_uexit(UEXIT_ASSERT);

	uint64 ptr = X86_SYZOS_ADDR_UNUSED + offset;
	guest_memset((void*)ptr, 0, KVM_PAGE_SIZE);
	return ptr;
}

GUEST_CODE static noinline void setup_l2_page_tables(cpu_vendor_id vendor, uint64 cpu_id, uint64 vm_id)
{
	// The Root PML4 remains at the fixed address assigned to this VM.
	uint64 l2_pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);

	// Allocate subsequent levels dynamically.
	uint64 l2_pdpt_addr = guest_alloc_page();
	uint64 l2_pd_addr = guest_alloc_page();
	uint64 l2_pt_addr = guest_alloc_page();

	volatile uint64* pml4 = (volatile uint64*)l2_pml4_addr;
	volatile uint64* pdpt = (volatile uint64*)l2_pdpt_addr;
	volatile uint64* pd = (volatile uint64*)l2_pd_addr;
	volatile uint64* pt = (volatile uint64*)l2_pt_addr;

	// Clear the root table (the others are cleared by guest_alloc_page).
	guest_memset((void*)l2_pml4_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)X86_SYZOS_ADDR_MSR_BITMAP(cpu_id, vm_id), 0, KVM_PAGE_SIZE);

	// Intel EPT: set Read, Write, Execute.
	// AMD NPT: set Present, Write, User.
	uint64 flags = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER;

	// Setup Hierarchy:
	// PML4[0] -> PDPT
	pml4[0] = l2_pdpt_addr | flags;
	// PDPT[0] -> PD
	pdpt[0] = l2_pd_addr | flags;
	// PD[0] -> PT
	pd[0] = l2_pt_addr | flags;

	// PT[0..511] -> Maps 2MB identity
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
	vmx_msr = (uint32)rdmsr(X86_MSR_IA32_VMX_PROCBASED_CTLS2);
	vmx_msr |= SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_RDTSCP;
	vmwrite(VMCS_SECONDARY_VM_EXEC_CONTROL, vmx_msr);

	// Read and write Primary Processor-Based controls from TRUE MSR.
	// We also add the bit to enable the secondary controls.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	vmx_msr |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	// Exit on HLT and RDTSC.
	vmx_msr |= CPU_BASED_HLT_EXITING | CPU_BASED_RDTSC_EXITING;
	vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, (uint32)vmx_msr);

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

// Common L2 exit reasons for Intel and AMD.
typedef enum {
	SYZOS_NESTED_EXIT_REASON_HLT = 1,
	SYZOS_NESTED_EXIT_REASON_INVD = 2,
	SYZOS_NESTED_EXIT_REASON_CPUID = 3,
	SYZOS_NESTED_EXIT_REASON_RDTSC = 4,
	SYZOS_NESTED_EXIT_REASON_RDTSCP = 5,
	SYZOS_NESTED_EXIT_REASON_UNKNOWN = 0xFF,
} syz_nested_exit_reason;

GUEST_CODE static void guest_uexit_l2(uint64 exit_reason, syz_nested_exit_reason mapped_reason,
				      cpu_vendor_id vendor)
{
	if (mapped_reason != SYZOS_NESTED_EXIT_REASON_UNKNOWN) {
		guest_uexit(0xe2e20000 | mapped_reason);
	} else if (vendor == CPU_VENDOR_INTEL) {
		guest_uexit(0xe2110000 | exit_reason);
	} else {
		guest_uexit(0xe2aa0000 | exit_reason);
	}
}

#define EXIT_REASON_CPUID 0xa
#define EXIT_REASON_HLT 0xc
#define EXIT_REASON_INVD 0xd
#define EXIT_REASON_RDTSC 0x10
#define EXIT_REASON_RDTSCP 0x33

GUEST_CODE static syz_nested_exit_reason map_intel_exit_reason(uint64 basic_reason)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	if (reason == EXIT_REASON_HLT)
		return SYZOS_NESTED_EXIT_REASON_HLT;
	if (reason == EXIT_REASON_INVD)
		return SYZOS_NESTED_EXIT_REASON_INVD;
	if (reason == EXIT_REASON_CPUID)
		return SYZOS_NESTED_EXIT_REASON_CPUID;
	if (reason == EXIT_REASON_RDTSC)
		return SYZOS_NESTED_EXIT_REASON_RDTSC;
	if (reason == EXIT_REASON_RDTSCP)
		return SYZOS_NESTED_EXIT_REASON_RDTSCP;
	return SYZOS_NESTED_EXIT_REASON_UNKNOWN;
}

GUEST_CODE static void advance_l2_rip_intel(uint64 basic_reason)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	uint64 rip = vmread(VMCS_GUEST_RIP);
	if ((reason == EXIT_REASON_INVD) || (reason == EXIT_REASON_CPUID) ||
	    (reason == EXIT_REASON_RDTSC)) {
		rip += 2;
	} else if (reason == EXIT_REASON_RDTSCP) {
		// We insist on a single-line compound statement for else-if.
		rip += 3;
	}
	vmwrite(VMCS_GUEST_RIP, rip);
}

// This function is called from inline assembly.
__attribute__((used))
GUEST_CODE static void
nested_vm_exit_handler_intel(uint64 exit_reason, struct l2_guest_regs* regs)
{
	uint64 basic_reason = exit_reason & 0xFFFF;
	syz_nested_exit_reason mapped_reason = map_intel_exit_reason(basic_reason);
	guest_uexit_l2(exit_reason, mapped_reason, CPU_VENDOR_INTEL);
	advance_l2_rip_intel(basic_reason);
}

extern char after_vmentry_label;
__attribute__((naked)) GUEST_CODE static void nested_vm_exit_handler_intel_asm(void)
{
	asm volatile(R"(
      // Save L2's GPRs. This creates the 'struct l2_guest_regs' on the stack.
      // The order MUST match the struct.
      push %%rax
      push %%rbx
      push %%rcx
      push %%rdx
      push %%rsi
      push %%rdi
      push %%rbp
      push %%r8
      push %%r9
      push %%r10
      push %%r11
      push %%r12
      push %%r13
      push %%r14
      push %%r15

      // Prepare arguments for the C handler:
      //    arg1 (RDI) = exit_reason
      //    arg2 (RSI) = pointer to the saved registers
      mov %%rsp, %%rsi
      mov %[vm_exit_reason], %%rbx
      vmread %%rbx, %%rdi

      // Call the C handler.
      call nested_vm_exit_handler_intel

      // The C handler has processed the exit. Now, return to the L1 command
      // processing loop. VMX remains enabled.
      add %[stack_cleanup_size], %%rsp

      // Jump to L1 main flow
      jmp after_vmentry_label
	)"

		     : : [stack_cleanup_size] "i"(sizeof(struct l2_guest_regs)),
			 [vm_exit_reason] "i"(VMCS_VM_EXIT_REASON) : "memory", "cc", "rbx", "rdi", "rsi");
}

#define VMEXIT_RDTSC 0x6e
#define VMEXIT_CPUID 0x72
#define VMEXIT_INVD 0x76
#define VMEXIT_HLT 0x78
#define VMEXIT_RDTSCP 0x87

GUEST_CODE static syz_nested_exit_reason map_amd_exit_reason(uint64 basic_reason)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	if (reason == VMEXIT_HLT)
		return SYZOS_NESTED_EXIT_REASON_HLT;
	if (reason == VMEXIT_INVD)
		return SYZOS_NESTED_EXIT_REASON_INVD;
	if (reason == VMEXIT_CPUID)
		return SYZOS_NESTED_EXIT_REASON_CPUID;
	if (reason == VMEXIT_RDTSC)
		return SYZOS_NESTED_EXIT_REASON_RDTSC;
	if (reason == VMEXIT_RDTSCP)
		return SYZOS_NESTED_EXIT_REASON_RDTSCP;
	return SYZOS_NESTED_EXIT_REASON_UNKNOWN;
}

GUEST_CODE static void advance_l2_rip_amd(uint64 basic_reason, uint64 cpu_id, uint64 vm_id)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 rip = vmcb_read64((volatile uint8*)vmcb_addr, VMCB_GUEST_RIP);
	if ((reason == VMEXIT_INVD) || (reason == VMEXIT_CPUID) ||
	    (reason == VMEXIT_RDTSC)) {
		rip += 2;
	} else if (reason == VMEXIT_RDTSCP) {
		// We insist on a single-line compound statement for else-if.
		rip += 3;
	}
	vmcb_write64(vmcb_addr, VMCB_GUEST_RIP, rip);
}

__attribute__((used)) GUEST_CODE static void
nested_vm_exit_handler_amd(uint64 exit_reason, uint64 cpu_id, uint64 vm_id)
{
	volatile uint64 basic_reason = exit_reason & 0xFFFF;
	syz_nested_exit_reason mapped_reason = map_amd_exit_reason(basic_reason);
	guest_uexit_l2(exit_reason, mapped_reason, CPU_VENDOR_AMD);
	advance_l2_rip_amd(basic_reason, cpu_id, vm_id);
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
	vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3, VMCB_CTRL_INTERCEPT_VEC3_ALL);
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

// Clang's LTO may ignore noinline and attempt to inline this function into both callers,
// which results in duplicate declaration of after_vmentry_label.
// Applying __optnone should prevent this behavior.
GUEST_CODE static noinline __optnone void
guest_handle_nested_vmentry_intel(uint64 vm_id, uint64 cpu_id, bool is_launch)
{
	uint64 vmx_error_code = 0;
	uint8 fail_flag = 0; // Will be 1 if EITHER CF or ZF is set

	nested_vmptrld(cpu_id, vm_id);

	if (is_launch) {
		asm volatile(R"(
	// Attempt to launch the L2 guest.
	vmlaunch
	// Set AL to 1 if CF=1 (VMfailValid)
	setc %%al
	// Set BL to 1 if ZF=1 (VMfailInvalid)
	setz %%bl
	or %%bl, %%al)"
			     : "=a"(fail_flag)
			     :
			     : "rbx", "cc", "memory");
	} else {
		asm volatile(R"(
	// Attempt to resume the L2 guest.
	vmresume
	// Set AL to 1 if CF=1 (VMfailValid)
	setc %%al
	// Set BL to 1 if ZF=1 (VMfailInvalid)
	setz %%bl
	or %%bl, %%al)"
			     : "=a"(fail_flag)
			     :
			     : "rbx", "cc", "memory");
	}
	asm volatile(".globl after_vmentry_label\nafter_vmentry_label:");
	if (fail_flag) {
		// VMLAUNCH/VMRESUME failed, so VMCS is still valid and can be read.
		vmx_error_code = vmread(VMCS_VM_INSTRUCTION_ERROR);
		guest_uexit(0xE2E10000 | (uint32)vmx_error_code);
		return;
	}
	// If we get here, this means VMLAUNCH/VMRESUME truly succeeded (CF=0 and ZF=0)
	// and the L2 guest has run and exited.
}

GUEST_CODE static noinline void
guest_run_amd_vm(uint64 cpu_id, uint64 vm_id)
{
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	volatile uint8* vmcb_ptr = (volatile uint8*)vmcb_addr;
	uint8 fail_flag = 0;

	asm volatile(
	    "mov %1, %%rax\n\t" // Load VMCB physical address into RAX
	    "vmrun\n\t" // Launch or resume L2 guest
	    "setc %0\n\t"
	    : "=q"(fail_flag)
	    : "m"(vmcb_addr)
	    : "rax", "cc", "memory");

	if (fail_flag) {
		// VMRUN failed.
		guest_uexit(0xE2E10000 | 0xFFFF);
		return;
	}

	// VMRUN succeeded and we have a VM-exit.
	uint64 exit_reason = vmcb_read64(vmcb_ptr, VMCB_EXIT_CODE);
	nested_vm_exit_handler_amd(exit_reason, cpu_id, vm_id);
}

GUEST_CODE static noinline void
guest_handle_nested_vmlaunch(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		guest_handle_nested_vmentry_intel(vm_id, cpu_id, true);
	} else {
		guest_run_amd_vm(cpu_id, vm_id);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_vmresume(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		guest_handle_nested_vmentry_intel(vm_id, cpu_id, false);
	} else {
		guest_run_amd_vm(cpu_id, vm_id);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_intel_vmwrite_mask(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 vm_id = cmd->args[0];
	nested_vmptrld(cpu_id, vm_id);
	uint64 field = cmd->args[1];
	uint64 set_mask = cmd->args[2];
	uint64 unset_mask = cmd->args[3];
	uint64 flip_mask = cmd->args[4];

	uint64 current_value = vmread(field);
	uint64 new_value = (current_value & ~unset_mask) | set_mask;
	new_value ^= flip_mask;
	vmwrite(field, new_value);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_vmcb_write_mask(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	uint64 vm_id = cmd->args[0];
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 offset = cmd->args[1];
	uint64 set_mask = cmd->args[2];
	uint64 unset_mask = cmd->args[3];
	uint64 flip_mask = cmd->args[4];

	uint64 current_value = vmcb_read64((volatile uint8*)vmcb_addr, offset);
	uint64 new_value = (current_value & ~unset_mask) | set_mask;
	new_value ^= flip_mask;
	vmcb_write64(vmcb_addr, offset, new_value);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_invlpga(struct api_call_2* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;

	uint64 linear_addr = cmd->args[0];
	// ASID (Address Space ID) - only lower 16 bits matter usually, but register is 32-bit.
	uint32 asid = (uint32)cmd->args[1];

	asm volatile("invlpga" : : "a"(linear_addr), "c"(asid) : "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_stgi()
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	asm volatile("stgi" ::: "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_clgi()
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	asm volatile("clgi" ::: "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_inject_event(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;

	uint64 vm_id = cmd->args[0];
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	uint64 vector = cmd->args[1] & 0xFF;
	uint64 type = cmd->args[2] & 0x7;
	uint64 error_code = cmd->args[3] & 0xFFFFFFFF;
	uint64 flags = cmd->args[4];

	// Flags bit 0: Valid (V)
	// Flags bit 1: Error Code Valid (EV)
	uint64 event_inj = vector;
	event_inj |= (type << 8);
	if (flags & 2)
		event_inj |= (1ULL << 11); // EV bit
	if (flags & 1)
		event_inj |= (1ULL << 31); // V bit
	event_inj |= (error_code << 32);

	// Write to VMCB Offset 0x60 (EVENTINJ)
	vmcb_write64(vmcb_addr, 0x60, event_inj);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_set_intercept(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;

	uint64 vm_id = cmd->args[0];
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 offset = cmd->args[1];
	uint64 bit_mask = cmd->args[2];
	uint64 action = cmd->args[3]; // 1 = Set, 0 = Clear

	// Read 32-bit intercept field (Offsets 0x00 - 0x14 are all 32-bit vectors).
	uint32 current = vmcb_read32(vmcb_addr, (uint16)offset);

	if (action == 1)
		current |= (uint32)bit_mask;
	else
		current &= ~((uint32)bit_mask);

	vmcb_write32(vmcb_addr, (uint16)offset, current);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_vmload(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	uint64 vm_id = cmd->arg;
	uint64 vmcb_pa = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	asm volatile("vmload %%rax" ::"a"(vmcb_pa) : "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_vmsave(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	uint64 vm_id = cmd->arg;
	uint64 vmcb_pa = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	asm volatile("vmsave %%rax" ::"a"(vmcb_pa) : "memory");
}

#endif // EXECUTOR_COMMON_KVM_AMD64_SYZOS_H
