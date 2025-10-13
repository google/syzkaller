// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file provides guest code running inside the AMD64 KVM.

#include "common_kvm_syzos.h"
#include "kvm.h"
#include <linux/kvm.h>
#include <stdbool.h>

// Compilers will eagerly try to transform the switch statement in guest_main()
// into a jump table, unless the cases are sparse enough.
// We use prime numbers multiplied by 10 to prevent this behavior.
// Remember these constants must match those in sys/linux/dev_kvm_amd64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_CODE = 10,
	SYZOS_API_CPUID = 20,
	SYZOS_API_WRMSR = 30,
	SYZOS_API_RDMSR = 50,
	SYZOS_API_WR_CRN = 70,
	SYZOS_API_WR_DRN = 110,
	SYZOS_API_IN_DX = 130,
	SYZOS_API_OUT_DX = 170,
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

static void guest_uexit(uint64 exit_code);
static void guest_execute_code(uint8* insns, uint64 size);
static void guest_handle_cpuid(uint32 eax, uint32 ecx);
static void guest_handle_wrmsr(uint64 reg, uint64 val);
static void guest_handle_rdmsr(uint64 reg);
static void guest_handle_wr_crn(struct api_call_2* cmd);
static void guest_handle_wr_drn(struct api_call_2* cmd);
static void guest_handle_in_dx(struct api_call_2* cmd);
static void guest_handle_out_dx(struct api_call_3* cmd);

typedef enum {
	UEXIT_END = (uint64)-1,
	UEXIT_IRQ = (uint64)-2,
	UEXIT_ASSERT = (uint64)-3,
} uexit_code;

__attribute__((naked))
GUEST_CODE static void
dummy_null_handler()
{
	asm("iretq");
}

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
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
		switch (cmd->call) {
		case SYZOS_API_UEXIT: {
			struct api_call_uexit* ucmd = (struct api_call_uexit*)cmd;
			guest_uexit(ucmd->exit_code);
			break;
		}
		case SYZOS_API_CODE: {
			struct api_call_code* ccmd = (struct api_call_code*)cmd;
			guest_execute_code(ccmd->insns, cmd->size - sizeof(struct api_call_header));
			break;
		}
		case SYZOS_API_CPUID: {
			struct api_call_cpuid* ccmd = (struct api_call_cpuid*)cmd;
			guest_handle_cpuid(ccmd->eax, ccmd->ecx);
			break;
		}
		case SYZOS_API_WRMSR: {
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_wrmsr(ccmd->args[0], ccmd->args[1]);
			break;
		}
		case SYZOS_API_RDMSR: {
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_rdmsr(ccmd->arg);
			break;
		}
		case SYZOS_API_WR_CRN: {
			guest_handle_wr_crn((struct api_call_2*)cmd);
			break;
		}
		case SYZOS_API_WR_DRN: {
			guest_handle_wr_drn((struct api_call_2*)cmd);
			break;
		}
		case SYZOS_API_IN_DX: {
			guest_handle_in_dx((struct api_call_2*)cmd);
			break;
		}
		case SYZOS_API_OUT_DX: {
			guest_handle_out_dx((struct api_call_3*)cmd);
			break;
		}
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
GUEST_CODE static noinline void guest_uexit(uint64 exit_code)
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
