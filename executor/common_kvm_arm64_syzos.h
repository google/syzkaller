// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file provides guest code running inside the ARM64 KVM.

#include "kvm.h"
#include <linux/kvm.h>

// Host will map the code in this section into the guest address space.
#define GUEST_CODE __attribute__((section("guest")))

// Start/end of the guest section.
extern char *__start_guest, *__stop_guest;

typedef enum {
	SYZOS_API_UEXIT,
	SYZOS_API_CODE,
	SYZOS_API_MSR,
	SYZOS_API_SMC,
	SYZOS_API_HVC,
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

struct api_call_2 {
	struct api_call_header header;
	uint64 args[2];
};

struct api_call_code {
	struct api_call_header header;
	uint32 insns[];
};

struct api_call_smccc {
	struct api_call_header header;
	uint32 func_id;
	uint64 params[5];
};

static void guest_uexit(uint64 exit_code);
static void guest_execute_code(uint32* insns, uint64 size);
static void guest_handle_msr(uint64 reg, uint64 val);
static void guest_handle_smc(struct api_call_smccc* cmd);
static void guest_handle_hvc(struct api_call_smccc* cmd);

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
GUEST_CODE static void guest_main(uint64 size)
{
	uint64 addr = ARM64_ADDR_USER_CODE;

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
		case SYZOS_API_MSR: {
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_msr(ccmd->args[0], ccmd->args[1]);
			break;
		}
		case SYZOS_API_SMC: {
			guest_handle_smc((struct api_call_smccc*)cmd);
			break;
		}
		case SYZOS_API_HVC: {
			guest_handle_hvc((struct api_call_smccc*)cmd);
			break;
		}
		}
		addr += cmd->size;
		size -= cmd->size;
	};
	guest_uexit((uint64)-1);
}

GUEST_CODE static void guest_execute_code(uint32* insns, uint64 size)
{
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

// Perform a userspace exit that can be handled by the host.
// The host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO,
// and can handle the call depending on the data passed as exit code.
GUEST_CODE static void guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)ARM64_ADDR_UEXIT;
	*ptr = exit_code;
}

#define MSR_REG_OPCODE 0xd5100000

// Generate an `MSR register, x0` instruction based on the register ID.
// Luckily for us, the five operands, Op0, Op1, CRn, CRm, and Op2 are laid out sequentially in
// both the register ID and the MSR instruction encoding (see
// https://developer.arm.com/documentation/ddi0602/2024-06/Base-Instructions/MSR--register---Move-general-purpose-register-to-System-register-),
// so we can just extract the lower 16 bits and put them into the opcode.
GUEST_CODE static uint32 reg_to_msr(uint64 reg)
{
	return MSR_REG_OPCODE | ((reg & 0xffff) << 5);
}

// Write value to a system register using an MSR instruction.
// The word "MSR" here has nothing to do with the x86 MSR registers.
__attribute__((noinline))
GUEST_CODE static void
guest_handle_msr(uint64 reg, uint64 val)
{
	uint32 msr = reg_to_msr(reg);
	uint32* insn = (uint32*)ARM64_ADDR_SCRATCH_CODE;
	insn[0] = msr;
	insn[1] = 0xd65f03c0; // RET
	// Put `val` into x0 and make a call to the generated MSR instruction.
	asm("mov x0, %[val]\nblr %[pc]\n"
	    :
	    : [val] "r"(val), [pc] "r"(insn)
	    : "x0", "x30", "memory");
}

// See "SMC Calling Convention", https://documentation-service.arm.com/static/5f8edaeff86e16515cdbe4c6
GUEST_CODE static void guest_handle_smc(struct api_call_smccc* cmd)
{
	asm volatile(
	    "mov x0, %[func_id]\n"
	    "mov x1, %[arg1]\n"
	    "mov x2, %[arg2]\n"
	    "mov x3, %[arg3]\n"
	    "mov x4, %[arg4]\n"
	    "mov x5, %[arg5]\n"
	    // TODO(glider): it could be interesting to pass other immediate values here, although
	    // they are ignored as per the calling convention.
	    "smc #0\n"
	    : // Ignore the outputs for now
	    : [func_id] "r"((uint32)cmd->func_id),
	      [arg1] "r"(cmd->params[0]), [arg2] "r"(cmd->params[1]),
	      [arg3] "r"(cmd->params[2]), [arg4] "r"(cmd->params[3]),
	      [arg5] "r"(cmd->params[4])
	    : "x0", "x1", "x2", "x3", "x4", "x5",
	      // These registers are not used above, but may be clobbered by the SMC call.
	      "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
	      "memory");
}

GUEST_CODE static void guest_handle_hvc(struct api_call_smccc* cmd)
{
	asm volatile(
	    "mov x0, %[func_id]\n"
	    "mov x1, %[arg1]\n"
	    "mov x2, %[arg2]\n"
	    "mov x3, %[arg3]\n"
	    "mov x4, %[arg4]\n"
	    "mov x5, %[arg5]\n"
	    // TODO(glider): nonzero immediate values are designated for use by hypervisor vendors.
	    "hvc #0\n"
	    : // Ignore the outputs for now
	    : [func_id] "r"((uint32)cmd->func_id),
	      [arg1] "r"(cmd->params[0]), [arg2] "r"(cmd->params[1]),
	      [arg3] "r"(cmd->params[2]), [arg4] "r"(cmd->params[3]),
	      [arg5] "r"(cmd->params[4])
	    : "x0", "x1", "x2", "x3", "x4", "x5",
	      // These registers are not used above, but may be clobbered by the HVC call.
	      "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
	      "memory");
}
