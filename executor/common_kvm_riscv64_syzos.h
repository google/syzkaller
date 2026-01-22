// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_RISCV64_SYZOS_H
#define EXECUTOR_COMMON_KVM_RISCV64_SYZOS_H

// This file provides guest code running inside the RISCV64 KVM.

#include <linux/kvm.h>

#include "common_kvm_syzos.h"
#include "kvm.h"

// Remember these constants must match those in sys/linux/dev_kvm_riscv64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_CODE = 10,
	SYZOS_API_CSRR = 100,
	SYZOS_API_CSRW = 101,
	SYZOS_API_STOP, // Must be the last one
} syzos_api_id;

struct api_call_header {
	uint64 call;
	uint64 size;
};

struct api_call_code {
	struct api_call_header header;
	uint32 insns[];
};

struct api_call_1 {
	struct api_call_header header;
	uint64 arg;
};

struct api_call_2 {
	struct api_call_header header;
	uint64 args[2];
};

GUEST_CODE static void guest_uexit(uint64 exit_code);
GUEST_CODE static void guest_execute_code(uint32* insns, uint64 size);
GUEST_CODE static void guest_handle_csrr(uint32 csr);
GUEST_CODE static void guest_handle_csrw(uint32 csr, uint64 val);

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
// The inner loop uses a complex if-statement, because Clang is eager to insert a jump table into
// a switch statement.
// We add single-line comments to justify having the compound statements below.
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 size, uint64 cpu)
{
	uint64 addr = RISCV64_ADDR_USER_CODE + cpu * 0x1000;

	while (size >= sizeof(struct api_call_header)) {
		struct api_call_header* cmd = (struct api_call_header*)addr;
		if (cmd->call >= SYZOS_API_STOP)
			return;
		if (cmd->size > size)
			return;
		volatile uint64 call = cmd->call;
		if (call == SYZOS_API_UEXIT) {
			// Issue a user exit.
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_uexit(ccmd->arg);
		} else if (call == SYZOS_API_CODE) {
			// Execute an instruction blob.
			struct api_call_code* ccmd = (struct api_call_code*)cmd;
			guest_execute_code(ccmd->insns, cmd->size - sizeof(struct api_call_header));
		} else if (call == SYZOS_API_CSRR) {
			// Execute a csrr instruction.
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_csrr(ccmd->arg);
		} else if (call == SYZOS_API_CSRW) {
			// Execute a csrw instruction.
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_csrw(ccmd->args[0], ccmd->args[1]);
		}
		addr += cmd->size;
		size -= cmd->size;
	};
	guest_uexit((uint64)-1);
}

// Perform a userspace exit that can be handled by the host.
// The host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO,
// and can handle the call depending on the data passed as exit code.
GUEST_CODE static noinline void guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)RISCV64_ADDR_UEXIT;
	*ptr = exit_code;
}

GUEST_CODE static noinline void guest_execute_code(uint32* insns, uint64 size)
{
	asm volatile("fence.i" ::
			 : "memory");
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

// Host sets CORE_TP to contain the virtual CPU id.
GUEST_CODE static uint32 get_cpu_id()
{
	uint64 val = 0;
	asm volatile("mv %0, tp"
		     : "=r"(val));
	return (uint32)val;
}

#define MAX_CACHE_LINE_SIZE 256
#define RISCV_OPCODE_SYSTEM 0x73
#define FUNCT3_CSRRW 0x1
#define FUNCT3_CSRRS 0x2
#define REG_ZERO 0
#define REG_A0 10
#define ENCODE_CSR_INSN(csr, rs1, funct3, rd) \
	(((csr) << 20) | ((rs1) << 15) | ((funct3) << 12) | ((rd) << 7) | RISCV_OPCODE_SYSTEM)

GUEST_CODE static noinline void
guest_handle_csrr(uint32 csr)
{
	uint32 cpu_id = get_cpu_id();
	// Make sure CPUs use different cache lines for scratch code.
	uint32* insn = (uint32*)((uint64)RISCV64_ADDR_SCRATCH_CODE + cpu_id * MAX_CACHE_LINE_SIZE);
	// insn[0] - csrr a0, csr
	// insn[1] - ret
	insn[0] = ENCODE_CSR_INSN(csr, REG_ZERO, FUNCT3_CSRRS, REG_A0);
	insn[1] = 0x00008067;
	asm volatile("fence.i" ::
			 : "memory");
	asm volatile(
	    "jalr ra, 0(%0)"
	    :
	    : "r"(insn)
	    : "ra", "a0", "memory");
}

GUEST_CODE static noinline void
guest_handle_csrw(uint32 csr, uint64 val)
{
	uint32 cpu_id = get_cpu_id();
	// Make sure CPUs use different cache lines for scratch code.
	uint32* insn = (uint32*)((uint64)RISCV64_ADDR_SCRATCH_CODE + cpu_id * MAX_CACHE_LINE_SIZE);
	// insn[0] - csrw csr, a0
	// insn[1] - ret
	insn[0] = ENCODE_CSR_INSN(csr, REG_A0, FUNCT3_CSRRW, REG_ZERO);
	insn[1] = 0x00008067;
	asm volatile("fence.i" ::
			 : "memory");
	asm volatile(
	    "mv a0, %0\n"
	    "jalr ra, 0(%1)"
	    :
	    : "r"(val), "r"(insn)
	    : "a0", "ra", "memory");
}

// The exception vector table setup and SBI invocation here follow the
// implementation in Linux kselftest KVM RISC-V tests.
// See https://elixir.bootlin.com/linux/v6.19-rc5/source/tools/testing/selftests/kvm/lib/riscv/processor.c#L337 .
#define KVM_RISCV_SBI_EXT 0x08FFFFFF
#define KVM_RISCV_SBI_UNEXP 1

struct sbiret {
	long error;
	long value;
};

GUEST_CODE static inline struct sbiret
sbi_ecall(unsigned long arg0, unsigned long arg1,
	  unsigned long arg2, unsigned long arg3,
	  unsigned long arg4, unsigned long arg5,
	  int fid, int ext)
{
	struct sbiret ret;

	register unsigned long a0 asm("a0") = arg0;
	register unsigned long a1 asm("a1") = arg1;
	register unsigned long a2 asm("a2") = arg2;
	register unsigned long a3 asm("a3") = arg3;
	register unsigned long a4 asm("a4") = arg4;
	register unsigned long a5 asm("a5") = arg5;
	register unsigned long a6 asm("a6") = fid;
	register unsigned long a7 asm("a7") = ext;
	asm volatile("ecall"
		     : "+r"(a0), "+r"(a1)
		     : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
		     : "memory");
	ret.error = a0;
	ret.value = a1;

	return ret;
}

GUEST_CODE __attribute__((used)) __attribute((__aligned__(16))) static void
guest_unexp_trap(void)
{
	sbi_ecall(0, 0, 0, 0, 0, 0,
		  KVM_RISCV_SBI_UNEXP,
		  KVM_RISCV_SBI_EXT);
}

#endif // EXECUTOR_COMMON_KVM_RISCV64_SYZOS_H