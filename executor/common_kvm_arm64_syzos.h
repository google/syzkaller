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
	SYZOS_API_IRQ_SETUP,
	SYZOS_API_MEMWRITE,
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

struct api_call_irq_setup {
	struct api_call_header header;
	uint32 nr_cpus;
	uint32 nr_spis;
};

struct api_call_memwrite {
	struct api_call_header header;
	uint64 base_addr;
	uint64 offset;
	uint64 value;
	uint64 len;
};

static void guest_uexit(uint64 exit_code);
static void guest_execute_code(uint32* insns, uint64 size);
static void guest_handle_msr(uint64 reg, uint64 val);
static void guest_handle_smc(struct api_call_smccc* cmd);
static void guest_handle_hvc(struct api_call_smccc* cmd);
static void guest_handle_irq_setup(struct api_call_irq_setup* cmd);
static void guest_handle_memwrite(struct api_call_memwrite* cmd);

typedef enum {
	UEXIT_END = (uint64)-1,
	UEXIT_IRQ = (uint64)-2,
	UEXIT_ASSERT = (uint64)-3,
} uexit_code;

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
		case SYZOS_API_IRQ_SETUP: {
			guest_handle_irq_setup((struct api_call_irq_setup*)cmd);
			break;
		}
		case SYZOS_API_MEMWRITE: {
			guest_handle_memwrite((struct api_call_memwrite*)cmd);
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

// VGICv3 setup and IRQ handling code below.
// This code is based on the "Arm Generic Interrupt Controller (GIC) Architecture Specification.
// GIC architecture version 3 and version 4" doc (https://developer.arm.com/documentation/ihi0069/latest/)
// and KVM selftests in the Linux kernel.

// GICv3 Distributor registers.
#define GICD_CTLR 0x0000
#define GICD_IGROUPR 0x0080
#define GICD_ISENABLER 0x0100
#define GICD_ICENABLER 0x0180
#define GICD_ICACTIVER 0x0380
#define GICD_IPRIORITYR 0x0400

#define GICD_INT_DEF_PRI_X4 0xa0a0a0a0
#define GICD_CTLR_ARE_NS (1U << 4)
#define GICD_CTLR_ENABLE_G1A (1U << 1)
#define GICD_CTLR_ENABLE_G1 (1U << 0)

#define GICD_CTLR_RWP (1U << 31)

// GICv3 Redistributor registers.
#define GICR_CTLR_RWP (1UL << 3)
#define GICR_CTLR GICD_CTLR
#define GICR_WAKER 0x0014
#define GICR_IGROUPR0 GICD_IGROUPR
#define GICR_ICENABLER0 GICD_ICENABLER
#define GICR_ICACTIVER0 GICD_ICACTIVER
#define GICR_IPRIORITYR0 GICD_IPRIORITYR

#define ICC_SRE_EL1_SRE (1U << 0)
#define ICC_PMR_DEF_PRIO 0xff
#define ICC_IGRPEN1_EL1_ENABLE (1U << 0)

#define GICR_WAKER_ProcessorSleep (1U << 1)
#define GICR_WAKER_ChildrenAsleep (1U << 2)

// When building with tools/syz-old-env, GCC doesn't recognize the names of ICC registers.
// Replace them with generic S3_* names until we get a newer toolchain.
#define ICC_SRE_EL1 "S3_0_C12_C12_5"
#define ICC_PMR_EL1 "S3_0_C4_C6_0"
#define ICC_IGRPEN1_EL1 "S3_0_C12_C12_7"
#define ICC_IAR0_EL1 "S3_0_C12_C8_0"
#define ICC_IAR1_EL1 "S3_0_C12_C12_0"
#define ICC_EOIR0_EL1 "S3_0_C12_C8_1"
#define ICC_EOIR1_EL1 "S3_0_C12_C12_1"
#define ICC_DIR_EL1 "S3_0_C12_C11_1"

static GUEST_CODE __always_inline void __raw_writel(uint32 val, uint64 addr)
{
	asm volatile("str %w0, [%1]"
		     :
		     : "rZ"(val), "r"(addr));
}

static GUEST_CODE __always_inline uint32 __raw_readl(uint64 addr)
{
	uint32 val;
	asm volatile("ldr %w0, [%1]"
		     : "=r"(val)
		     : "r"(addr));
	return val;
}
#define writel_relaxed(v, c) ((void)__raw_writel((uint32)cpu_to_le32(v), (c)))
#define readl_relaxed(c) ({ uint32 __r = le32_to_cpu(( __le32)__raw_readl(c)); __r; })

#define dmb() asm volatile("dmb sy" \
			   :        \
			   :        \
			   : "memory")

#define writel(v, c) ({ dmb(); __raw_writel(v, c); })
#define readl(c) ({ uint32 __v = __raw_readl(c); dmb(); __v; })

// TODO(glider): may want to return extra data to the host.
#define GUEST_ASSERT(val)                          \
	do {                                       \
		if (!(val))                        \
			guest_uexit(UEXIT_ASSERT); \
	} while (0)

// Helper to implement guest_udelay().
GUEST_CODE uint64 read_cntvct(void)
{
	uint64 val;
	asm volatile("mrs %0, cntvct_el0"
		     : "=r"(val));
	return val;
}

// Wait for roughly @us microseconds.
GUEST_CODE static void guest_udelay(uint32 us)
{
	uint64 ticks_per_second = 0;
	// Have to read the frequency every time, since we don't have static storage.
	asm volatile("mrs %0, cntfrq_el0"
		     : "=r"(ticks_per_second));

	uint64 start = read_cntvct();

	// Target counter value for the desired delay.
	uint64 target = start + (us * ticks_per_second) / 1000000;

	while (read_cntvct() < target) {
	}
}

// Spin for at most one second as long as the register value has bits from mask.
GUEST_CODE static void spin_while_readl(uint64 reg, uint32 mask)
{
	volatile unsigned int count = 100000;
	while (readl(reg) & mask) {
		GUEST_ASSERT(count--);
		guest_udelay(10);
	}
}

// Wait for the Register Write Pending bit on GICD_CTLR.
GUEST_CODE static void gicd_wait_for_rwp()
{
	spin_while_readl(ARM64_ADDR_GICD_BASE + GICD_CTLR, GICD_CTLR_RWP);
}

#define SZ_64K 0x00010000
GUEST_CODE static uint64 gicr_base_cpu(uint32 cpu)
{
	return ARM64_ADDR_GICR_BASE + cpu * SZ_64K * 2;
}

GUEST_CODE static uint64 sgi_base_cpu(uint32 cpu)
{
	return gicr_base_cpu(cpu) + SZ_64K;
}

// Wait for the Register Write Pending bit on GICR_CTLR.
GUEST_CODE static void gicr_wait_for_rwp(uint32 cpu)
{
	spin_while_readl(gicr_base_cpu(cpu) + GICR_CTLR, GICR_CTLR_RWP);
}

// Set up the distributor part.
GUEST_CODE static void gicv3_dist_init(int nr_spis)
{
	// Disable the distributor.
	writel(0, ARM64_ADDR_GICD_BASE + GICD_CTLR);
	gicd_wait_for_rwp();

	// Mark all the SPI interrupts as non-secure Group-1. Also, deactivate and disable them.
	for (int i = 32; i < nr_spis + 32; i += 32) {
		writel(~0, ARM64_ADDR_GICD_BASE + GICD_IGROUPR + i / 8);
		writel(~0, ARM64_ADDR_GICD_BASE + GICD_ICACTIVER + i / 8);
		writel(~0, ARM64_ADDR_GICD_BASE + GICD_ICENABLER + i / 8);
	}

	// Set a default priority for all the SPIs.
	for (int i = 32; i < nr_spis + 32; i += 4) {
		writel(GICD_INT_DEF_PRI_X4,
		       ARM64_ADDR_GICD_BASE + GICD_IPRIORITYR + i);
	}

	// Wait for the settings to sync-in.
	gicd_wait_for_rwp();

	// Finally, enable the distributor globally with Affinity Routing Enable, Non-Secure.
	writel(GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A | GICD_CTLR_ENABLE_G1, ARM64_ADDR_GICD_BASE + GICD_CTLR);
	gicd_wait_for_rwp();
}

// https://developer.arm.com/documentation/198123/0302/Configuring-the-Arm-GIC
GUEST_CODE void gicv3_enable_redist(uint32 cpu)
{
	uint64 redist_base_cpu = gicr_base_cpu(cpu);
	uint32 val = readl(redist_base_cpu + GICR_WAKER);

	val &= ~GICR_WAKER_ProcessorSleep;
	writel(val, ARM64_ADDR_GICR_BASE + GICR_WAKER);
	// Wait until the processor is 'active'.
	spin_while_readl(ARM64_ADDR_GICR_BASE + GICR_WAKER, GICR_WAKER_ChildrenAsleep);
}

GUEST_CODE void gicv3_cpu_init(uint32 cpu)
{
	uint64 sgi_base = sgi_base_cpu(cpu);

	// It is important that software performs these steps before configuring
	// the CPU interface, otherwise behavior can be UNPREDICTABLE.
	gicv3_enable_redist(cpu);

	// Mark all the SGI and PPI interrupts as non-secure Group-1. Also, deactivate and disable them.
	writel(~0, sgi_base + GICR_IGROUPR0);
	writel(~0, sgi_base + GICR_ICACTIVER0);
	writel(~0, sgi_base + GICR_ICENABLER0);

	// Set a default priority for all the SGIs and PPIs.
	for (int i = 0; i < 32; i += 4) {
		writel(GICD_INT_DEF_PRI_X4,
		       sgi_base + GICR_IPRIORITYR0 + i);
	}

	gicr_wait_for_rwp(cpu);

	// Enable the GIC system register (ICC_*) access.
	uint32 icc_sre_el1 = 0;
	asm volatile("mrs %0, " ICC_SRE_EL1
		     :
		     : "r"(icc_sre_el1));
	icc_sre_el1 |= ICC_SRE_EL1_SRE;
	asm volatile("msr " ICC_SRE_EL1 ", %0"
		     :
		     : "r"(icc_sre_el1));

	// Set a default priority threshold.
	uint32 value = ICC_PMR_DEF_PRIO;
	asm volatile("msr " ICC_PMR_EL1 ", %0"
		     :
		     : "r"(value));

	// Enable non-secure Group-1 interrupts.
	value = ICC_IGRPEN1_EL1_ENABLE;
	asm volatile("msr " ICC_IGRPEN1_EL1 ", %0"
		     :
		     : "r"(value));
}

// GICv3 reserves interrupts 32-1019 for SPI.
#define VGICV3_MIN_SPI 32
#define VGICV3_MAX_SPI 1019

// https://developer.arm.com/documentation/ihi0048/b/Programmers--Model/Distributor-register-descriptions/Interrupt-Set-Enable-Registers--GICD-ISENABLERn
GUEST_CODE void gicv3_irq_enable(uint32 intid)
{
	// TODO(glider): support multiple CPUs. E.g. KVM selftests store CPU ID in TPIDR_EL1.
	uint32 cpu = 0;

	writel(1 << (intid % 32), ARM64_ADDR_GICD_BASE + GICD_ISENABLER + (intid / 32) * 4);
	if ((intid >= VGICV3_MIN_SPI) && (intid <= VGICV3_MAX_SPI))
		gicd_wait_for_rwp();
	else
		gicr_wait_for_rwp(cpu);
}

GUEST_CODE static void guest_handle_irq_setup(struct api_call_irq_setup* cmd)
{
	int nr_spis = cmd->nr_spis;
	if ((nr_spis > VGICV3_MAX_SPI - VGICV3_MIN_SPI) || (nr_spis < 0))
		nr_spis = 32;
	int nr_cpus = cmd->nr_cpus;

	gicv3_dist_init(nr_spis);
	for (int i = 0; i < nr_cpus; i++)
		gicv3_cpu_init(i);
	for (int i = 0; i < nr_spis; i++)
		gicv3_irq_enable(VGICV3_MIN_SPI + i);
	// Set up the vector table.
	asm(R"(
		adr x1, guest_vector_table
		msr vbar_el1, x1
		msr daifclr, #0b1111
	)"
	    :
	    :
	    : "x1");
}

GUEST_CODE static void guest_handle_memwrite(struct api_call_memwrite* cmd)
{
	uint64 dest = cmd->base_addr + cmd->offset;
	switch (cmd->len) {
	case 1: {
		volatile uint8* p = (uint8*)dest;
		*p = (uint8)cmd->value;
		break;
	}

	case 2: {
		volatile uint16* p = (uint16*)dest;
		*p = (uint16)cmd->value;
		break;
	}
	case 4: {
		volatile uint32* p = (uint32*)dest;
		*p = (uint32)cmd->value;
		break;
	}
	case 8:
	default: {
		volatile uint64* p = (uint64*)dest;
		*p = (uint64)cmd->value;
		break;
	}
	}
}

// Registers saved by one_irq_handler() and received by guest_irq_handler().
struct ex_regs {
	uint64 regs[31];
	uint64 sp;
	uint64 pc;
	uint64 pstate;
};

// Placeholder function to declare one_irq_handler() inside the assembly blob. We cannot put it
// into a separate .S file, because syzkaller requires a standalone header for reproducers.
__attribute__((used))
GUEST_CODE static void
one_irq_handler_fn()
{
	asm volatile(
	    R"(.global one_irq_handler
	       one_irq_handler:
	       # Allocate 34 * uint64 for struct ex_regs.
	       add sp, sp, #-16 * 17
	       # Store registers x0-x29 on the stack.
	       stp x0, x1, [sp, #16 * 0]
	       stp x2, x3, [sp, #16 * 1]
	       stp x4, x5, [sp, #16 * 2]
	       stp x6, x7, [sp, #16 * 3]
	       stp x8, x9, [sp, #16 * 4]
	       stp x10, x11, [sp, #16 * 5]
	       stp x12, x13, [sp, #16 * 6]
	       stp x14, x15, [sp, #16 * 7]
	       stp x16, x17, [sp, #16 * 8]
	       stp x18, x19, [sp, #16 * 9]
	       stp x20, x21, [sp, #16 * 10]
	       stp x22, x23, [sp, #16 * 11]
	       stp x24, x25, [sp, #16 * 12]
	       stp x26, x27, [sp, #16 * 13]
	       stp x28, x29, [sp, #16 * 14]

	       add x1, sp, #16 * 17
	       # Store x30 and SP (before allocating ex_regs).
	       stp x30, x1, [sp, #16 * 15] 

	       # ELR_EL1 holds the PC to return to.
	       mrs x1, elr_el1
	       # SPSR_EL1 is the saved PSTATE.
	       mrs x2, spsr_el1
	       # Also store them to ex_regs.
	       stp x1, x2, [sp, #16 * 16]

	       # Call guest_irq_handler(ex_regs).
	       mov x0, sp
	       bl guest_irq_handler

	       # Restore ELR_EL1 and SPSR_EL1.
	       ldp x1, x2, [sp, #16 * 16]
	       msr elr_el1, x1
	       msr spsr_el1, x2

	       # Restore the GP registers x0-x30 (ignoring SP).
	       ldp x30, xzr, [sp, #16 * 15]
	       ldp x28, x29, [sp, #16 * 14]
	       ldp x26, x27, [sp, #16 * 13]
	       ldp x24, x25, [sp, #16 * 12]
	       ldp x22, x23, [sp, #16 * 11]
	       ldp x20, x21, [sp, #16 * 10]
	       ldp x18, x19, [sp, #16 * 9]
	       ldp x16, x17, [sp, #16 * 8]
	       ldp x14, x15, [sp, #16 * 7]
	       ldp x12, x13, [sp, #16 * 6]
	       ldp x10, x11, [sp, #16 * 5]
	       ldp x8, x9, [sp, #16 * 4]
	       ldp x6, x7, [sp, #16 * 3]
	       ldp x4, x5, [sp, #16 * 2]
	       ldp x2, x3, [sp, #16 * 1]
	       ldp x0, x1, [sp, #16 * 0]

	       add sp, sp, #16 * 17

	       # Use ERET to exit from an exception.
	       eret)"
	    :
	    :
	    : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
	      "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
	      "x26", "x27", "x28", "x29", "x30", "memory");
}

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((used))
GUEST_CODE static void
guest_irq_handler(struct ex_regs* regs)
{
	uint32 iar0, iar1, irq_num = 0;
	// Acknowledge the interrupt by reading the IAR.
	asm volatile("mrs %0, " ICC_IAR0_EL1
		     : "=r"(iar0));
	asm volatile("mrs %0, " ICC_IAR1_EL1
		     : "=r"(iar1));
	if (iar0 != 0x3ff) {
		irq_num = iar0 & 0x3FF;
	} else if (iar1 != 0x3ff) {
		irq_num = iar1 & 0x3FF;
	} else {
		return;
	}

	// Handle the interrupt by doing a uexit.
	// TODO(glider): do something more interesting here.
	guest_uexit(UEXIT_IRQ);

	// Signal End of Interrupt (EOI) by writing back to the EOIR.
	if (iar0 != 0x3ff) {
		asm volatile("msr " ICC_EOIR0_EL1 ", %0"
			     :
			     : "r"(irq_num));
	} else {
		asm volatile("msr " ICC_EOIR1_EL1 ", %0"
			     :
			     : "r"(irq_num));
	}
	// Deactivate the interrupt.
	asm volatile("msr " ICC_DIR_EL1 ", %0"
		     :
		     : "r"(irq_num));
}
#ifdef __cplusplus
}
#endif

// Default IRQ handler.
#define IRQ_ENTRY        \
	".balign 0x80\n" \
	"b one_irq_handler\n"

// Unused IRQ entry.
#define IRQ_ENTRY_DUMMY  \
	".balign 0x80\n" \
	"eret\n"

// clang-format off
// guest_vector_table_fn() is never used, it is just needed to declare guest_vector_table()
// inside the assembly blob.
__attribute__((used))
GUEST_CODE static void guest_vector_table_fn()
{
	// Exception vector table as explained at
	// https://developer.arm.com/documentation/100933/0100/AArch64-exception-vector-table.
	asm volatile(
	    ".global guest_vector_table\n"
	    ".balign 2048\n"
	    "guest_vector_table:\n"
		// Exception handlers for current EL with SP0.
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY

		// Exception handlers for current EL with SPx.
		IRQ_ENTRY_DUMMY
		// Only handle IRQ/vIRQ for now.
		IRQ_ENTRY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY

		// Exception handlers for lower EL using AArch64.
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY

		// Exception handlers for lower EL using AArch32.
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY
		IRQ_ENTRY_DUMMY);
}
// clang-format on
