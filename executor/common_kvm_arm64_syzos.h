// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file provides guest code running inside the ARM64 KVM.

#include "kvm.h"
#include <linux/kvm.h>
#include <stdbool.h>

// Host will map the code in this section into the guest address space.
#define GUEST_CODE __attribute__((section("guest")))

// Prevent function inlining. This attribute is applied to every guest_handle_* function,
// making sure they remain small so that the compiler does not attempt to be too clever
// (e.g. generate switch tables).
#define noinline __attribute__((noinline))

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
	SYZOS_API_ITS_SETUP,
	SYZOS_API_ITS_SEND_CMD,
	SYZOS_API_MRS,
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

struct api_call_its_send_cmd {
	struct api_call_header header;
	uint8 type;
	uint8 valid;
	uint32 cpuid;
	uint32 devid;
	uint32 eventid;
	uint32 intid;
	uint32 cpuid2;
};

static void guest_uexit(uint64 exit_code);
static void guest_execute_code(uint32* insns, uint64 size);
static void guest_handle_mrs(uint64 reg);
static void guest_handle_msr(uint64 reg, uint64 val);
static void guest_handle_smc(struct api_call_smccc* cmd);
static void guest_handle_hvc(struct api_call_smccc* cmd);
static void guest_handle_irq_setup(struct api_call_irq_setup* cmd);
static void guest_handle_memwrite(struct api_call_memwrite* cmd);
static void guest_handle_its_setup(struct api_call_3* cmd);
static void guest_handle_its_send_cmd(struct api_call_its_send_cmd* cmd);

typedef enum {
	UEXIT_END = (uint64)-1,
	UEXIT_IRQ = (uint64)-2,
	UEXIT_ASSERT = (uint64)-3,
} uexit_code;

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 size, uint64 cpu)
{
	uint64 addr = ARM64_ADDR_USER_CODE + cpu * 0x1000;

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
		case SYZOS_API_MRS: {
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_mrs(ccmd->arg);
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
		case SYZOS_API_ITS_SETUP: {
			guest_handle_its_setup((struct api_call_3*)cmd);
			break;
		}
		case SYZOS_API_ITS_SEND_CMD: {
			guest_handle_its_send_cmd((struct api_call_its_send_cmd*)cmd);
			break;
		}
		}
		addr += cmd->size;
		size -= cmd->size;
	};
	guest_uexit((uint64)-1);
}

GUEST_CODE static noinline void guest_execute_code(uint32* insns, uint64 size)
{
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

// Perform a userspace exit that can be handled by the host.
// The host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO,
// and can handle the call depending on the data passed as exit code.
GUEST_CODE static noinline void guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)ARM64_ADDR_UEXIT;
	*ptr = exit_code;
}

#define MSR_REG_OPCODE 0xd5100000
#define MRS_REG_OPCODE 0xd5300000

// Generate an `MSR register, x0` instruction based on the register ID.
// Luckily for us, the five operands, Op0, Op1, CRn, CRm, and Op2 are laid out sequentially in
// both the register ID and the MSR instruction encoding (see
// https://developer.arm.com/documentation/ddi0602/2024-06/Base-Instructions/MSR--register---Move-general-purpose-register-to-System-register-),
// so we can just extract the lower 16 bits and put them into the opcode.
GUEST_CODE static uint32 reg_to_msr(uint64 reg)
{
	return MSR_REG_OPCODE | ((reg & 0xffff) << 5);
}

// Generate an `MRS register, x0` instruction based on the register ID.
GUEST_CODE static uint32 reg_to_mrs(uint64 reg)
{
	return MRS_REG_OPCODE | ((reg & 0xffff) << 5);
}

// Host sets TPIDR_EL1 to contain the virtual CPU id.
GUEST_CODE static uint32 get_cpu_id()
{
	uint64 val = 0; // Suppress lint warning.
	asm volatile("mrs %0, tpidr_el1"
		     : "=r"(val));
	return (uint32)val;
}

// Some ARM chips use 128-byte cache lines. Pick 256 to be on the safe side.
#define MAX_CACHE_LINE_SIZE 256

// Read the value from a system register using an MRS instruction.
GUEST_CODE static noinline void
guest_handle_mrs(uint64 reg)
{
	uint32 mrs = reg_to_mrs(reg);
	uint32 cpu_id = get_cpu_id();
	// Make sure CPUs use different cache lines for scratch code.
	uint32* insn = (uint32*)((uint64)ARM64_ADDR_SCRATCH_CODE + cpu_id * MAX_CACHE_LINE_SIZE);
	insn[0] = mrs;
	insn[1] = 0xd65f03c0; // RET
	// Make a call to the generated MSR instruction and clobber x0.
	asm("blr %[pc]\n"
	    :
	    : [pc] "r"(insn)
	    : "x0", "x30");
}

// Write value to a system register using an MSR instruction.
// The word "MSR" here has nothing to do with the x86 MSR registers.
GUEST_CODE static noinline void
guest_handle_msr(uint64 reg, uint64 val)
{
	uint32 msr = reg_to_msr(reg);
	uint32 cpu_id = get_cpu_id();
	// Make sure CPUs use different cache lines for scratch code.
	uint32* insn = (uint32*)((uint64)ARM64_ADDR_SCRATCH_CODE + cpu_id * MAX_CACHE_LINE_SIZE);
	insn[0] = msr;
	insn[1] = 0xd65f03c0; // RET
	// Put `val` into x0 and make a call to the generated MSR instruction.
	asm("mov x0, %[val]\nblr %[pc]\n"
	    :
	    : [val] "r"(val), [pc] "r"(insn)
	    : "x0", "x30", "memory");
}

// See "SMC Calling Convention", https://documentation-service.arm.com/static/5f8edaeff86e16515cdbe4c6
GUEST_CODE static noinline void guest_handle_smc(struct api_call_smccc* cmd)
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
	    : [func_id] "r"((uint64)cmd->func_id),
	      [arg1] "r"(cmd->params[0]), [arg2] "r"(cmd->params[1]),
	      [arg3] "r"(cmd->params[2]), [arg4] "r"(cmd->params[3]),
	      [arg5] "r"(cmd->params[4])
	    : "x0", "x1", "x2", "x3", "x4", "x5",
	      // These registers are not used above, but may be clobbered by the SMC call.
	      "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
	      "memory");
}

GUEST_CODE static noinline void guest_handle_hvc(struct api_call_smccc* cmd)
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
	    : [func_id] "r"((uint64)cmd->func_id),
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
#define GICR_CTLR GICD_CTLR
#define GICR_WAKER 0x0014
#define GICR_PROPBASER 0x0070
#define GICR_PENDBASER 0x0078

#define GICR_CTLR_ENABLE_LPIS (1UL << 0)
#define GICR_CTLR_RWP (1UL << 3)

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

GUEST_CODE static __always_inline void __raw_writel(uint32 val, uint64 addr)
{
	asm volatile("str %w0, [%1]"
		     :
		     : "rZ"(val), "r"(addr));
}

GUEST_CODE static __always_inline void __raw_writeq(uint64 val, uint64 addr)
{
	asm volatile("str %x0, [%1]"
		     :
		     : "rZ"(val), "r"(addr));
}

GUEST_CODE static __always_inline uint32 __raw_readl(uint64 addr)
{
	uint32 val;
	asm volatile("ldr %w0, [%1]"
		     : "=r"(val)
		     : "r"(addr));
	return val;
}

GUEST_CODE static __always_inline uint64 __raw_readq(uint64 addr)
{
	uint64 val;
	asm volatile("ldr %x0, [%1]"
		     : "=r"(val)
		     : "r"(addr));
	return val;
}

#define dmb() asm volatile("dmb sy" \
			   :        \
			   :        \
			   : "memory")

#define writel(v, c) ({ dmb(); __raw_writel(v, c); })
#define readl(c) ({ uint32 __v = __raw_readl(c); dmb(); __v; })
#define writeq(v, c) ({ dmb(); __raw_writeq(v, c); })
#define readq(c) ({ uint64 __v = __raw_readq(c); dmb(); __v; })

// TODO(glider): may want to return extra data to the host.
#define GUEST_ASSERT(val)                          \
	do {                                       \
		if (!(val))                        \
			guest_uexit(UEXIT_ASSERT); \
	} while (0)

// Helper to implement guest_udelay().
GUEST_CODE static uint64 read_cntvct(void)
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
GUEST_CODE static void gicv3_enable_redist(uint32 cpu)
{
	uint64 redist_base_cpu = gicr_base_cpu(cpu);
	uint32 val = readl(redist_base_cpu + GICR_WAKER);

	val &= ~GICR_WAKER_ProcessorSleep;
	writel(val, ARM64_ADDR_GICR_BASE + GICR_WAKER);
	// Wait until the processor is 'active'.
	spin_while_readl(ARM64_ADDR_GICR_BASE + GICR_WAKER, GICR_WAKER_ChildrenAsleep);
}

GUEST_CODE static void gicv3_cpu_init(uint32 cpu)
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
	uint64 icc_sre_el1 = 0;
	asm volatile("mrs %0, " ICC_SRE_EL1
		     :
		     : "r"(icc_sre_el1));
	icc_sre_el1 |= ICC_SRE_EL1_SRE;
	asm volatile("msr " ICC_SRE_EL1 ", %0"
		     :
		     : "r"(icc_sre_el1));

	// Set a default priority threshold.
	uint64 value = ICC_PMR_DEF_PRIO;
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
GUEST_CODE static void gicv3_irq_enable(uint32 intid)
{
	uint32 cpu = get_cpu_id();

	writel(1 << (intid % 32), ARM64_ADDR_GICD_BASE + GICD_ISENABLER + (intid / 32) * 4);
	if ((intid >= VGICV3_MIN_SPI) && (intid <= VGICV3_MAX_SPI))
		gicd_wait_for_rwp();
	else
		gicr_wait_for_rwp(cpu);
}

GUEST_CODE static noinline void guest_handle_irq_setup(struct api_call_irq_setup* cmd)
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

GUEST_CODE static noinline void guest_handle_memwrite(struct api_call_memwrite* cmd)
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

GUEST_CODE static void guest_prepare_its(int nr_cpus, int nr_devices, int nr_events);

GUEST_CODE static noinline void guest_handle_its_setup(struct api_call_3* cmd)
{
	guest_prepare_its(cmd->args[0], cmd->args[1], cmd->args[2]);
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
	uint64 iar0, iar1, irq_num = 0;
	bool is_group0 = false;
	// Acknowledge the interrupt by reading the IAR.
	// Depending on the particular interrupt's Group (0 or 1), its number will appear in either ICC_IAR0_EL1, or ICC_IAR1_EL1.
	// The other register will contain a special interrupt number between 1020 and 1023.
	// Numbers below 1020 are SGIs, PPIs and SPIs, numbers above 1023 are reserved interrupts and LPIs.
	asm volatile("mrs %0, " ICC_IAR0_EL1
		     : "=r"(iar0));
	asm volatile("mrs %0, " ICC_IAR1_EL1
		     : "=r"(iar1));
	if ((iar0 < 1020) || (iar0 > 1023)) {
		irq_num = iar0;
		is_group0 = true;
	} else if ((iar1 < 1020) || (iar1 > 1023)) {
		irq_num = iar1;
	} else {
		return;
	}

	// Handle the interrupt by doing a uexit.
	// TODO(glider): do something more interesting here.
	guest_uexit(UEXIT_IRQ);

	// Signal End of Interrupt (EOI) by writing back to the EOIR.
	if (is_group0) {
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

// ITS setup below.
#define GITS_CTLR 0x0000
#define GITS_CBASER 0x0080
#define GITS_CWRITER 0x0088
#define GITS_CREADR 0x0090
#define GITS_BASER 0x0100

#define GITS_CTLR_ENABLE (1U << 0)

#define GIC_BASER_InnerShareable 1ULL

#define GIC_PAGE_SIZE_64K 2ULL
#define GITS_BASER_PAGE_SIZE_SHIFT (8)
#define __GITS_BASER_PSZ(sz) (GIC_PAGE_SIZE_##sz << GITS_BASER_PAGE_SIZE_SHIFT)
#define GITS_BASER_PAGE_SIZE_64K __GITS_BASER_PSZ(64K)

#define GIC_BASER_CACHE_RaWaWb 7ULL
#define GITS_BASER_INNER_CACHEABILITY_SHIFT (59)
#define GITS_BASER_RaWaWb GIC_BASER_CACHEABILITY(GITS_BASER, INNER, RaWaWb)

#define GITS_CBASER_INNER_CACHEABILITY_SHIFT (59)
#define GITS_CBASER_RaWaWb GIC_BASER_CACHEABILITY(GITS_CBASER, INNER, RaWaWb)

#define GICR_PROPBASER_SHAREABILITY_SHIFT (10)
#define GICR_PROPBASER_INNER_CACHEABILITY_SHIFT (7)
#define GICR_PROPBASER_RaWaWb GIC_BASER_CACHEABILITY(GICR_PROPBASER, INNER, RaWaWb)
#define GICR_PROPBASER_IDBITS_MASK (0x1f)

#define GIC_BASER_CACHEABILITY(reg, inner_outer, type) \
	(GIC_BASER_CACHE_##type << reg##_##inner_outer##_CACHEABILITY_SHIFT)

#define GITS_BASER_SHAREABILITY_SHIFT (10)
#define GITS_CBASER_SHAREABILITY_SHIFT (10)
#define GIC_BASER_SHAREABILITY(reg, type) \
	(GIC_BASER_##type << reg##_SHAREABILITY_SHIFT)
#define GITS_BASER_InnerShareable \
	GIC_BASER_SHAREABILITY(GITS_BASER, InnerShareable)

#define GITS_CBASER_InnerShareable \
	GIC_BASER_SHAREABILITY(GITS_CBASER, InnerShareable)

#define GICR_PROPBASER_InnerShareable \
	GIC_BASER_SHAREABILITY(GICR_PROPBASER, InnerShareable)

#define GICR_PENDBASER_InnerShareable \
	GIC_BASER_SHAREABILITY(GICR_PENDBASER, InnerShareable)

#define GICR_PENDBASER_SHAREABILITY_SHIFT (10)
#define GICR_PENDBASER_INNER_CACHEABILITY_SHIFT (7)
#define GICR_PENDBASER_RaWaWb GIC_BASER_CACHEABILITY(GICR_PENDBASER, INNER, RaWaWb)

#define GITS_BASER_TYPE_NONE 0
#define GITS_BASER_TYPE_DEVICE 1
#define GITS_BASER_TYPE_VCPU 2
#define GITS_BASER_TYPE_RESERVED3 3
#define GITS_BASER_TYPE_COLLECTION 4
#define GITS_BASER_TYPE_RESERVED5 5
#define GITS_BASER_TYPE_RESERVED6 6
#define GITS_BASER_TYPE_RESERVED7 7

#define GITS_BASER_TYPE_SHIFT (56)
#define GITS_BASER_TYPE(r) (((r) >> GITS_BASER_TYPE_SHIFT) & 7)

#define GITS_BASER_NR_REGS 8
#define GITS_BASER_VALID (1ULL << 63)

#define GITS_CBASER_VALID (1ULL << 63)

GUEST_CODE static uint64 its_read_u64(unsigned long offset)
{
	return readq(ARM64_ADDR_GITS_BASE + offset);
}

GUEST_CODE static void its_write_u64(unsigned long offset, uint64 val)
{
	writeq(val, ARM64_ADDR_GITS_BASE + offset);
}

GUEST_CODE static uint32 its_read_u32(unsigned long offset)
{
	return readl(ARM64_ADDR_GITS_BASE + offset);
}

GUEST_CODE static void its_write_u32(unsigned long offset, uint32 val)
{
	writel(val, ARM64_ADDR_GITS_BASE + offset);
}

struct its_cmd_block {
	// Kernel defines this struct as a union, but we don't need raw_cmd_le for now.
	uint64 raw_cmd[4];
};

// Guest memcpy implementation is using volatile accesses to prevent the compiler from optimizing it
// into a memcpy() call.
GUEST_CODE static noinline void guest_memcpy(void* dst, void* src, size_t size)
{
	volatile char* pdst = (char*)dst;
	volatile char* psrc = (char*)src;
	for (size_t i = 0; i < size; i++)
		pdst[i] = psrc[i];
}

// Send an ITS command by copying it to the command queue at the offset defined by GITS_CWRITER.
// https://developer.arm.com/documentation/100336/0106/operation/interrupt-translation-service--its-/its-commands-and-errors.
GUEST_CODE static noinline void its_send_cmd(uint64 cmdq_base, struct its_cmd_block* cmd)
{
	uint64 cwriter = its_read_u64(GITS_CWRITER);
	struct its_cmd_block* dst = (struct its_cmd_block*)(cmdq_base + cwriter);
	uint64 cbaser = its_read_u64(GITS_CBASER);
	size_t cmdq_size = ((cbaser & 0xFF) + 1) * SZ_4K;
	guest_memcpy(dst, cmd, sizeof(*cmd));
	dmb();
	uint64 next = (cwriter + sizeof(*cmd)) % cmdq_size;
	its_write_u64(GITS_CWRITER, next);
	// KVM synchronously processes the command after writing to GITS_CWRITER.
	// Hardware ITS implementation would've required polling here.
}

GUEST_CODE static unsigned long its_find_baser(unsigned int type)
{
	for (int i = 0; i < GITS_BASER_NR_REGS; i++) {
		uint64 baser;
		unsigned long offset = GITS_BASER + (i * sizeof(baser));

		baser = its_read_u64(offset);
		if (GITS_BASER_TYPE(baser) == type)
			return offset;
	}

	GUEST_ASSERT(0);
	return -1;
}

GUEST_CODE static void its_install_table(unsigned int type, uint64 base, size_t size)
{
	unsigned long offset = its_find_baser(type);
	uint64 baser = ((size / SZ_64K) - 1) |
		       GITS_BASER_PAGE_SIZE_64K |
		       GITS_BASER_InnerShareable |
		       base |
		       GITS_BASER_RaWaWb |
		       GITS_BASER_VALID;

	its_write_u64(offset, baser);
}

GUEST_CODE static void its_install_cmdq(uint64 base, size_t size)
{
	uint64 cbaser = ((size / SZ_4K) - 1) |
			GITS_CBASER_InnerShareable |
			base |
			GITS_CBASER_RaWaWb |
			GITS_CBASER_VALID;

	its_write_u64(GITS_CBASER, cbaser);
}

GUEST_CODE static void its_init(uint64 coll_tbl,
				uint64 device_tbl, uint64 cmdq)
{
	its_install_table(GITS_BASER_TYPE_COLLECTION, coll_tbl, SZ_64K);
	its_install_table(GITS_BASER_TYPE_DEVICE, device_tbl, SZ_64K);
	its_install_cmdq(cmdq, SZ_64K);

	uint32 ctlr = its_read_u32(GITS_CTLR);
	ctlr |= GITS_CTLR_ENABLE;
	its_write_u32(GITS_CTLR, ctlr);
}

#define GIC_LPI_OFFSET 8192

#define GITS_CMD_MAPD 0x08
#define GITS_CMD_MAPC 0x09
#define GITS_CMD_MAPTI 0x0a
#define GITS_CMD_MAPI 0x0b
#define GITS_CMD_MOVI 0x01
#define GITS_CMD_DISCARD 0x0f
#define GITS_CMD_INV 0x0c
#define GITS_CMD_MOVALL 0x0e
#define GITS_CMD_INVALL 0x0d
#define GITS_CMD_INT 0x03
#define GITS_CMD_CLEAR 0x04
#define GITS_CMD_SYNC 0x05

#define GENMASK_ULL(h, l)                   \
	(((~0ULL) - (1ULL << (l)) + 1ULL) & \
	 (~0ULL >> (63 - (h))))

// Avoid inlining this function, because it may cause emitting constants into .rodata.
GUEST_CODE static noinline void
its_mask_encode(uint64* raw_cmd, uint64 val, int h, int l)
{
	uint64 mask = GENMASK_ULL(h, l);
	*raw_cmd &= ~mask;
	*raw_cmd |= (val << l) & mask;
}

GUEST_CODE static void its_encode_cmd(struct its_cmd_block* cmd, uint8 cmd_nr)
{
	its_mask_encode(&cmd->raw_cmd[0], cmd_nr, 7, 0);
}

GUEST_CODE static void its_encode_devid(struct its_cmd_block* cmd, uint32 devid)
{
	its_mask_encode(&cmd->raw_cmd[0], devid, 63, 32);
}

GUEST_CODE static void its_encode_event_id(struct its_cmd_block* cmd, uint32 id)
{
	its_mask_encode(&cmd->raw_cmd[1], id, 31, 0);
}

GUEST_CODE static void its_encode_phys_id(struct its_cmd_block* cmd, uint32 phys_id)
{
	its_mask_encode(&cmd->raw_cmd[1], phys_id, 63, 32);
}

GUEST_CODE static void its_encode_size(struct its_cmd_block* cmd, uint8 size)
{
	its_mask_encode(&cmd->raw_cmd[1], size, 4, 0);
}

GUEST_CODE static void its_encode_itt(struct its_cmd_block* cmd, uint64 itt_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], itt_addr >> 8, 51, 8);
}

GUEST_CODE static void its_encode_valid(struct its_cmd_block* cmd, int valid)
{
	its_mask_encode(&cmd->raw_cmd[2], !!valid, 63, 63);
}

GUEST_CODE static void its_encode_target(struct its_cmd_block* cmd, uint64 target_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], target_addr >> 16, 51, 16);
}

// RDbase2 encoded in the fourth double word of the command.
GUEST_CODE static void its_encode_target2(struct its_cmd_block* cmd, uint64 target_addr)
{
	its_mask_encode(&cmd->raw_cmd[3], target_addr >> 16, 51, 16);
}

GUEST_CODE static void its_encode_collection(struct its_cmd_block* cmd, uint16 col)
{
	its_mask_encode(&cmd->raw_cmd[2], col, 15, 0);
}

GUEST_CODE static noinline void guest_memzero(void* ptr, size_t size)
{
	volatile char* p = (char*)ptr;
	for (size_t i = 0; i < size; i++)
		p[i] = 0;
}

GUEST_CODE static void its_send_mapd_cmd(uint64 cmdq_base, uint32 device_id, uint64 itt_base,
					 size_t num_idbits, bool valid)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, GITS_CMD_MAPD);
	its_encode_devid(&cmd, device_id);
	its_encode_size(&cmd, num_idbits - 1);
	its_encode_itt(&cmd, itt_base);
	its_encode_valid(&cmd, valid);

	its_send_cmd(cmdq_base, &cmd);
}

GUEST_CODE static void its_send_mapc_cmd(uint64 cmdq_base, uint32 vcpu_id, uint32 collection_id, bool valid)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, GITS_CMD_MAPC);
	its_encode_collection(&cmd, collection_id);
	its_encode_target(&cmd, vcpu_id);
	its_encode_valid(&cmd, valid);

	its_send_cmd(cmdq_base, &cmd);
}

GUEST_CODE static void its_send_mapti_cmd(uint64 cmdq_base, uint32 device_id,
					  uint32 event_id, uint32 collection_id,
					  uint32 intid)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, GITS_CMD_MAPTI);
	its_encode_devid(&cmd, device_id);
	its_encode_event_id(&cmd, event_id);
	its_encode_phys_id(&cmd, intid);
	its_encode_collection(&cmd, collection_id);
	its_send_cmd(cmdq_base, &cmd);
}

GUEST_CODE static void its_send_devid_eventid_icid_cmd(uint64 cmdq_base, uint8 cmd_nr, uint32 device_id,
						       uint32 event_id, uint32 intid)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, cmd_nr);
	its_encode_devid(&cmd, device_id);
	its_encode_event_id(&cmd, event_id);
	its_encode_phys_id(&cmd, intid);
	its_send_cmd(cmdq_base, &cmd);
}

GUEST_CODE static void its_send_devid_eventid_cmd(uint64 cmdq_base, uint8 cmd_nr, uint32 device_id,
						  uint32 event_id)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, cmd_nr);
	its_encode_devid(&cmd, device_id);
	its_encode_event_id(&cmd, event_id);
	its_send_cmd(cmdq_base, &cmd);
}

GUEST_CODE static void its_send_movall_cmd(uint64 cmdq_base, uint32 vcpu_id, uint32 vcpu_id2)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, GITS_CMD_MOVALL);
	its_encode_target(&cmd, vcpu_id);
	its_encode_target2(&cmd, vcpu_id2);

	its_send_cmd(cmdq_base, &cmd);
}

GUEST_CODE static void its_send_invall_cmd(uint64 cmdq_base, uint32 collection_id)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, GITS_CMD_INVALL);
	its_encode_collection(&cmd, collection_id);
	its_send_cmd(cmdq_base, &cmd);
}

// We assume that the number of supported IDbits for the proproperties table is 16, so the size of the
// table itself is 64K.
// TODO(glider): it may be interesting to use a different size here.
#define SYZOS_NUM_IDBITS 16

GUEST_CODE static void its_send_sync_cmd(uint64 cmdq_base, uint32 vcpu_id)
{
	struct its_cmd_block cmd;
	guest_memzero(&cmd, sizeof(cmd));
	its_encode_cmd(&cmd, GITS_CMD_SYNC);
	its_encode_target(&cmd, vcpu_id);
	its_send_cmd(cmdq_base, &cmd);
}

// This function is carefully written in a way that prevents jump table emission.
// SyzOS cannot reference global constants, and compilers are very eager to generate a jump table
// for a switch over GITS commands.
// To work around that, we replace the switch statement with a series of if statements.
// In addition, cmd->type is stored in a volatile variable, so that it is read on each if statement,
// preventing the compiler from folding them together.
GUEST_CODE static noinline void guest_handle_its_send_cmd(struct api_call_its_send_cmd* cmd)
{
	volatile uint8 type = cmd->type;
	if (type == GITS_CMD_MAPD) {
		uint64 itt_base = ARM64_ADDR_ITS_ITT_TABLES + cmd->devid * SZ_64K;
		its_send_mapd_cmd(ARM64_ADDR_ITS_CMDQ_BASE, cmd->devid, itt_base,
				  SYZOS_NUM_IDBITS, cmd->valid);
		return;
	}
	if (type == GITS_CMD_MAPC) {
		its_send_mapc_cmd(ARM64_ADDR_ITS_CMDQ_BASE, cmd->cpuid, cmd->cpuid,
				  cmd->valid);
		return;
	}
	if (type == GITS_CMD_MAPTI) {
		its_send_mapti_cmd(ARM64_ADDR_ITS_CMDQ_BASE, cmd->devid, cmd->eventid,
				   cmd->cpuid, cmd->intid);
		return;
	}
	if (type == GITS_CMD_MAPI || type == GITS_CMD_MOVI) {
		its_send_devid_eventid_icid_cmd(ARM64_ADDR_ITS_CMDQ_BASE, type,
						cmd->devid, cmd->eventid, cmd->intid);
		return;
	}
	if (type == GITS_CMD_MOVALL) {
		its_send_movall_cmd(ARM64_ADDR_ITS_CMDQ_BASE, cmd->cpuid, cmd->cpuid2);
		return;
	}
	if (type == GITS_CMD_INVALL) {
		its_send_invall_cmd(ARM64_ADDR_ITS_CMDQ_BASE, cmd->cpuid);
		return;
	}
	if (type == GITS_CMD_INT || type == GITS_CMD_INV || type == GITS_CMD_DISCARD || type == GITS_CMD_CLEAR) {
		its_send_devid_eventid_cmd(ARM64_ADDR_ITS_CMDQ_BASE, type, cmd->devid,
					   cmd->eventid);
		return;
	}
	if (type == GITS_CMD_SYNC) {
		its_send_sync_cmd(ARM64_ADDR_ITS_CMDQ_BASE, cmd->cpuid);
		return;
	}
}

GUEST_CODE static noinline void guest_setup_its_mappings(uint64 cmdq_base,
							 uint64 itt_tables,
							 uint32 nr_events,
							 uint32 nr_devices,
							 uint32 nr_cpus)
{
	if ((nr_events < 1) || (nr_devices < 1) || (nr_cpus < 1))
		return;

	// Event IDs start from 0 and map to LPI IDs starting from GIC_LPI_OFFSET.
	uint32 coll_id, device_id, event_id, intid = GIC_LPI_OFFSET;
	for (coll_id = 0; coll_id < nr_cpus; coll_id++) {
		// If GITS_TYPER.PTA == 0, RDbase is just the CPU id.
		its_send_mapc_cmd(cmdq_base, coll_id, coll_id, true);
	}
	// Round-robin the LPIs to all of the vCPUs in the VM.
	coll_id = 0;
	for (device_id = 0; device_id < nr_devices; device_id++) {
		uint64 itt_base = itt_tables + (device_id * SZ_64K);
		its_send_mapd_cmd(cmdq_base, device_id, itt_base, SYZOS_NUM_IDBITS, true);
		for (event_id = 0; event_id < nr_events; event_id++) {
			its_send_mapti_cmd(cmdq_base, device_id, event_id, coll_id, intid++);
			coll_id = (coll_id + 1) % nr_cpus;
		}
	}
}

GUEST_CODE static void guest_invalidate_all_rdists(uint64 cmdq_base, int nr_cpus)
{
	for (int i = 0; i < nr_cpus; i++)
		its_send_invall_cmd(cmdq_base, i);
}

// Set up GIRC_PROPBASER and GICR_PENDBASER.
void gic_rdist_enable_lpis(uint64 cfg_table, size_t cfg_table_size,
			   uint64 pend_table)
{
	uint64 rdist_base = gicr_base_cpu(get_cpu_id());
	uint64 val = (cfg_table |
		      GICR_PROPBASER_InnerShareable |
		      GICR_PROPBASER_RaWaWb |
		      ((SYZOS_NUM_IDBITS - 1) & GICR_PROPBASER_IDBITS_MASK));

	writeq(val, rdist_base + GICR_PROPBASER);

	val = (pend_table |
	       GICR_PENDBASER_InnerShareable |
	       GICR_PENDBASER_RaWaWb);
	writeq(val, rdist_base + GICR_PENDBASER);

	uint64 ctlr = readl(rdist_base + GICR_CTLR);
	ctlr |= GICR_CTLR_ENABLE_LPIS;
	writel(ctlr, rdist_base + GICR_CTLR);
}

#define LPI_PROP_DEFAULT_PRIO 0xa0
#define LPI_PROP_GROUP1 (1 << 1)
#define LPI_PROP_ENABLED (1 << 0)

// TODO(glider) non-volatile access is compiled into:
// 0000000000452154 <configure_lpis.constprop.0>:
//   452154:       4f05e460        movi    v0.16b, #0xa3
//   452158:       3d800000        str     q0, [x0]
//   45215c:       d65f03c0        ret
// , which for some reason hangs.
GUEST_CODE static noinline void configure_lpis(uint64 prop_table, int nr_devices, int nr_events)
{
	int nr_lpis = nr_devices * nr_events;
	volatile uint8* tbl = (uint8*)prop_table;
	for (int i = 0; i < nr_lpis; i++) {
		tbl[i] = LPI_PROP_DEFAULT_PRIO |
			 LPI_PROP_GROUP1 |
			 LPI_PROP_ENABLED;
	}
}

GUEST_CODE static void guest_prepare_its(int nr_cpus, int nr_devices, int nr_events)
{
	configure_lpis(ARM64_ADDR_ITS_PROP_TABLE, nr_devices, nr_events);
	gic_rdist_enable_lpis(ARM64_ADDR_ITS_PROP_TABLE, SZ_64K, ARM64_ADDR_ITS_PEND_TABLES);
	its_init(ARM64_ADDR_ITS_COLL_TABLE, ARM64_ADDR_ITS_DEVICE_TABLE, ARM64_ADDR_ITS_CMDQ_BASE);
	guest_setup_its_mappings(ARM64_ADDR_ITS_CMDQ_BASE, ARM64_ADDR_ITS_ITT_TABLES, nr_events, nr_devices, nr_cpus);
	guest_invalidate_all_rdists(ARM64_ADDR_ITS_CMDQ_BASE, nr_cpus);
}
