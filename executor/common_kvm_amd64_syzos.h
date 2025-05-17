// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file provides guest code running inside the AMD64 KVM.

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
	SYZOS_API_CPUID,
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

static void guest_uexit(uint64 exit_code);
static void guest_execute_code(uint8* insns, uint64 size);
static void guest_cpuid(uint32 eax, uint32 ecx);

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
	uint64 addr = X86_ADDR_USER_CODE + cpu * KVM_PAGE_SIZE;

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
			guest_cpuid(ccmd->eax, ccmd->ecx);
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
	volatile uint64* ptr = (volatile uint64*)X86_ADDR_UEXIT;
	*ptr = exit_code;
}

GUEST_CODE static noinline void guest_cpuid(uint32 eax, uint32 ecx)
{
	asm volatile(
	    "cpuid\n"
	    : // Currently ignore outputs
	    : "a"(eax), "c"(ecx)
	    : "rbx", "rdx");
}
