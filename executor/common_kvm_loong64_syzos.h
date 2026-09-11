// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_LOONG64_SYZOS_H
#define EXECUTOR_COMMON_KVM_LOONG64_SYZOS_H

// Guest code running inside Loong64 KVM. First slice only implements UEXIT.

#include <linux/kvm.h>

#include "common_kvm_syzos.h"
#include "kvm.h"

// Remember these constants must match those in sys/linux/dev_kvm_loong64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_STOP, // Must be the last one
} syzos_api_id;

GUEST_CODE static void guest_uexit(uint64 exit_code);

// Main guest function that interprets the host-provided API command stream.
// Use if-statements rather than switch to avoid jump tables that need data
// relocations (see https://github.com/google/syzkaller/issues/5565).
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 size, uint64 cpu)
{
	uint64 addr = LOONG64_ADDR_USER_CODE + cpu * LOONG64_KVM_PAGE_SIZE;

	while (size >= sizeof(struct api_call_header)) {
		struct api_call_header* cmd = (struct api_call_header*)addr;
		uint64 call = cmd->call;
		uint64 cmd_size = cmd->size;
		if (call >= SYZOS_API_STOP)
			return;
		if (cmd_size < sizeof(struct api_call_header) || cmd_size > size)
			return;
		if (call == SYZOS_API_UEXIT) {
			if (cmd_size < sizeof(struct api_call_1))
				return;
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			uint64 arg = ccmd->arg;
			guest_uexit(arg);
		}
		addr += cmd_size;
		size -= cmd_size;
	}
	guest_uexit((uint64)-1);
}

// Perform a userspace exit that can be handled by the host.
// Host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO.
GUEST_CODE static noinline void guest_uexit(uint64 exit_code)
{
	volatile uint64* ptr = (volatile uint64*)LOONG64_ADDR_UEXIT;
	*ptr = exit_code;
}

#endif // EXECUTOR_COMMON_KVM_LOONG64_SYZOS_H
