// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file provides guest code running inside the ARM64 KVM.

#include "kvm.h"

// Host will map the code in this section into the guest address space.
#define GUEST_CODE __attribute__((section("guest")))

// Start/end of the guest section.
extern char *__start_guest, *__stop_guest;

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
GUEST_CODE static void guest_main()
{
	void (*guest_payload)() = (void (*)())ARM64_ADDR_USER_CODE;
	guest_payload();
}
