// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <windows.h>

#define doexit exit
#define NORETURN
#define SYSCALLAPI WINAPI

#include "common.h"

#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
static void install_segv_handler()
{
}

// TODO(dvyukov): implement me
#define NONFAILING(...)                          \
	__try {                                  \
		__VA_ARGS__;                     \
	} __except (EXCEPTION_EXECUTE_HANDLER) { \
	}
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT))
static uint64_t current_time_ms()
{
	return GetTickCount64();
}
#endif

#if defined(SYZ_EXECUTOR)
static void sleep_ms(uint64_t ms)
{
	Sleep(ms);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_FAULT_INJECTION)
static int inject_fault(int nth)
{
	return 0;
}

static int fault_injected(int fail_fd)
{
	return 0;
}
#endif
