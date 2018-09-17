// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <unistd.h>

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

#if SYZ_EXECUTOR
#define do_sandbox_setuid() 0
#define do_sandbox_namespace() 0
#define do_sandbox_android_untrusted_app() 0
#endif

#if GOOS_openbsd

#define __syscall syscall

#if SYZ_EXECUTOR || __NR_syz_open_pts

#if defined(__OpenBSD__)
#include <termios.h>
#include <util.h>
#else
// Needed when compiling on Linux.
#include <pty.h>
#endif

static uintptr_t syz_open_pts(void)
{
	int master, slave;

	if (openpty(&master, &slave, NULL, NULL, NULL) == -1)
		return -1;
	// Move the master fd up in order to reduce the chances of the fuzzer
	// generating a call to close(2) with the same fd.
	if (dup2(master, master + 100) != -1)
		close(master);
	return slave;
}

#endif

#endif
