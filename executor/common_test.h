// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdlib.h>
#include <unistd.h>

#if SYZ_EXECUTOR || __NR_syz_mmap
static long syz_mmap(long a0, long a1)
{
	return 0;
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	doexit(0);
}
#endif

#if SYZ_EXECUTOR
#define do_sandbox_setuid() 0
#define do_sandbox_namespace() 0
#endif
