// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zircon/syscalls.h>

#include "nocover.h"

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	if (syz_mmap((size_t)data, data_size) != ZX_OK)
		fail("mmap of data segment failed");
}

static long execute_syscall(const call_t* c, long a[kMaxArgs])
{
	long res = c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	if (strncmp(c->name, "zx_", 3) == 0) {
		// Convert zircon error convention to the libc convention that executor expects.
		if (res == ZX_OK ||
		    !strcmp(c->name, "zx_log_read") ||
		    !strcmp(c->name, "zx_clock_get") ||
		    !strcmp(c->name, "zx_ticks_get"))
			return 0;
		errno = (-res) & 0x7f;
		return -1;
	}
	// We cast libc functions to signature returning long,
	// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
	if (res == 0xffffffff)
		res = (long)-1;
	return res;
}
