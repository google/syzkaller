// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zircon/status.h>
#include <zircon/syscalls.h>

#include "nocover.h"

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	zx_status_t status = syz_mmap((size_t)data, data_size);
	if (status != ZX_OK)
		fail("mmap of data segment failed: %s (%d)", zx_status_get_string(status), status);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	intptr_t res = c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	if (strncmp(c->name, "zx_", 3) == 0) {
		// Convert zircon error convention to the libc convention that executor expects.
		// The following calls return arbitrary integers instead of error codes.
		if (res == ZX_OK ||
		    !strcmp(c->name, "zx_debuglog_read") ||
		    !strcmp(c->name, "zx_clock_get") ||
		    !strcmp(c->name, "zx_clock_get_monotonic") ||
		    !strcmp(c->name, "zx_deadline_after") ||
		    !strcmp(c->name, "zx_ticks_get"))
			return 0;
		errno = (-res) & 0x7f;
		return -1;
	}
	// We cast libc functions to signature returning intptr_t,
	// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
	if (res == 0xffffffff)
		res = (intptr_t)-1;
	return res;
}
