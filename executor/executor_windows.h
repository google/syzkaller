// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <io.h>
#include <windows.h>

#include "nocover.h"

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	if (VirtualAlloc(data, data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != data)
		fail("mmap of data segment failed");
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	__try {
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
}
