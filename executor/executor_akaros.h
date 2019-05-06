// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "nocover.h"

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	program_name = argv[0];
	if (argc == 2 && strcmp(argv[1], "child") == 0) {
		if (mmap(data, data_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
			fail("mmap of data segment failed");
		child();
	}
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	return syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}
