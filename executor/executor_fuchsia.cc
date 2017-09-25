// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_fuchsia.h"

#include "executor_posix.h"

#include "executor.h"

#include "syscalls_fuchsia.h"

char input_data[kMaxInput];
uint32_t output;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts("linux " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	install_segv_handler();
	int pos = 0;
	for (;;) {
		int rv = read(0, input_data + pos, sizeof(input_data) - pos);
		if (rv < 0)
			fail("read failed");
		if (rv == 0)
			break;
		pos += rv;
	}
	if (pos < 24)
		fail("truncated input");

	uint64_t flags = *(uint64_t*)input_data;
	flag_debug = flags & (1 << 0);
	flag_threaded = flags & (1 << 2);
	flag_collide = flags & (1 << 3);
	if (!flag_threaded)
		flag_collide = false;
	uint64_t executor_pid = *((uint64_t*)input_data + 2);
	debug("input %d, threaded=%d collide=%d pid=%llu\n",
	      pos, flag_threaded, flag_collide, executor_pid);

	execute_one(((uint64_t*)input_data) + 3);
	return 0;
}

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	debug("%s = %p\n", c->name, c->call);
	long res = c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8);
	debug("%s = %ld\n", c->name, res);
	return res;
}

void cover_open()
{
}

void cover_enable(thread_t* th)
{
}

void cover_reset(thread_t* th)
{
}

uint64_t read_cover_size(thread_t* th)
{
	return 0;
}

uint32_t* write_output(uint32_t v)
{
	return &output;
}

void write_completed(uint32_t completed)
{
}
