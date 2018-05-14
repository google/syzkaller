// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_fuchsia.h"

#include "executor_posix.h"

#include "executor.h"

#include "syscalls_fuchsia.h"

uint32 output;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	if (syz_mmap(SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE) != ZX_OK)
		fail("mmap of data segment failed");

	install_segv_handler();
	setup_control_pipes();
	receive_execute(true);
	execute_one();
	return 0;
}

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	long res = ZX_ERR_INVALID_ARGS;
	NONFAILING(res = c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8));
	errno = res;
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

uint32 read_cover_size(thread_t* th)
{
	return 0;
}

bool cover_check(uint32 pc)
{
	return true;
}

bool cover_check(uint64 pc)
{
	return true;
}

uint32* write_output(uint32 v)
{
	return &output;
}

void write_completed(uint32 completed)
{
}

bool kcov_comparison_t::ignore() const
{
	return false;
}
