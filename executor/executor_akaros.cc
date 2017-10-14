// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_akaros.h"

#include "executor_posix.h"

#include "executor.h"

#include "syscalls_akaros.h"

char input_buffer[kMaxInput];
uint32_t output;

struct in_header {
	uint64_t magic;
	uint64_t flags;
	uint64_t pid;
	uint64_t progSize;
	uint64_t execFlags;
	uint64_t prog[0];
};

struct out_header {
	uint64_t magic;
	uint64_t status;
};

const uint64_t kInMagic = 0xbadc0ffee;
const uint64_t kOutMagic = 0xbadf00d;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts("akaros " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	use_temporary_dir();
	install_segv_handler();
	for (;;) {
		size_t pos = 0;
		in_header* hdr = (in_header*)input_buffer;
		for (;;) {
			int rv = read(0, input_buffer + pos, sizeof(input_buffer) - pos);
			if (rv < 0)
				fail("read failed");
			if (rv == 0)
				fail("stdin closed, read %d", (int)pos);
			pos += rv;
			if (pos > sizeof(in_header)) {
				if (hdr->magic != kInMagic)
					fail("bad header magic 0x%llx", hdr->magic);
				if (pos > sizeof(in_header) + hdr->progSize)
					fail("excessive input data");
				if (pos == sizeof(in_header) + hdr->progSize)
					break;
			}
		}
		flag_debug = hdr->flags & (1 << 0);
		flag_threaded = hdr->flags & (1 << 2);
		flag_collide = hdr->flags & (1 << 3);
		if (!flag_threaded)
			flag_collide = false;
		debug("input %d, threaded=%d collide=%d pid=%llu\n",
		      pos, flag_threaded, flag_collide, hdr->pid);
		char cwdbuf[128] = "/syz-tmpXXXXXX";
		mkdtemp(cwdbuf);
		int pid = fork();
		if (pid < 0)
			fail("fork failed");
		if (pid == 0) {
			close(0);
			dup2(2, 1);
			if (chdir(cwdbuf))
				fail("chdir failed");
			execute_one(hdr->prog);
			doexit(0);
		}
		int status = 0;
		while (waitpid(pid, &status, 0) != pid) {
		}
		remove_dir(cwdbuf);
		out_header out;
		out.magic = kOutMagic;
		out.status = 0;
		if (write(1, &out, sizeof(out)) != sizeof(out))
			fail("stdout write failed");
	}
	return 0;
}

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	return syscall(c->sys_nr, a0, a1, a2, a3, a4, a5, a6, a7, a8);
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
