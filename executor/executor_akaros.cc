// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_akaros.h"

#include "executor_posix.h"

#include "executor.h"

#include "syscalls_akaros.h"

uint32_t output;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	use_temporary_dir();
	install_segv_handler();
	setup_control_pipes();
	receive_handshake();
	reply_handshake();

	for (;;) {
		receive_execute(true);
		char cwdbuf[128] = "/syz-tmpXXXXXX";
		mkdtemp(cwdbuf);
		int pid = fork();
		if (pid < 0)
			fail("fork failed");
		if (pid == 0) {
			close(kInPipeFd);
			close(kOutPipeFd);
			if (chdir(cwdbuf))
				fail("chdir failed");
			execute_one();
			doexit(0);
		}
		int status = 0;
		uint64_t start = current_time_ms();
		for (;;) {
			int res = waitpid(pid, &status, WNOHANG);
			if (res == pid)
				break;
			sleep_ms(10);
			uint64_t now = current_time_ms();
			if (now - start < 3 * 1000)
				continue;
			kill(pid, SIGKILL);
			while (waitpid(pid, &status, 0) != pid) {
			}
			break;
		}
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		remove_dir(cwdbuf);
		reply_execute(0);
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

bool kcov_comparison_t::ignore() const
{
	return false;
}
