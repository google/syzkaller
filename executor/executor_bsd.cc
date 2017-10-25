// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_bsd.h"

#include "executor_posix.h"

#include "executor.h"

// This file is used by both freebsd and netbsd (as a link to executor_bsd.cc).
#if defined(__FreeBSD__)
#include "syscalls_freebsd.h"
#elif defined(__NetBSD__)
#include "syscalls_netbsd.h"
#else
// This is just so that "make executor TARGETOS=freebsd" works on linux.
#include "syscalls_freebsd.h"
#define __syscall syscall
#endif

#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

const int kInFd = 3;
const int kOutFd = 4;

uint32_t* output_data;
uint32_t* output_pos;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	if (mmap(&input_data[0], kMaxInput, PROT_READ, MAP_PRIVATE | MAP_FIXED, kInFd, 0) != &input_data[0])
		fail("mmap of input file failed");
	// The output region is the only thing in executor process for which consistency matters.
	// If it is corrupted ipc package will fail to parse its contents and panic.
	// But fuzzer constantly invents new ways of how to currupt the region,
	// so we map the region at a (hopefully) hard to guess address surrounded by unmapped pages.
	void* const kOutputDataAddr = (void*)0x1ddbc20000;
	output_data = (uint32_t*)mmap(kOutputDataAddr, kMaxOutput, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0);
	if (output_data != kOutputDataAddr)
		fail("mmap of output file failed");
	// Prevent random programs to mess with these fds.
	// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
	// which will cause fuzzer to crash.
	// That's also the reason why we close kInPipeFd/kOutPipeFd below.
	close(kInFd);
	close(kOutFd);

	// Some minimal sandboxing.
	struct rlimit rlim;
#ifndef __NetBSD__
	// This causes frequent random aborts on netbsd. Reason unknown.
	rlim.rlim_cur = rlim.rlim_max = 128 << 20;
	setrlimit(RLIMIT_AS, &rlim);
#endif
	rlim.rlim_cur = rlim.rlim_max = 8 << 20;
	setrlimit(RLIMIT_MEMLOCK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlim);

	install_segv_handler();
	setup_control_pipes();
	receive_handshake();
	reply_handshake();
	cover_open();

	for (;;) {
		receive_execute(false);
		char cwdbuf[128] = "/syz-tmpXXXXXX";
		if (!mkdtemp(cwdbuf))
			fail("mkdtemp failed");
		int pid = fork();
		if (pid < 0)
			fail("fork failed");
		if (pid == 0) {
			close(kInPipeFd);
			close(kOutPipeFd);
			if (chdir(cwdbuf))
				fail("chdir failed");
			output_pos = output_data;
			execute_one();
			doexit(0);
		}
		int status = 0;
		uint64_t start = current_time_ms();
		uint64_t last_executed = start;
		uint32_t executed_calls = __atomic_load_n(output_data, __ATOMIC_RELAXED);
		for (;;) {
			int res = waitpid(pid, &status, WNOHANG);
			if (res == pid)
				break;
			sleep_ms(1);
			uint64_t now = current_time_ms();
			uint32_t now_executed = __atomic_load_n(output_data, __ATOMIC_RELAXED);
			if (executed_calls != now_executed) {
				executed_calls = now_executed;
				last_executed = now;
			}
			if ((now - start < 3 * 1000) && (now - last_executed < 500))
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
	if (c->call)
		return c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8);
	return __syscall(c->sys_nr, a0, a1, a2, a3, a4, a5, a6, a7, a8);
}

void cover_open()
{
	if (!flag_cover)
		return;
	for (int i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		th->cover_data = &th->cover_buffer[0];
	}
}

void cover_enable(thread_t* th)
{
}

void cover_reset(thread_t* th)
{
}

uint64_t read_cover_size(thread_t* th)
{
	if (!flag_cover)
		return 0;
	// Fallback coverage since we have no real coverage available.
	// We use syscall number or-ed with returned errno value as signal.
	// At least this gives us all combinations of syscall+errno.
	th->cover_data[0] = (th->call_num << 16) | ((th->res == -1 ? th->reserrno : 0) & 0x3ff);
	return 1;
}

uint32_t* write_output(uint32_t v)
{
	if (collide)
		return 0;
	if (output_pos < output_data || (char*)output_pos >= (char*)output_data + kMaxOutput)
		fail("output overflow");
	*output_pos = v;
	return output_pos++;
}

void write_completed(uint32_t completed)
{
	__atomic_store_n(output_data, completed, __ATOMIC_RELEASE);
}

bool kcov_comparison_t::ignore() const
{
	return false;
}
