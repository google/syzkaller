// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_bsd.h"

#include "executor_posix.h"

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

#include "executor.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#if defined(__FreeBSD__)
#define KIOENABLE _IOW('c', 2, int) // Enable coverage recording
#define KIODISABLE _IO('c', 3) // Disable coverage recording
#define KIOSETBUFSIZE _IOW('c', 4, unsigned int) // Set the buffer size

#define KCOV_MODE_NONE -1
#define KCOV_MODE_TRACE_PC 0
#define KCOV_MODE_TRACE_CMP 1
#endif

const int kInFd = 3;
const int kOutFd = 4;

uint32* output_data;
uint32* output_pos;

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
	output_data = (uint32*)mmap(kOutputDataAddr, kMaxOutput, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0);
	if (output_data != kOutputDataAddr)
		fail("mmap of output file failed");
	if (mmap((void*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE, PROT_READ | PROT_WRITE,
		 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != (void*)SYZ_DATA_OFFSET)
		fail("mmap of data segment failed");
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

	const int nfiles = 1 << 8;
	if (kInPipeFd >= nfiles)
		fail("RLIMIT_NOFILE too low: %d > %d", kInPipeFd, nfiles);
	rlim.rlim_cur = rlim.rlim_max = nfiles;
	setrlimit(RLIMIT_NOFILE, &rlim);

	install_segv_handler();
	main_init();
	reply_handshake();

	for (;;) {
		receive_execute();
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
		uint64 start = current_time_ms();
		uint64 last_executed = start;
		uint32 executed_calls = __atomic_load_n(output_data, __ATOMIC_RELAXED);
		for (;;) {
			int res = waitpid(pid, &status, WNOHANG);
			if (res == pid)
				break;
			sleep_ms(1);
			uint64 now = current_time_ms();
			uint32 now_executed = __atomic_load_n(output_data, __ATOMIC_RELAXED);
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

long execute_syscall(const call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	if (c->call)
		return c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8);
	return __syscall(c->sys_nr, a0, a1, a2, a3, a4, a5, a6, a7, a8);
}

void cover_open()
{
#if defined(__FreeBSD__)
	for (int i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		th->cover_fd = open("/dev/kcov", O_RDWR);
		if (th->cover_fd == -1)
			fail("open of /dev/kcov failed");
		if (ioctl(th->cover_fd, KIOSETBUFSIZE, &kCoverSize))
			fail("ioctl init trace write failed");
		size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
		char* mmap_ptr = (char*)mmap(NULL, mmap_alloc_size,
					     PROT_READ | PROT_WRITE,
					     MAP_SHARED, th->cover_fd, 0);
		if (mmap_ptr == NULL)
			fail("cover mmap failed");
		th->cover_data = mmap_ptr;
		th->cover_end = mmap_ptr + mmap_alloc_size;
		th->cover_size_ptr = (uint64*)mmap_ptr;
	}
#endif
}

void cover_enable(thread_t* th)
{
#if defined(__FreeBSD__)
	debug("#%d: enabling /dev/kcov\n", th->id);
	int kcov_mode = flag_collect_comps ? KCOV_MODE_TRACE_CMP : KCOV_MODE_TRACE_PC;
	if (ioctl(th->cover_fd, KIOENABLE, &kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
	debug("#%d: enabled /dev/kcov\n", th->id);
#endif
}

void cover_reset(thread_t* th)
{
#if defined(__FreeBSD__)
	*th->cover_size_ptr = 0;
#endif
}

uint32 cover_read_size(thread_t* th)
{
#if defined(__FreeBSD__)
	uint64 size = *th->cover_size_ptr;
	debug("#%d: read cover size = %llu\n", th->id, size);
	if (size > kCoverSize)
		fail("#%d: too much cover %llu", th->id, size);
	return size;
#else
	return 0;
#endif
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
	if (collide)
		return 0;
	if (output_pos < output_data || (char*)output_pos >= (char*)output_data + kMaxOutput)
		fail("output overflow");
	*output_pos = v;
	return output_pos++;
}

void write_completed(uint32 completed)
{
	__atomic_store_n(output_data, completed, __ATOMIC_RELEASE);
}

bool kcov_comparison_t::ignore() const
{
	return false;
}
