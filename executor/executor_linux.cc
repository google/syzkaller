// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYZ_EXECUTOR
#include "common_linux.h"

#include "executor_linux.h"

#include "executor.h"

#include "syscalls_linux.h"

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long long)
#define KCOV_INIT_CMP _IOR('c', 2, unsigned long long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

const unsigned long KCOV_TRACE_PC = 0;
const unsigned long KCOV_TRACE_CMP = 1;

const int kInFd = 3;
const int kOutFd = 4;

void* const kOutputDataAddr = (void*)0x1bdbc20000ull;

uint32_t* output_data;
uint32_t* output_pos;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (mmap(&input_data[0], kMaxInput, PROT_READ, MAP_PRIVATE | MAP_FIXED, kInFd, 0) != &input_data[0])
		fail("mmap of input file failed");
	// The output region is the only thing in executor process for which consistency matters.
	// If it is corrupted ipc package will fail to parse its contents and panic.
	// But fuzzer constantly invents new ways of how to currupt the region,
	// so we map the region at a (hopefully) hard to guess address surrounded by unmapped pages.
	output_data = (uint32_t*)mmap(kOutputDataAddr, kMaxOutput, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0);
	if (output_data != kOutputDataAddr)
		fail("mmap of output file failed");
	// Prevent random programs to mess with these fds.
	// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
	// which will cause fuzzer to crash.
	// That's also the reason why we close kInPipeFd/kOutPipeFd below.
	close(kInFd);
	close(kOutFd);
	setup_control_pipes();
	receive_handshake();

	cover_open();
	install_segv_handler();
	use_temporary_dir();

#if defined(__i386__) || defined(__arm__)
	// mmap syscall on i386/arm is translated to old_mmap and has different signature.
	// As a workaround fix it up to mmap2, which has signature that we expect.
	// pkg/csource has the same hack.
	for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
		if (syscalls[i].sys_nr == __NR_mmap)
			syscalls[i].sys_nr = __NR_mmap2;
	}
#endif

	int pid = -1;
	switch (flag_sandbox) {
	case sandbox_none:
		pid = do_sandbox_none(flag_pid, flag_enable_tun);
		break;
	case sandbox_setuid:
		pid = do_sandbox_setuid(flag_pid, flag_enable_tun);
		break;
	case sandbox_namespace:
		pid = do_sandbox_namespace(flag_pid, flag_enable_tun);
		break;
	default:
		fail("unknown sandbox type");
	}
	if (pid < 0)
		fail("clone failed");
	debug("spawned loop pid %d\n", pid);
	int status = 0;
	while (waitpid(-1, &status, __WALL) != pid) {
	}
	status = WEXITSTATUS(status);
	if (status == 0)
		status = kRetryStatus;
	// If an external sandbox process wraps executor, the out pipe will be closed
	// before the sandbox process exits this will make ipc package kill the sandbox.
	// As the result sandbox process will exit with exit status 9 instead of the executor
	// exit status (notably kRetryStatus). Consequently, ipc will treat it as hard
	// failure rather than a temporal failure. So we duplicate the exit status on the pipe.
	reply_execute(status);
	errno = 0;
	if (status == kFailStatus)
		fail("loop failed");
	if (status == kErrorStatus)
		error("loop errored");
	// Loop can be killed by a test process with e.g.:
	// ptrace(PTRACE_SEIZE, 1, 0, 0x100040)
	// This is unfortunate, but I don't have a better solution than ignoring it for now.
	exitf("loop exited with status %d", status);
	// Unreachable.
	return 1;
}

void loop()
{
	// Tell parent that we are ready to serve.
	reply_handshake();

	for (int iter = 0;; iter++) {
		// Create a new private work dir for this test (removed at the end of the loop).
		char cwdbuf[256];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");

		// TODO: consider moving the read into the child.
		// Potentially it can speed up things a bit -- when the read finishes
		// we already have a forked worker process.
		receive_execute(false);
		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
			setpgrp();
			if (chdir(cwdbuf))
				fail("failed to chdir");
			close(kInPipeFd);
			close(kOutPipeFd);
			if (flag_enable_tun) {
				// Read all remaining packets from tun to better
				// isolate consequently executing programs.
				flush_tun();
			}
			output_pos = output_data;
			execute_one();
			debug("worker exiting\n");
			doexit(0);
		}
		debug("spawned worker pid %d\n", pid);

		// We used to use sigtimedwait(SIGCHLD) to wait for the subprocess.
		// But SIGCHLD is also delivered when a process stops/continues,
		// so it would require a loop with status analysis and timeout recalculation.
		// SIGCHLD should also unblock the usleep below, so the spin loop
		// should be as efficient as sigtimedwait.
		int status = 0;
		uint64_t start = current_time_ms();
		uint64_t last_executed = start;
		uint32_t executed_calls = __atomic_load_n(output_data, __ATOMIC_RELAXED);
		for (;;) {
			int res = waitpid(-1, &status, __WALL | WNOHANG);
			int errno0 = errno;
			if (res == pid) {
				debug("waitpid(%d)=%d (%d)\n", pid, res, errno0);
				break;
			}
			usleep(1000);
			// Even though the test process executes exit at the end
			// and execution time of each syscall is bounded by 20ms,
			// this backup watchdog is necessary and its performance is important.
			// The problem is that exit in the test processes can fail (sic).
			// One observed scenario is that the test processes prohibits
			// exit_group syscall using seccomp. Another observed scenario
			// is that the test processes setups a userfaultfd for itself,
			// then the main thread hangs when it wants to page in a page.
			// Below we check if the test process still executes syscalls
			// and kill it after 200ms of inactivity.
			uint64_t now = current_time_ms();
			uint32_t now_executed = __atomic_load_n(output_data, __ATOMIC_RELAXED);
			if (executed_calls != now_executed) {
				executed_calls = now_executed;
				last_executed = now;
			}
			if ((now - start < 3 * 1000) && (now - last_executed < 500))
				continue;
			debug("waitpid(%d)=%d (%d)\n", pid, res, errno0);
			debug("killing\n");
			kill(-pid, SIGKILL);
			kill(pid, SIGKILL);
			for (;;) {
				int res = waitpid(-1, &status, __WALL);
				debug("waitpid(%d)=%d (%d)\n", pid, res, errno);
				if (res == pid)
					break;
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
}

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	if (c->call)
		return c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8);
	return syscall(c->sys_nr, a0, a1, a2, a3, a4, a5);
}

void cover_open()
{
	if (!flag_cover)
		return;
	for (int i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		th->cover_fd = open("/sys/kernel/debug/kcov", O_RDWR);
		if (th->cover_fd == -1)
			fail("open of /sys/kernel/debug/kcov failed");
		if (ioctl(th->cover_fd, KCOV_INIT_TRACE, kCoverSize))
			fail("cover init trace write failed");
		size_t mmap_alloc_size = kCoverSize * sizeof(th->cover_data[0]);
		uint64_t* mmap_ptr = (uint64_t*)mmap(NULL, mmap_alloc_size,
						     PROT_READ | PROT_WRITE, MAP_SHARED, th->cover_fd, 0);
		if (mmap_ptr == MAP_FAILED)
			fail("cover mmap failed");
		th->cover_size_ptr = mmap_ptr;
		th->cover_data = &mmap_ptr[1];
	}
}

void cover_enable(thread_t* th)
{
	if (!flag_cover)
		return;
	debug("#%d: enabling /sys/kernel/debug/kcov\n", th->id);
	int kcov_mode = flag_collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
	// This should be fatal,
	// but in practice ioctl fails with assorted errors (9, 14, 25),
	// so we use exitf.
	if (ioctl(th->cover_fd, KCOV_ENABLE, kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
	debug("#%d: enabled /sys/kernel/debug/kcov\n", th->id);
}

void cover_reset(thread_t* th)
{
	if (!flag_cover)
		return;
	__atomic_store_n(th->cover_size_ptr, 0, __ATOMIC_RELAXED);
}

uint64_t read_cover_size(thread_t* th)
{
	if (!flag_cover)
		return 0;
	uint64_t n = __atomic_load_n(th->cover_size_ptr, __ATOMIC_RELAXED);
	debug("#%d: read cover size = %u\n", th->id, n);
	if (n >= kCoverSize)
		fail("#%d: too much cover %u", th->id, n);
	return n;
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
	// Comparisons with 0 are not interesting, fuzzer should be able to guess 0's without help.
	if (arg1 == 0 && (arg2 == 0 || (type & KCOV_CMP_CONST)))
		return true;
	if ((type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8) {
		// This can be a pointer (assuming 64-bit kernel).
		// First of all, we want avert fuzzer from our output region.
		// Without this fuzzer manages to discover and corrupt it.
		uint64_t out_start = (uint64_t)kOutputDataAddr;
		uint64_t out_end = out_start + kMaxOutput;
		if (arg1 >= out_start && arg1 <= out_end)
			return true;
		if (arg2 >= out_start && arg2 <= out_end)
			return true;
#if defined(__i386__) || defined(__x86_64__)
		// Filter out kernel physical memory addresses.
		// These are internal kernel comparisons and should not be interesting.
		// The range covers first 1TB of physical mapping.
		uint64_t kmem_start = (uint64_t)0xffff880000000000ull;
		uint64_t kmem_end = (uint64_t)0xffff890000000000ull;
		bool kptr1 = arg1 >= kmem_start && arg1 <= kmem_end;
		bool kptr2 = arg2 >= kmem_start && arg2 <= kmem_end;
		if (kptr1 && kptr2)
			return true;
		if (kptr1 && arg2 == 0)
			return true;
		if (kptr2 && arg1 == 0)
			return true;
#endif
	}
	return false;
}
