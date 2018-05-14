// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
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

#define KCOV_INIT_TRACE32 _IOR('c', 1, uint32)
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

const unsigned long KCOV_TRACE_PC = 0;
const unsigned long KCOV_TRACE_CMP = 1;

const int kInFd = 3;
const int kOutFd = 4;

uint32* output_data;
uint32* output_pos;

static bool detect_kernel_bitness();

int main(int argc, char** argv)
{
	is_kernel_64_bit = detect_kernel_bitness();
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
	// so we map the region at a (hopefully) hard to guess address with random offset,
	// surrounded by unmapped pages.
	// The address chosen must also work on 32-bit kernels with 1GB user address space.
	void* preferred = (void*)(0x1b2bc20000ull + (1 << 20) * (getpid() % 128));
	output_data = (uint32*)mmap(preferred, kMaxOutput,
				    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0);
	if (output_data != preferred)
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
	setup_control_pipes();
	receive_handshake();

	cover_open();
	install_segv_handler();
	use_temporary_dir();

	int pid = -1;
	switch (flag_sandbox) {
	case sandbox_none:
		pid = do_sandbox_none();
		break;
	case sandbox_setuid:
		pid = do_sandbox_setuid();
		break;
	case sandbox_namespace:
		pid = do_sandbox_namespace();
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
	// Other statuses happen when fuzzer processes manages to kill loop.
	if (status != kFailStatus && status != kErrorStatus)
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

static __thread thread_t* current_thread;

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
		const int kcov_init_trace = is_kernel_64_bit ? KCOV_INIT_TRACE64 : KCOV_INIT_TRACE32;
		if (ioctl(th->cover_fd, kcov_init_trace, kCoverSize))
			fail("cover init trace write failed");
		size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
		th->cover_data = (char*)mmap(NULL, mmap_alloc_size,
					     PROT_READ | PROT_WRITE, MAP_SHARED, th->cover_fd, 0);
		th->cover_end = th->cover_data + mmap_alloc_size;
		if (th->cover_data == MAP_FAILED)
			fail("cover mmap failed");
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
	current_thread = th;
}

void cover_reset(thread_t* th)
{
	if (!flag_cover)
		return;
	if (th == 0)
		th = current_thread;
	*(uint64*)th->cover_data = 0;
}

uint32 read_cover_size(thread_t* th)
{
	if (!flag_cover)
		return 0;
	// Note: this assumes little-endian kernel.
	uint32 n = *(uint32*)th->cover_data;
	debug("#%d: read cover size = %u\n", th->id, n);
	if (n >= kCoverSize)
		fail("#%d: too much cover %u", th->id, n);
	return n;
}

bool cover_check(uint32 pc)
{
	return true;
}

bool cover_check(uint64 pc)
{
#if defined(__i386__) || defined(__x86_64__)
	// Text/modules range for x86_64.
	return pc >= 0xffffffff80000000ull && pc < 0xffffffffff000000ull;
#else
	return true;
#endif
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
	// Comparisons with 0 are not interesting, fuzzer should be able to guess 0's without help.
	if (arg1 == 0 && (arg2 == 0 || (type & KCOV_CMP_CONST)))
		return true;
	if ((type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8) {
		// This can be a pointer (assuming 64-bit kernel).
		// First of all, we want avert fuzzer from our output region.
		// Without this fuzzer manages to discover and corrupt it.
		uint64 out_start = (uint64)output_data;
		uint64 out_end = out_start + kMaxOutput;
		if (arg1 >= out_start && arg1 <= out_end)
			return true;
		if (arg2 >= out_start && arg2 <= out_end)
			return true;
#if defined(__i386__) || defined(__x86_64__)
		// Filter out kernel physical memory addresses.
		// These are internal kernel comparisons and should not be interesting.
		// The range covers first 1TB of physical mapping.
		uint64 kmem_start = (uint64)0xffff880000000000ull;
		uint64 kmem_end = (uint64)0xffff890000000000ull;
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

static bool detect_kernel_bitness()
{
	if (sizeof(void*) == 8)
		return true;
	// It turns out to be surprisingly hard to understand if the kernel underneath is 64-bits.
	// A common method is to look at uname.machine. But it is produced in some involved ways,
	// and we will need to know about all strings it returns and in the end it can be overriden
	// during build and lie (and there are known precedents of this).
	// So instead we look at size of addresses in /proc/kallsyms.
	bool wide = true;
	int fd = open("/proc/kallsyms", O_RDONLY);
	if (fd != -1) {
		char buf[16];
		if (read(fd, buf, sizeof(buf)) == sizeof(buf) &&
		    (buf[8] == ' ' || buf[8] == '\t'))
			wide = false;
		close(fd);
	}
	debug("detected %d-bit kernel\n", wide ? 64 : 32);
	return wide;
}
