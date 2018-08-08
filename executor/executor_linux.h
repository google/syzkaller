// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KCOV_INIT_TRACE32 _IOR('c', 1, uint32)
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

const unsigned long KCOV_TRACE_PC = 0;
const unsigned long KCOV_TRACE_CMP = 1;

static bool detect_kernel_bitness();

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	is_kernel_64_bit = detect_kernel_bitness();
	if (mmap(data, data_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
		fail("mmap of data segment failed");
}

static __thread cover_t* current_cover;

static long execute_syscall(const call_t* c, long a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	return syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void cover_open(cover_t* cov)
{
	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1)
		fail("open of /sys/kernel/debug/kcov failed");
	if (dup2(fd, cov->fd) < 0)
		fail("filed to dup2(%d, %d) cover fd", fd, cov->fd);
	close(fd);
	const int kcov_init_trace = is_kernel_64_bit ? KCOV_INIT_TRACE64 : KCOV_INIT_TRACE32;
	if (ioctl(cov->fd, kcov_init_trace, kCoverSize))
		fail("cover init trace write failed");
	size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
	cov->data = (char*)mmap(NULL, mmap_alloc_size,
				PROT_READ | PROT_WRITE, MAP_SHARED, cov->fd, 0);
	if (cov->data == MAP_FAILED)
		fail("cover mmap failed");
	cov->data_end = cov->data + mmap_alloc_size;
}

static void cover_enable(cover_t* cov, bool collect_comps)
{
	int kcov_mode = collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
	// This should be fatal,
	// but in practice ioctl fails with assorted errors (9, 14, 25),
	// so we use exitf.
	if (ioctl(cov->fd, KCOV_ENABLE, kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
	current_cover = cov;
}

static void cover_reset(cover_t* cov)
{
	if (cov == 0)
		cov = current_cover;
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	// Note: this assumes little-endian kernel.
	cov->size = *(uint32*)cov->data;
}

static bool cover_check(uint32 pc)
{
	return true;
}

static bool cover_check(uint64 pc)
{
#if defined(__i386__) || defined(__x86_64__)
	// Text/modules range for x86_64.
	return pc >= 0xffffffff80000000ull && pc < 0xffffffffff000000ull;
#else
	return true;
#endif
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

// One does not simply exit.
// _exit can in fact fail.
// syzkaller did manage to generate a seccomp filter that prohibits exit_group syscall.
// Previously, we get into infinite recursion via segv_handler in such case
// and corrupted output_data, which does matter in our case since it is shared
// with fuzzer process. Loop infinitely instead. Parent will kill us.
// But one does not simply loop either. Compilers are sure that _exit never returns,
// so they remove all code after _exit as dead. Call _exit via volatile indirection.
// And this does not work as well. _exit has own handling of failing exit_group
// in the form of HLT instruction, it will divert control flow from our loop.
// So call the syscall directly.
NORETURN void doexit(int status)
{
	volatile unsigned i;
	syscall(__NR_exit_group, status);
	for (i = 0;; i++) {
	}
}
