// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__FreeBSD__) && !defined(__NetBSD__)
// This is just so that "make executor TARGETOS=freebsd/netbsd" works on linux.
#define __syscall syscall
#endif

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	if (mmap(data, data_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
		fail("mmap of data segment failed");

	// Some minimal sandboxing.
	// TODO: this should go into common_bsd.h because csource needs this too.
	struct rlimit rlim;
#if GOOS_netbsd
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
	rlim.rlim_cur = rlim.rlim_max = 256; // see kMaxFd
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static long execute_syscall(const call_t* c, long a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	return __syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

#if GOOS_freebsd
#define KIOENABLE _IOW('c', 2, int) // Enable coverage recording
#define KIODISABLE _IO('c', 3) // Disable coverage recording
#define KIOSETBUFSIZE _IOW('c', 4, unsigned int) // Set the buffer size

#define KCOV_MODE_NONE -1
#define KCOV_MODE_TRACE_PC 0
#define KCOV_MODE_TRACE_CMP 1

static void cover_open(cover_t* cov)
{
	int fd = open("/dev/kcov", O_RDWR);
	if (fd == -1)
		fail("open of /dev/kcov failed");
	if (dup2(fd, cov->fd) < 0)
		fail("filed to dup2(%d, %d) cover fd", fd, cov->fd);
	close(fd);
	if (ioctl(cov->fd, KIOSETBUFSIZE, &kCoverSize))
		fail("ioctl init trace write failed");
	size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
	char* mmap_ptr = (char*)mmap(NULL, mmap_alloc_size,
				     PROT_READ | PROT_WRITE,
				     MAP_SHARED, cov->fd, 0);
	if (mmap_ptr == NULL)
		fail("cover mmap failed");
	cov->data = mmap_ptr;
	cov->data_end = mmap_ptr + mmap_alloc_size;
}

static void cover_enable(cover_t* cov, bool collect_comps)
{
	int kcov_mode = flag_collect_comps ? KCOV_MODE_TRACE_CMP : KCOV_MODE_TRACE_PC;
	if (ioctl(cov->fd, KIOENABLE, &kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
}

static void cover_reset(cover_t* cov)
{
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	cov->size = *(uint64*)cov->data;
}

static bool cover_check(uint32 pc)
{
	return true;
}

static bool cover_check(uint64 pc)
{
	return true;
}
#else
#include "nocover.h"
#endif
