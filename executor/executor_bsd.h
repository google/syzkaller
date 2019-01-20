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

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
#if GOOS_openbsd
	// W^X not allowed by default on OpenBSD.
	int prot = PROT_READ | PROT_WRITE;
#elif GOOS_netbsd
	// W^X not allowed by default on NetBSD (PaX MPROTECT).
	int prot = PROT_READ | PROT_WRITE | PROT_MPROTECT(PROT_EXEC);
#else
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
#endif

	if (mmap(data, data_size, prot, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
		fail("mmap of data segment failed");

	// Makes sure the file descriptor limit is sufficient to map control pipes.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kMaxFd;
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static long execute_syscall(const call_t* c, long a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	return __syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

#if GOOS_freebsd || GOOS_openbsd

// KCOV support was added to FreeBSD in https://svnweb.freebsd.org/changeset/base/342962

#include <sys/kcov.h>

static void cover_open(cover_t* cov, bool extra)
{
	int fd = open("/dev/kcov", O_RDWR);
	if (fd == -1)
		fail("open of /dev/kcov failed");
	if (dup2(fd, cov->fd) < 0)
		fail("failed to dup2(%d, %d) cover fd", fd, cov->fd);
	close(fd);

#if GOOS_freebsd
	if (ioctl(cov->fd, KIOSETBUFSIZE, kCoverSize))
		fail("ioctl init trace write failed");
#elif GOOS_openbsd
	unsigned long cover_size = kCoverSize;
	if (ioctl(cov->fd, KIOSETBUFSIZE, &cover_size))
		fail("ioctl init trace write failed");
#endif

#if GOOS_freebsd
	size_t mmap_alloc_size = kCoverSize * KCOV_ENTRY_SIZE;
#else
	size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
#endif
	void* mmap_ptr = mmap(NULL, mmap_alloc_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, cov->fd, 0);
	if (mmap_ptr == MAP_FAILED)
		fail("cover mmap failed");
	cov->data = (char*)mmap_ptr;
	cov->data_end = cov->data + mmap_alloc_size;
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	int kcov_mode = collect_comps ? KCOV_MODE_TRACE_CMP : KCOV_MODE_TRACE_PC;
#if GOOS_freebsd
	// FreeBSD uses an int as the third argument.
	if (ioctl(cov->fd, KIOENABLE, kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
#elif GOOS_openbsd
	// OpenBSD uses an pointer to an int as the third argument.
	if (ioctl(cov->fd, KIOENABLE, &kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
#endif
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
