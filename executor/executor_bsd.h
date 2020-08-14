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

#if GOOS_openbsd
#include <sys/sysctl.h>
#endif

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

	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED;
#if GOOS_freebsd
	// Fail closed if the chosen data offset conflicts with an existing mapping.
	flags |= MAP_EXCL;
#endif

	if (mmap(data, data_size, prot, flags, -1, 0) != data)
		fail("mmap of data segment failed");

	// Makes sure the file descriptor limit is sufficient to map control pipes.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kMaxFd;
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	return __syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

#if GOOS_freebsd || GOOS_openbsd || GOOS_netbsd

// KCOV support was added to FreeBSD in https://svnweb.freebsd.org/changeset/base/342962
// KCOV support added to NetBSD in https://github.com/NetBSD/src/commit/080a26f01d79ded8a2154c128950d1d663c6ca88

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
	size_t mmap_alloc_size = kCoverSize * KCOV_ENTRY_SIZE;
#elif GOOS_openbsd
	unsigned long cover_size = kCoverSize;
	if (ioctl(cov->fd, KIOSETBUFSIZE, &cover_size))
		fail("ioctl init trace write failed");
	if (extra) {
		struct kio_remote_attach args;
		args.subsystem = KCOV_REMOTE_COMMON;
		args.id = 0;
		if (ioctl(cov->fd, KIOREMOTEATTACH, &args))
			fail("ioctl remote attach failed");
	}
	size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
#elif GOOS_netbsd
	uint64_t cover_size;
	if (extra) {
		// USB coverage, the size is fixed to the maximum
		cover_size = (256 << 10); // maximum size
		struct kcov_ioc_remote_attach args;
		args.subsystem = KCOV_REMOTE_VHCI;
		args.id = KCOV_REMOTE_VHCI_ID(procid, 1); // first port
		if (ioctl(cov->fd, KCOV_IOC_REMOTE_ATTACH, &args))
			fail("ioctl remote attach failed");
	} else {
		// Normal coverage
		cover_size = kCoverSize;
		if (ioctl(cov->fd, KCOV_IOC_SETBUFSIZE, &cover_size))
			fail("ioctl init trace write failed");
	}
	size_t mmap_alloc_size = cover_size * KCOV_ENTRY_SIZE;
#endif

	void* mmap_ptr = mmap(NULL, mmap_alloc_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, cov->fd, 0);
	if (mmap_ptr == MAP_FAILED)
		fail("cover mmap failed");
	cov->data = (char*)mmap_ptr;
	cov->data_end = cov->data + mmap_alloc_size;
}

static void cover_protect(cover_t* cov)
{
#if GOOS_freebsd
	size_t mmap_alloc_size = kCoverSize * KCOV_ENTRY_SIZE;
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size > 0)
		mprotect(cov->data + page_size, mmap_alloc_size - page_size,
			 PROT_READ);
#elif GOOS_openbsd
	int mib[2], page_size;
	size_t mmap_alloc_size = kCoverSize * sizeof(uintptr_t);
	mib[0] = CTL_HW;
	mib[1] = HW_PAGESIZE;
	size_t len = sizeof(page_size);
	if (sysctl(mib, ARRAY_SIZE(mib), &page_size, &len, NULL, 0) != -1)
		mprotect(cov->data + page_size, mmap_alloc_size - page_size, PROT_READ);
#endif
}

static void cover_unprotect(cover_t* cov)
{
#if GOOS_freebsd
	size_t mmap_alloc_size = kCoverSize * KCOV_ENTRY_SIZE;
	mprotect(cov->data, mmap_alloc_size, PROT_READ | PROT_WRITE);
#elif GOOS_openbsd
	size_t mmap_alloc_size = kCoverSize * sizeof(uintptr_t);
	mprotect(cov->data, mmap_alloc_size, PROT_READ | PROT_WRITE);
#endif
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
	// Whether it is a regular coverage or an extra coverage, the enable
	// ioctl is the same.
	if (ioctl(cov->fd, KIOENABLE, &kcov_mode))
		exitf("cover enable write trace failed, mode=%d", kcov_mode);
#elif GOOS_netbsd
	// Whether it is a regular coverage or a USB coverage, the enable
	// ioctl is the same.
	if (ioctl(cov->fd, KCOV_IOC_ENABLE, &kcov_mode))
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

#if GOOS_netbsd
#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {"usb", setup_usb},
    {"fault", setup_fault},
};

static void setup_machine(void)
{
}
#endif
