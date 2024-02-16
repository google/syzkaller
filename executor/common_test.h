// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdlib.h>
#include <unistd.h>

#if SYZ_EXECUTOR || __NR_syz_mmap
#include <sys/mman.h>

// syz_mmap(addr vma, len len[addr])
static long syz_mmap(volatile long a0, volatile long a1)
{
	return (long)mmap((void*)a0, a1, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_errno
#include <errno.h>

// syz_errno(v int32)
static long syz_errno(volatile long v)
{
	errno = v;
	return v == 0 ? 0 : -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_exit
// syz_exit(status int32)
static long syz_exit(volatile long status)
{
	_exit(status);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_sleep_ms
// syz_sleep_ms(ms intptr)
static long syz_sleep_ms(volatile long ms)
{
	sleep_ms(ms);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_compare
#include <errno.h>
#include <string.h>

// syz_compare(want ptr[in, string], want_len len[want], got ptr[in, compare_data], got_len len[got])
static long syz_compare(volatile long want, volatile long want_len, volatile long got, volatile long got_len)
{
	if (want_len != got_len) {
		errno = EBADF;
		goto error;
	}
	if (memcmp((void*)want, (void*)got, want_len)) {
		errno = EINVAL;
		goto error;
	}
	return 0;

error:
	debug("syz_compare: want (%lu):\n", want_len);
	debug_dump_data((char*)want, want_len);
	debug("got (%lu):\n", got_len);
	debug_dump_data((char*)got, got_len);
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_compare_int
#include <errno.h>
#include <stdarg.h>

// syz_compare_int$4(n const[2], v0 intptr, v1 intptr, v2 intptr, v3 intptr)
static long syz_compare_int(volatile long n, ...)
{
	va_list args;
	va_start(args, n);
	long v0 = va_arg(args, long);
	long v1 = va_arg(args, long);
	long v2 = va_arg(args, long);
	long v3 = va_arg(args, long);
	va_end(args);
	if (n < 2 || n > 4)
		return errno = E2BIG, -1;
	if (n <= 2 && v2 != 0)
		return errno = EFAULT, -1;
	if (n <= 3 && v3 != 0)
		return errno = EFAULT, -1;
	if (v0 != v1)
		return errno = EINVAL, -1;
	if (n > 2 && v0 != v2)
		return errno = EINVAL, -1;
	if (n > 3 && v0 != v3)
		return errno = EINVAL, -1;
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_compare_zlib
#include "common_zlib.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

// syz_compare_zlib(data ptr[in, array[int8]], size bytesize[data], zdata ptr[in, compressed_image], zsize bytesize[zdata])
static long syz_compare_zlib(volatile long data, volatile long size, volatile long zdata, volatile long zsize)
{
	int fd = open("./uncompressed", O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd == -1)
		return -1;
	if (puff_zlib_to_file((unsigned char*)zdata, zsize, fd))
		return -1;
	struct stat statbuf;
	if (fstat(fd, &statbuf))
		return -1;
	void* uncompressed = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (uncompressed == MAP_FAILED)
		return -1;
	return syz_compare(data, size, (long)uncompressed, statbuf.st_size);
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_test_fuzzer1

static void fake_crash(const char* name)
{
	failmsg("crash", "{{CRASH: %s}}", name);
	doexit(1);
}

static long syz_test_fuzzer1(volatile long a, volatile long b, volatile long c)
{
	// We probably want something more interesting here.
	if (a == 1 && b == 1 && c == 1)
		fake_crash("first bug");
	if (a == 1 && b == 2 && c == 3)
		fake_crash("second bug");
	return 0;
}

#endif
