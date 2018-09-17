// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdlib.h>
#include <unistd.h>

#if SYZ_EXECUTOR || __NR_syz_mmap
#include <sys/mman.h>

// syz_mmap(addr vma, len len[addr])
static long syz_mmap(long a0, long a1)
{
	return (long)mmap((void*)a0, a1, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_errno
#include <errno.h>

// syz_errno(v int32)
static long syz_errno(long v)
{
	errno = v;
	return v == 0 ? 0 : -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_compare
#include <errno.h>
#include <string.h>

// syz_compare(want ptr[in, string], want_len len[want], got ptr[in, compare_data], got_len len[got])
static long syz_compare(long want, long want_len, long got, long got_len)
{
	if (want_len != got_len) {
		debug("syz_compare: want_len=%lu got_len=%lu\n", want_len, got_len);
		errno = EBADF;
		return -1;
	}
	if (memcmp((void*)want, (void*)got, want_len)) {
		debug("syz_compare: data differs\n");
		errno = EINVAL;
		return -1;
	}
	return 0;
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	doexit(0);
}
#endif

#if SYZ_EXECUTOR
#define do_sandbox_setuid() 0
#define do_sandbox_namespace() 0
#define do_sandbox_android_untrusted_app() 0
#endif
