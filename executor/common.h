// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdint.h>
#include <string.h>
#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_HANDLE_SEGV)
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_DEBUG)
#include <stdarg.h>
#include <stdio.h>
#endif

#if defined(SYZ_EXECUTOR)
#ifndef SYSCALLAPI
#define SYSCALLAPI
#endif

typedef long(SYSCALLAPI* syscall_t)(long, long, long, long, long, long, long, long, long);

struct call_t {
	const char* name;
	int sys_nr;
	syscall_t call;
};

// Defined in generated syscalls_OS.h files.
extern call_t syscalls[];
extern unsigned syscall_count;
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||            \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_TUN_ENABLE) || defined(SYZ_SANDBOX_NAMESPACE) || \
    defined(SYZ_SANDBOX_SETUID) || defined(SYZ_FAULT_INJECTION) || defined(__NR_syz_kvm_setup_cpu)
const int kFailStatus = 67;
const int kRetryStatus = 69;
#endif

#if defined(SYZ_EXECUTOR)
const int kErrorStatus = 68;
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||            \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_TUN_ENABLE) || defined(SYZ_SANDBOX_NAMESPACE) || \
    defined(SYZ_SANDBOX_SETUID) || defined(SYZ_FAULT_INJECTION) || defined(__NR_syz_kvm_setup_cpu)
// logical error (e.g. invalid input program), use as an assert() alernative
NORETURN static void fail(const char* msg, ...)
{
	int e = errno;
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	// ENOMEM/EAGAIN is frequent cause of failures in fuzzing context,
	// so handle it here as non-fatal error.
	doexit((e == ENOMEM || e == EAGAIN) ? kRetryStatus : kFailStatus);
}
#endif

#if defined(SYZ_EXECUTOR)
// kernel error (e.g. wrong syscall return value)
NORETURN static void error(const char* msg, ...)
{
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	doexit(kErrorStatus);
}
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT))
// just exit (e.g. due to temporal ENOMEM error)
NORETURN static void exitf(const char* msg, ...)
{
	int e = errno;
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(kRetryStatus);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_DEBUG)
static int flag_debug;

static void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	va_list args;
	va_start(args, msg);
	vfprintf(stdout, msg, args);
	va_end(args);
	fflush(stdout);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_BITMASKS)
#define BITMASK_LEN(type, bf_len) (type)((1ull << (bf_len)) - 1)

#define BITMASK_LEN_OFF(type, bf_off, bf_len) (type)(BITMASK_LEN(type, (bf_len)) << (bf_off))

#define STORE_BY_BITMASK(type, addr, val, bf_off, bf_len)                         \
	if ((bf_off) == 0 && (bf_len) == 0) {                                     \
		*(type*)(addr) = (type)(val);                                     \
	} else {                                                                  \
		type new_val = *(type*)(addr);                                    \
		new_val &= ~BITMASK_LEN_OFF(type, (bf_off), (bf_len));            \
		new_val |= ((type)(val)&BITMASK_LEN(type, (bf_len))) << (bf_off); \
		*(type*)(addr) = new_val;                                         \
	}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_CHECKSUMS)
struct csum_inet {
	uint32_t acc;
};

static void csum_inet_init(struct csum_inet* csum)
{
	csum->acc = 0;
}

static void csum_inet_update(struct csum_inet* csum, const uint8_t* data, size_t length)
{
	if (length == 0)
		return;

	size_t i;
	for (i = 0; i < length - 1; i += 2)
		csum->acc += *(uint16_t*)&data[i];

	if (length & 1)
		csum->acc += (uint16_t)data[length - 1];

	while (csum->acc > 0xffff)
		csum->acc = (csum->acc & 0xffff) + (csum->acc >> 16);
}

static uint16_t csum_inet_digest(struct csum_inet* csum)
{
	return ~csum->acc;
}
#endif
