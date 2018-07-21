// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdint.h>
#include <string.h>
#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||               \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_TUN_ENABLE) || defined(SYZ_SANDBOX_NAMESPACE) ||    \
    defined(SYZ_SANDBOX_NONE) || defined(SYZ_SANDBOX_SETUID) || defined(SYZ_FAULT_INJECTION) || \
    defined(__NR_syz_kvm_setup_cpu) || defined(__NR_syz_init_net_socket) ||                     \
    defined(__NR_syz_mmap)
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#endif
#if defined(SYZ_EXECUTOR) || defined(SYZ_USE_TMP_DIR)
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
// exit/_exit do not necessary work (e.g. if fuzzer sets seccomp filter that prohibits exit_group).
// Use doexit instead.  We must redefine exit to something that exists in stdlib,
// because some standard libraries contain "using ::exit;", but has different signature.
#define exit vsnprintf
#define _exit vsnprintf

// uint64 is impossible to printf without using the clumsy and verbose "%" PRId64.
// So we define and use uint64. Note: pkg/csource does s/uint64/uint64/.
// Also define uint32/16/8 for consistency.
typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

#ifdef SYZ_EXECUTOR
// Note: zircon max fd is 256.
const int kInPipeFd = 250; // remapped from stdin
const int kOutPipeFd = 251; // remapped from stdout
#endif

#if defined(__GNUC__)
#define SYSCALLAPI
#define NORETURN __attribute__((noreturn))
#define ALIGNED(N) __attribute__((aligned(N)))
#define PRINTF __attribute__((format(printf, 1, 2)))
#else
// Assuming windows/cl.
#define SYSCALLAPI WINAPI
#define NORETURN __declspec(noreturn)
#define ALIGNED(N) __declspec(align(N))
#define PRINTF
#endif

typedef long(SYSCALLAPI* syscall_t)(long, long, long, long, long, long, long, long, long);

struct call_t {
	const char* name;
	int sys_nr;
	syscall_t call;
};

#endif // #if defined(SYZ_EXECUTOR)

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||               \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_TUN_ENABLE) || defined(SYZ_SANDBOX_NAMESPACE) ||    \
    defined(SYZ_SANDBOX_NONE) || defined(SYZ_SANDBOX_SETUID) || defined(SYZ_FAULT_INJECTION) || \
    defined(__NR_syz_kvm_setup_cpu) || defined(__NR_syz_mmap)
const int kFailStatus = 67;
const int kRetryStatus = 69;
#endif

#if defined(SYZ_EXECUTOR)
const int kErrorStatus = 68;
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT)) ||                       \
    defined(SYZ_USE_TMP_DIR) || defined(SYZ_TUN_ENABLE) || defined(SYZ_SANDBOX_NAMESPACE) ||            \
    defined(SYZ_SANDBOX_NONE) || defined(SYZ_SANDBOX_SETUID) || defined(__NR_syz_kvm_setup_cpu) ||      \
    defined(__NR_syz_init_net_socket) &&                                                                \
	(defined(SYZ_SANDBOX_NONE) || defined(SYZ_SANDBOX_SETUID) || defined(SYZ_SANDBOX_NAMESPACE)) || \
    defined(__NR_syz_mmap)
// logical error (e.g. invalid input program), use as an assert() alternative
NORETURN PRINTF static void fail(const char* msg, ...)
{
	int e = errno;
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
NORETURN PRINTF static void error(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	doexit(kErrorStatus);
}
#endif

#if defined(SYZ_EXECUTOR) || (defined(SYZ_REPEAT) && defined(SYZ_WAIT_REPEAT) && defined(SYZ_USE_TMP_DIR)) || defined(SYZ_FAULT_INJECTION)
// just exit (e.g. due to temporal ENOMEM error)
NORETURN PRINTF static void exitf(const char* msg, ...)
{
	int e = errno;
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

PRINTF static void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
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
	uint32 acc;
};

static void csum_inet_init(struct csum_inet* csum)
{
	csum->acc = 0;
}

static void csum_inet_update(struct csum_inet* csum, const uint8* data, size_t length)
{
	if (length == 0)
		return;

	size_t i;
	for (i = 0; i < length - 1; i += 2)
		csum->acc += *(uint16*)&data[i];

	if (length & 1)
		csum->acc += (uint16)data[length - 1];

	while (csum->acc > 0xffff)
		csum->acc = (csum->acc & 0xffff) + (csum->acc >> 16);
}

static uint16 csum_inet_digest(struct csum_inet* csum)
{
	return ~csum->acc;
}
#endif
