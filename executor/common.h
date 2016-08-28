// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

__thread int skip_segv;
__thread jmp_buf segv_env;

static void segv_handler(int sig, siginfo_t* info, void* uctx)
{
	if (__atomic_load_n(&skip_segv, __ATOMIC_RELAXED))
		_longjmp(segv_env, 1);
	exit(sig);
}

static void install_segv_handler()
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

#define NONFAILING(...)                                              \
	{                                                            \
		__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		if (_setjmp(segv_env) == 0) {                        \
			__VA_ARGS__;                                 \
		}                                                    \
		__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); \
	}
