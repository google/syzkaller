// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	doexit(0);
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
static void execute_one();
const char* program_name;

void child()
{
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
	install_segv_handler();
#endif
#if SYZ_EXECUTOR
	receive_execute();
	close(kInPipeFd);
#endif
	execute_one();
	doexit(0);
}
#endif

#define do_sandbox_setuid() 0
#define do_sandbox_namespace() 0
#define setup_loop()
#define reset_loop()
#define setup_test()
#define reset_test()
