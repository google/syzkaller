// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <ros/syscall.h>
#include <stdlib.h>
#include <unistd.h>

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
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
