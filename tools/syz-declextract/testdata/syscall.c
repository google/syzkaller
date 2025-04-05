// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/syscall.h"

SYSCALL_DEFINE1(open, const char* filename, int flags, int mode) {
	return 0;
}

SYSCALL_DEFINE1(chmod, const char* filename, int mode) {
	return 0;
}
