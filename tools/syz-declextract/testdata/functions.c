// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/types.h"
#include "include/syscall.h"

static void func_foo() {
}

static void func_bar() {
	func_foo();
}

void func_baz(int f) {
	func_foo();
	if (f)
		func_bar();
	if (__builtin_constant_p(f))
		func_bar();
}

SYSCALL_DEFINE1(functions) {
	func_baz(1);
	return 0;
}
