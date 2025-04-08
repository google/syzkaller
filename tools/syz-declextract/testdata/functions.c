// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/fs.h"
#include "include/types.h"
#include "include/syscall.h"

static void func_foo() {
}

static void func_bar() {
	func_foo();
}

int func_baz(int f) {
	func_foo();
	if (f)
		func_bar();
	if (__builtin_constant_p(f))
		func_bar();
	if (f)
		return from_kuid();
	return alloc_fd();
}

int func_qux() {
	int fd = alloc_fd();
	return fd;
}

SYSCALL_DEFINE1(functions, long x) {
	__fget_light(x);
	return func_baz(1);
}

struct Typed {
  int a;
  int b;
  int c;
};

int typing1(int a, int b) {
  return a;
}

int typing(struct Typed* t1, int i) {
  struct Typed t2;
  t2.a = t1->b;
  int l = typing1(i, t2.a);
  t1->c = l;
  return l;
}
