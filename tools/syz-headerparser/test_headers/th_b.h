// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef _TEST_HEADER_B
#define _TEST_HEADER_B

#include <linux/types.h>		/* header comment */

enum random_enum {
	ONE = 1<<0,
	TWO = 1<<1,
};

struct B {
	unsigned long B1;
	unsigned long B2;
};

struct struct_containing_union {
	int something;
	union {
		char  *a_char;
		struct B *B_ptr;
	} a_union;
};

#endif /* _TEST_HEADER_B */
