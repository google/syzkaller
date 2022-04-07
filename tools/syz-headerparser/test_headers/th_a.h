// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef __TEST_HEADER_A
#define __TEST_HEADER_A

#define RANDOM_MACRO_1 1
#define RANDOM_MACRO_2 2

struct A {
	struct B *B_item;
	const char *char_ptr;
	unsigned int an_unsigned_int;
	/*
	 * Some comments
	 */
	bool a_bool;
	bool another_bool;
	some_type var;
};

#endif /* __TEST_HEADER_A */
