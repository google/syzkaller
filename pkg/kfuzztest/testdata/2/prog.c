// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#include "../common.h"

#include <stdlib.h>

struct bar {
	int a;
	int b;
};

struct foo {
	struct bar* b;
	const char* str;
	const char* data;
	size_t datalen;
	uint64_t* numbers;
};

DEFINE_FUZZ_TARGET(some_target, struct foo);
/* Expect foo.bar != NULL. */
DEFINE_CONSTRAINT(foo, bar, NULL, NULL, EXPECT_NE);
/* Expect foo.str != NULL. */
DEFINE_CONSTRAINT(foo, str, NULL, NULL, EXPECT_NE);
/* Annotate foo.str as a string. */
DEFINE_ANNOTATION(foo, str, , ATTRIBUTE_STRING);
/* Expect foo.data != NULL. */
DEFINE_CONSTRAINT(foo, data, NULL, NULL, EXPECT_NE);
/* Annotate foo.data as an array. */
DEFINE_ANNOTATION(foo, data, , ATTRIBUTE_ARRAY);
/* Annotate foo.datalen == len(foo.data). */
DEFINE_ANNOTATION(foo, datalen, data, ATTRIBUTE_LEN);
/* Annotate foo.numbers as an array. */
DEFINE_ANNOTATION(foo, numbers, , ATTRIBUTE_ARRAY);

/* Define a main function, otherwise the compiler complains. */
int main(void)
{
}
