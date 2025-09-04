// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#include "../common.h"

#include <stdio.h>
#include <stdlib.h>

struct pkcs7_parse_message_arg {
	const void* data;
	size_t datalen;
};

DEFINE_FUZZ_TARGET(test_pkcs7_parse_message, struct pkcs7_parse_message_arg);
/* Expect data != NULL. */
DEFINE_CONSTRAINT(pkcs7_parse_message_arg, data, NULL, NULL, EXPECT_NE);
/* Expect datalen == len(data). */
DEFINE_ANNOTATION(pkcs7_parse_message_arg, datalen, data, ATTRIBUTE_LEN);
/* Annotate data as an array. */
DEFINE_ANNOTATION(pkcs7_parse_message_arg, data, , ATTRIBUTE_ARRAY);

/* Define a main function, otherwise the compiler complains. */
int main(void)
{
}
