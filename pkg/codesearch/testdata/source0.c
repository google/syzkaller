// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "source0.h"

struct struct_in_c_file {
	int X;
	struct some_struct by_value;
};

/*
 * Comment about open.
 */
int open()
{
	return 0;
}

int close()
{
	return 0;
}

void function_with_comment_in_header()
{
	same_name_in_several_files();
}
