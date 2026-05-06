// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#define DEFINE_VAR(name) int name = 1
#define DEFINE_STATIC_VAR(name) static int name = 2

DEFINE_VAR(macro_var);

DEFINE_STATIC_VAR(static_macro_var);

int global_var = 3;
static int local_to_file_var = 4;

void some_function(void)
{
	int local_var = 5;
	(void)local_var;
}
