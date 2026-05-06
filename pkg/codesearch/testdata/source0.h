// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

/*
 * Comment about the function in header.
 * Multi-line just in case.
 */
void function_with_comment_in_header();

void same_name_in_several_files();

static inline int func_in_header()
{
	return 0;
}

struct some_struct {
	int x;
	int y;
};

typedef struct some_struct some_struct_t;

/*
 * This should not require an explanation.
 */
struct some_struct_with_a_comment {
	int x;
	struct some_struct* other_struct;
};

typedef struct {
	int x;
} typedefed_struct_t;

typedef struct another_struct {
	int x;
} another_struct_t;

union some_union {
	int x;
	void* p;
	struct some_struct s;
};

enum some_enum {
	enum_foo = 1,
	enum_bar = 2,
};

typedef enum some_enum some_enum_t;
