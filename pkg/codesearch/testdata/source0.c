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

int func_accepting_a_struct(struct some_struct* p)
{
	return ((some_struct_t*)p)->x +
	       ((union some_union*)p)->x;
}

void function_with_quotes_in_type(void __attribute__((btf_type_tag("user"))) *)
{
}

int field_refs(struct some_struct* p, union some_union* u)
{
	p->x = p->y;
	*(&p->x) = 1;
	u->p = 0;
	u->s.x = 2;
	return p->x;
}
