// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/uapi/io_uring.h"

struct io_issue_def {
	void (*prep)(void);
	void (*issue)(void);
};

void io_eopnotsupp_prep() {}
void io_nop_prep() {}
void io_nop() {}
void io_readv_prep() {}
void io_read() {}
void io_writev_prep() {}
void io_write() {}

const struct io_issue_def ops[] = {
	[IORING_OP_NOP] = {
		.prep			= io_nop_prep,
		.issue			= io_nop,
	},
	[IORING_OP_READV] = {
		.prep			= io_readv_prep,
		.issue			= io_read,
	},
	[IORING_OP_WRITEV] = {
		.prep			= io_writev_prep,
		.issue			= io_write,
	},
	[IORING_OP_NOT_SUPPORTED] = {
		.prep			= io_eopnotsupp_prep,
		.issue			= io_write,
	},
};
