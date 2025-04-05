// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/fs.h"
#include "include/uapi/file_operations.h"
#include "include/uapi/unused_ioctl.h"

static void foo_open() {}
static void foo_read() {}
static void foo_write() {}
static void foo_mmap() {}

static void foo_ioctl2(unsigned int cmd, unsigned long arg) {
	switch (cmd) {
	case FOO_IOCTL6:
	case FOO_IOCTL7:
	default:
	}
}

static void foo_ioctl(void* file, unsigned int cmd, unsigned long arg) {
	switch (cmd) {
	case FOO_IOCTL1:
	case FOO_IOCTL2:
	case FOO_IOCTL3:
	case FOO_IOCTL4:
	case FOO_IOCTL5:
	}
	foo_ioctl2(cmd, arg);
}

const struct file_operations foo = {
	.open = foo_open,
	.read = foo_read,
	.write = foo_write,
	.unlocked_ioctl = foo_ioctl,
	.mmap = foo_mmap,
};

static void proc_open() {}
static void proc_read() {}
static void proc_write() {}
static void proc_ioctl(void* file, unsigned int cmd, unsigned long arg) {}

const struct file_operations proc_ops[] = {
	{
		.open = proc_open,
		.read_iter = proc_read,
		.write_iter = proc_write,
	},
	{
		.open = proc_open,
		.unlocked_ioctl = proc_ioctl,
	},
};

#define UNUSED_IOCTL2		_IO('c', 2)

static void unused_ioctl(void* file, unsigned int cmd, unsigned long arg) {
	switch (cmd) {
	case UNUSED_IOCTL1:
	case UNUSED_IOCTL2:
	}
}

const struct file_operations unused = {
	.unlocked_ioctl = unused_ioctl,
};
