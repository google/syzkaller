// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "ioctl.h"

#define FOO_IOCTL1		_IO('c', 1)
#define FOO_IOCTL2		_IOR('c', 2, int)
#define FOO_IOCTL3		_IOR('c', 3, struct foo_ioctl_arg)
#define FOO_IOCTL4		_IOW('c', 4, struct foo_ioctl_arg)
#define FOO_IOCTL5		_IOWR('c', 5, struct foo_ioctl_arg)

struct foo_ioctl_arg {
	int a, b;
};
