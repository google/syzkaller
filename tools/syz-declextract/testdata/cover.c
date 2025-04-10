// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/syscall.h"

#define COVER_IOCTL1 1
#define COVER_IOCTL2 2
#define COVER_IOCTL3 3
#define COVER_IOCTL4 4

static void cover_helper(int cmd) {
	int tmp = 0;
	tmp++;
	switch (cmd) {
	case COVER_IOCTL3:
		break;
	case COVER_IOCTL4:
		tmp++;
		break;
	}
}

SYSCALL_DEFINE1(cover, int cmd) {
	int tmp = 0;
	tmp++;
	switch (cmd) {
	case COVER_IOCTL1:
		break;
	case COVER_IOCTL2:
		break;
	case COVER_IOCTL3:
	case COVER_IOCTL4:
		cover_helper(cmd);
		break;
	}
	return tmp;
}
