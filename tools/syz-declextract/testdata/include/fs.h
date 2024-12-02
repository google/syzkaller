// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

struct file_operations {
	void (*open)(void);
	void (*read)(void);
	void (*write)(void);
	void (*read_iter)(void);
	void (*write_iter)(void);
	void (*unlocked_ioctl)(unsigned int);
	void (*mmap)(void);
};
