// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// An example implementation of common_ext.h used for testing.

#define SYZ_HAVE_SETUP_EXT 1
static void setup_ext()
{
	debug("example setup_ext called\n");
}

#define SYZ_HAVE_SETUP_EXT_TEST 1
static void setup_ext_test()
{
	// See TestCommonExt.
	memcpy((void*)(SYZ_DATA_OFFSET + 0x1234), "\xee\xff\xc0\xad\x0b\x00\x00\x00", 8);
}
