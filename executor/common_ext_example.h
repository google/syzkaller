// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// An example implementation of common_ext.h used for testing.

#define SYZ_HAVE_SETUP_EXT 1
static void setup_ext()
{
	debug("example setup_ext called\n");
}
