// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is included into executor and C reproducers and can be used to add
// non-mainline pseudo-syscalls and to provide some other extension points
// w/o changing any other files. See common_ext_example.h for an example implementation.

// Pseudo-syscalls defined in this file should start with syz_ext_.

// This file can also define SYZ_HAVE_SETUP_EXT to 1 and provide
// void setup_ext() function that will be called during VM setup.

// This file can also define SYZ_HAVE_SETUP_EXT_TEST to 1 and provide
// void setup_ext_test() function that will be called during setup of each test process.
