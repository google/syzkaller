// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is included into executor and C reproducers and can be used to add
// non-mainline pseudo-syscalls w/o changing any other files.
// These syscalls should start with syz_ext_.
