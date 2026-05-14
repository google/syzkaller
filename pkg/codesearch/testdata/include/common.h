// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef INCLUDE_COMMON_H
#define INCLUDE_COMMON_H

static inline void foo() {}

#define FOO() foo()

#endif
