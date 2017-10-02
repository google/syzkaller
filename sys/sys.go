// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	_ "github.com/google/syzkaller/sys/freebsd"
	_ "github.com/google/syzkaller/sys/fuchsia"
	_ "github.com/google/syzkaller/sys/linux"
	_ "github.com/google/syzkaller/sys/windows"
)

// Emitted by Makefile.
var GitRevision string
