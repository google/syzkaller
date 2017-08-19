// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"golang.org/x/sys/unix"
)

// Builds but is not tested.
const (
	unix_CBAUD     = unix.CBAUD
	unix_CRTSCTS   = unix.CRTSCTS
	syscall_TCGETS = unix.TCGETS2
	syscall_TCSETS = unix.TCSETS2
)
