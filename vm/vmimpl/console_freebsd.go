// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"syscall"
	"golang.org/x/sys/unix"
)

const (
	unix_CBAUD     = 0
	unix_CRTSCTS   = unix.CRTSCTS
	syscall_TCGETS = syscall.TIOCGETA
	syscall_TCSETS = syscall.TIOCSETA
)
