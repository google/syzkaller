// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build linux

package vmimpl

import (
    "syscall"
    "unix"
)

const (
    unix_CBAUD = unix.CBAUD
    unix_CRTSCTS = unix.CRTSCTS
    syscall_TCGETS = syscall.TCGETS
    syscall_TCSETS = syscall.TCSETS
)
