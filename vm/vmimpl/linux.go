// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build linux

package vmimpl

import (
    "syscall"
    "unix"
)

const (
    CBAUD = unix.CBAUD
    CRTSCTS = unix.CRTSCTS
    TCGETS = syscall.TCGETS
    TCSETS = syscall.TCSETS
)
