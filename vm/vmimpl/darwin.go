// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin

package vmimpl

import "syscall"

const (
    CBAUD = 0
    CRTSCTS = 0
    TCGETS = syscall.TIOCGETA
    TCSETS = syscall.TIOCSETA
)
