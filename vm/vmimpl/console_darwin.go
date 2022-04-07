// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import "syscall"

const (
	unixCBAUD     = 0
	unixCRTSCTS   = 0
	syscallTCGETS = syscall.TIOCGETA
	syscallTCSETS = syscall.TIOCSETA
)
