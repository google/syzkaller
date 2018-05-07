// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"golang.org/x/sys/unix"
)

// Builds but is not tested.
const (
	unixCBAUD     = unix.CBAUD
	unixCRTSCTS   = unix.CRTSCTS
	syscallTCGETS = unix.TCGETS2
	syscallTCSETS = unix.TCSETS2
)
