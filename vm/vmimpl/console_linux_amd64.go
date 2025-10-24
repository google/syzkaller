
package vmimpl

import (
	"golang.org/x/sys/unix"
)

const (
	unixCBAUD     = unix.CBAUD
	unixCRTSCTS   = unix.CRTSCTS
	syscallTCGETS = unix.TCGETS2
	syscallTCSETS = unix.TCSETS2
)
