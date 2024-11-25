// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"github.com/google/syzkaller/prog"
)

type netbsd struct {
	nopChecker
}

func (netbsd) syscallCheck(ctx *checkContext, call *prog.Syscall) string {
	switch call.CallName {
	case "openat":
		return supportedOpenat(ctx, call)
	case "syz_usb_connect", "syz_usb_disconnect":
		return ctx.rootCanOpen("/dev/vhci0")
	default:
		return ""
	}
}
