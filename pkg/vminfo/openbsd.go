// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"github.com/google/syzkaller/prog"
)

type openbsd struct {
	nopChecker
}

func (openbsd) syscallCheck(ctx *checkContext, call *prog.Syscall) string {
	switch call.CallName {
	case "openat":
		return supportedOpenat(ctx, call)
	default:
		return ""
	}
}
