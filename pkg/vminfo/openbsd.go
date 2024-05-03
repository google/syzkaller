// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/prog"
)

type openbsd int

func (openbsd) RequiredFiles() []string {
	return nil
}

func (openbsd) checkFiles() []string {
	return nil
}

func (openbsd) parseModules(files filesystem) ([]cover.KernelModule, error) {
	return nil, nil
}

func (openbsd) machineInfos() []machineInfoFunc {
	return nil
}

func (openbsd) syscallCheck(ctx *checkContext, call *prog.Syscall) string {
	switch call.CallName {
	case "openat":
		return supportedOpenat(ctx, call)
	default:
		return ""
	}
}
