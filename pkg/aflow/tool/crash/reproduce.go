// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"github.com/google/syzkaller/pkg/aflow"
)

var Reproduce = aflow.NewFuncAction("crash-reproducer", reproduce)

type reproduceArgs struct {
	KernelSrc    string `json:"kernel-src"`
	KernelCommit string `json:"kernel-commit"`
	KernelConfig string `json:"kernel-config"`
}

type reproduceResult struct {
	//!!! provide updated crash report, etc
	// or return an error if it does not reproduce
}

func reproduce(ctx *aflow.Context, args reproduceArgs) (reproduceResult, error) {
	return reproduceResult{}, nil
}
