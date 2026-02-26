// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"github.com/google/syzkaller/pkg/aflow"
)

var CompareCrashSignature = aflow.NewFuncAction("compare-crash-signature", compareCrash)

type CompareCrashArgs struct {
	BugTitle         string
	ProducedBugTitle string
}

type CompareCrashResult struct {
	Matches       bool
	CompareErrors string
}

func compareCrash(ctx *aflow.Context, args CompareCrashArgs) (CompareCrashResult, error) {
	if args.BugTitle != args.ProducedBugTitle {
		return CompareCrashResult{Matches: false, CompareErrors: "Crash signature did not match target"}, nil
	}
	return CompareCrashResult{Matches: true}, nil
}
