// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
)

var PrepareSyzFS = aflow.NewFuncAction("prepare-syzfs", prepareSyzFSFunc)

type PrepareSyzFSArgs struct {
	Syzkaller string
	TargetOS  string
}

type PrepareSyzFSResult struct {
	SyzFS                  *syzspec.SyzFS
	DescriptionFilesPrompt string
}

func prepareSyzFSFunc(ctx *aflow.Context, args PrepareSyzFSArgs) (PrepareSyzFSResult, error) {
	syzFS := syzspec.NewSyzFS(args.Syzkaller, args.TargetOS)
	return PrepareSyzFSResult{
		SyzFS:                  syzFS,
		DescriptionFilesPrompt: syzlang.DescriptionFilesPrompt(syzFS),
	}, nil
}
