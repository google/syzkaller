// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var GetMaintainers = aflow.NewFuncAction("get-maintainers", maintainers)

type maintainersArgs struct {
	KernelSrc string
	PatchDiff string
}

type maintainersResult struct {
	Recipients []ai.Recipient
}

func maintainers(ctx *aflow.Context, args maintainersArgs) (maintainersResult, error) {
	res := maintainersResult{}
	// See #1441 re --git-min-percent.
	script := filepath.Join(args.KernelSrc, "scripts/get_maintainer.pl")
	cmd := exec.Command(script, "--git-min-percent=15")
	cmd.Dir = args.KernelSrc
	cmd.Stdin = strings.NewReader(args.PatchDiff)
	output, err := osutil.Run(time.Minute, cmd)
	if err != nil {
		return res, err
	}
	for _, recipient := range vcs.ParseMaintainersLinux(output) {
		res.Recipients = append(res.Recipients, ai.Recipient{
			Name:  recipient.Address.Name,
			Email: recipient.Address.Address,
			To:    recipient.Type == vcs.To,
		})
	}
	return res, nil
}
