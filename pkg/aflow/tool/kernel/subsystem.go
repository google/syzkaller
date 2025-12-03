// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

var SubsystemToRepo = aflow.NewFuncAction("kernel-subsystem-to-repo", subsystemToRepo)

type subsystemArgs struct {
	Subsystem string `json:"kernel-subsystem"`
}

type subsystemResult struct {
	Subsystem    string `json:"kernel-subsystem"`
	KernelRepo   string `json:"kernel-repo"`
	KernelCommit string `json:"kernel-commit"`
}

func subsystemToRepo(ctx *aflow.Context, args subsystemArgs) (subsystemResult, error) {
	subsystem := strings.TrimSpace(args.Subsystem)
	repo := "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
	branch := "master"
	switch subsystem {
	case "usb":
		repo = "git://git.kernel.org/pub/scm/linux/kernel/git/gregkh/usb.git"
		branch = "main"
	}
	return subsystemResult{
		Subsystem:    subsystem,
		KernelRepo:   repo,
		KernelCommit: branch,
	}, nil
}
