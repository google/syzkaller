// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package common provides helpers used across multiple workflows.
package common

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/codeexpert"
)

// CodeAccessTools is a set of tools for accessing source code.
var CodeAccessTools = CodeAccessToolsWithGit(true)

func CodeAccessToolsWithGit(enableGit bool) []aflow.Tool {
	expert := codeexpert.New(enableGit)
	return aflow.Tools(expert.Tools, expert)
}

const InstructionDontMakeAssumptionsAboutSourceCode = `
Don't make assumptions about the kernel source code (it may be different from what you assume it is).
Extensively use the provided code access tools (codesearch-*, git-*, {{.toolGrepper}}, etc)
to examine the actual source code, and confirm any assumptions.
`
