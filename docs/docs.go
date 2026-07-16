// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package docs exports some of the docs for LLM agents in pkg/aflow.
package docs

import (
	_ "embed"
)

// ProgramSyntax contains the documentation for syzkaller program syntax.
//go:embed program_syntax.md
var ProgramSyntax string

// SyscallDescriptionsSyntax contains the documentation for syzkaller syscall descriptions syntax.
//go:embed syscall_descriptions_syntax.md
var SyscallDescriptionsSyntax string
