// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package common

import (
	"embed"
	"fmt"
	"strings"
)

// Prompt loads a prompt from the provided embed.FS and performs common substitutions.
func Prompt(fs embed.FS, name string) string {
	b, err := fs.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to read prompt %s: %v", name, err))
	}
	res := string(b)
	// Apply common instruction substitutions.
	res = strings.ReplaceAll(res, "{{.CommonInstructionDontMakeAssumptions}}",
		strings.TrimSpace(InstructionDontMakeAssumptionsAboutSourceCode))
	res = strings.TrimSpace(res)
	if res == "" {
		panic(fmt.Sprintf("prompt %s is empty", name))
	}
	return res
}
