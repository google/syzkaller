// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/aflow/syzspec"
)

func init() {
	// Used externally - do not remove.
	runtime.KeepAlive(TestSeeds)
}

// DescriptionFilesPrompt generates a formatted prompt string listing all
// non-const description files for the given SyzFS instance, along with usage
// instructions.
func DescriptionFilesPrompt(syzFS *syzspec.SyzFS) string {
	files := syzFS.DescriptionFiles()
	var filtered []string
	for _, f := range files {
		if strings.HasSuffix(f, ".const") {
			continue
		}
		filtered = append(filtered, f)
	}
	sb := new(strings.Builder)
	sb.WriteString("Available Syscall Description Files:\n")
	for _, f := range filtered {
		sb.WriteString(f)
		sb.WriteByte('\n')
	}
	sb.WriteString("\nNote that the constant values for the descriptions are defined " +
		"in the file suffixed with .const (e.g. sys.txt.const for sys.txt).\n" +
		"If you need base seeds for file system image setup or other device setup, " +
		"use read-syz-spec and syz-grepper to look up files in the test/ directory.\n")
	return sb.String()
}

// TestSeeds returns the list of test seed files (e.g. test/syz_mount_...) for
// the given syzkaller directory and target OS.
func TestSeeds(syzkallerDir, osTarget string) []string {
	return syzspec.NewSyzFS(syzkallerDir, osTarget).TestSeeds()
}
