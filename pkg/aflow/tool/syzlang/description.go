// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"path"
	"runtime"
	"slices"
	"strings"

	"github.com/google/syzkaller/sys"
)

func init() {
	// Used externally - do not remove.
	runtime.KeepAlive(TestSeeds)
}

// DescriptionFiles returns the list of syzlang description files (e.g. sys.txt)
// for the given target OS. Test seed files in the test/ directory are excluded;
// use TestSeeds to retrieve them.
func DescriptionFiles(osTarget string) []string {
	entries, err := sys.Files.ReadDir(osTarget)
	if err != nil {
		panic(err)
	}
	var files []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if ent.Name() == autoTxt || ent.Name() == autoTxt+".const" {
			continue
		}
		files = append(files, ent.Name())
	}
	slices.Sort(files)
	return files
}

// DescriptionFilesPrompt generates a formatted prompt string listing all
// non-const description files for the given target OS, along with usage
// instructions.
func DescriptionFilesPrompt(osTarget string) string {
	files := DescriptionFiles(osTarget)
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
// the given target OS.
func TestSeeds(osTarget string) []string {
	var files []string
	testEntries, err := sys.Files.ReadDir(path.Join(osTarget, "test"))
	if err == nil {
		for _, testEnt := range testEntries {
			if !testEnt.IsDir() {
				files = append(files, path.Join("test", testEnt.Name()))
			}
		}
	}
	slices.Sort(files)
	return files
}
