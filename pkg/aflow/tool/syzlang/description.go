// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"path"
	"slices"
	"strings"

	"github.com/google/syzkaller/sys"
)

func DescriptionFiles(osTarget string) []string {
	entries, err := sys.Files.ReadDir(osTarget)
	if err != nil {
		panic(err)
	}
	var files []string
	for _, ent := range entries {
		if ent.IsDir() && ent.Name() == "test" {
			files = append(files, testSeeds(osTarget)...)
			continue
		}
		if ent.Name() == "auto.txt" || ent.Name() == "auto.txt.const" {
			continue
		}
		if !ent.IsDir() {
			files = append(files, ent.Name())
		}
	}
	slices.Sort(files)
	return files
}

func DescriptionFilesPrompt(osTarget string) string {
	files := DescriptionFiles(osTarget)
	var filtered []string
	for _, f := range files {
		if strings.HasSuffix(f, ".const") || strings.HasPrefix(f, "test/") {
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
		"use syz-grepper (with PathPrefix set to \"test\") to search for relevant syscalls or device names " +
		"within the test seeds in the test/ directory.\n" +
		"If you need to use pseudo syscalls or understand their behavior (e.g. " +
		"syz_usb_connect, syz_mount_image), look for syz_* pseudo syscalls in the executor header " +
		"files (located under the executor/ directory, e.g. executor/common_usb_linux.h). You can " +
		"directly use these pseudo syscalls in your syzlang program to use the syscalls of the " +
		"same name more conveniently.\n")
	return sb.String()
}

func testSeeds(osTarget string) []string {
	var files []string
	testEntries, err := sys.Files.ReadDir(path.Join(osTarget, "test"))
	if err == nil {
		for _, testEnt := range testEntries {
			if !testEnt.IsDir() {
				files = append(files, path.Join("test", testEnt.Name()))
			}
		}
	}
	return files
}
