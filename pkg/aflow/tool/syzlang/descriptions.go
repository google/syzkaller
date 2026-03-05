// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func DescriptionFiles() []string {
	entries, err := sys.Files.ReadDir(targets.Linux)
	if err != nil {
		panic(err)
	}
	var files []string
	for _, ent := range entries {
		files = append(files, ent.Name())
	}
	return files
}
