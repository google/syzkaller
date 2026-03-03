// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

var ToolListDescriptions = aflow.NewFuncTool("descriptions-list", listFiles, `
Tool lists all the available description files.`)

var ToolGetDescriptions = aflow.NewFuncTool("descriptions-get", getFile, `
Tool returns the specific description file in syzlang format.`)

type descriptionsToolState struct {
	Syzkaller string
}

type listFilesArgs struct {
}

type listFilesResult struct {
	Files []string `jsonschema:"List of available description files."`
}

func listFiles(ctx *aflow.Context, state descriptionsToolState, args listFilesArgs) (listFilesResult, error) {
	var files []string
	dir := filepath.Join(state.Syzkaller, "sys", "linux")
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".txt") {
			return nil
		}

		files = append(files, d.Name())
		return nil
	})
	if err != nil {
		return listFilesResult{}, aflow.BadCallError("failed to access sys/linux: %v", err)
	}
	if len(files) == 0 {
		return listFilesResult{}, aflow.BadCallError("failed to access sys/linux: no files found")
	}
	return listFilesResult{Files: files}, nil
}

type getFileArgs struct {
	File string `jsonschema:"Name of the file. Use descriptions-list tool to get the full list."`
}

type getFileResult struct {
	Content string `jsonschema:"Syzlang definitions."`
}

func getFile(ctx *aflow.Context, state descriptionsToolState, args getFileArgs) (getFileResult, error) {
	data, err := os.ReadFile(filepath.Join(state.Syzkaller, "sys", "linux", args.File))
	if err != nil {
		return getFileResult{}, aflow.BadCallError("failed to access %s: %v", args.File, err)
	}
	if len(data) == 0 {
		return getFileResult{}, aflow.BadCallError("failed to access %s: empty file", args.File)
	}
	return getFileResult{Content: string(data)}, nil
}
