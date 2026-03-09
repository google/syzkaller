// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"path"

	"github.com/google/syzkaller/pkg/aflow"
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

var ReadDescription = aflow.NewFuncTool("read-description", readDescription, `
The tool reads the content of a syzlang description file (e.g. sys.txt, socket.txt, etc).
Description files contain syscall definitions and related types.
`)

type readDescArgs struct {
	File string `jsonschema:"the name of the syzlang description file to read, e.g. sys.txt or socket.txt"`
}

type readDescResults struct {
	Output string `jsonschema:"Content of the description file."`
}

func readDescription(ctx *aflow.Context, state struct{}, args readDescArgs) (readDescResults, error) {
	// sys.Files always uses a slash as a file separator.
	data, err := sys.Files.ReadFile(path.Join(targets.Linux, args.File))
	if err != nil {
		return readDescResults{}, aflow.BadCallError("failed to read file %q: %v", args.File, err)
	}
	return readDescResults{string(data)}, nil
}
