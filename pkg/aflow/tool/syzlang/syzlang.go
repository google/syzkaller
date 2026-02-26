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

var Tools = []aflow.Tool{
	aflow.NewFuncTool("syzlang-search", search, `
Tool provides syzlang definitions for a given subsystem (e.g., "bpf", "io_uring").
`),
}

type searchArgs struct {
	Subsystem string `jsonschema:"Name of the subsystem to retrieve descriptions for (e.g. bpf, ext4)."`
}

type searchResult struct {
	Definitions string `jsonschema:"Syzlang definitions."`
	Error       string `jsonschema:"Error message, if any." json:",omitempty"`
}

func search(ctx *aflow.Context, state struct{}, args searchArgs) (searchResult, error) {
	if args.Subsystem == "" || args.Subsystem == "all" {
		return searchResult{Error: "Subsystem name is required and cannot be 'all'. " +
			"Please specify a specific subsystem like 'bpf' or 'ext4'."}, nil
	}

	// Let's assume the current working directory of the process is syzkaller root,
	// because aflow tools are executed by the syzkaller manager/tools.
	var out strings.Builder
	err := filepath.WalkDir("sys/linux", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".txt") {
			return nil
		}

		name := strings.TrimSuffix(d.Name(), ".txt")
		if name != "sys" && name != args.Subsystem && !strings.HasPrefix(name, args.Subsystem+"_") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out.Write(data)
		out.WriteString("\n")
		return nil
	})
	if err != nil {
		return searchResult{Error: "failed to access sys/linux: " + err.Error()}, nil
	}
	return searchResult{Definitions: out.String()}, nil
}
