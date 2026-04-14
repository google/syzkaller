// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/symbolizer"
)

var (
	CoverageFiles = aflow.NewFuncTool("get-coverage-files", getCoverageFiles, `
Tool returns a list of source files that were covered during a crash reproducer run.
The list is deduplicated and sorted, presenting a high-level summary of the covered code regions.
`)

	FileCoverage = aflow.NewFuncTool("get-file-coverage", getFileCoverage, `
Tool evaluates code coverage for a specific file and returns coverage snippets highlighting the executed lines.
For each function that had hits in the file, it will dump the executed source lines with short context
around them. Covered lines are prefixed with '* '.
`)

	Coverage = []aflow.Tool{CoverageFiles, FileCoverage}
)

type CoverageFilesArgs struct {
	CoverageID string `jsonschema:"Coverage ID returned by the reproduce-crash tool."`
}

type CoverageFilesResult struct {
	Files []string `jsonschema:"List of source files containing coverage."`
}

func getCoverageFiles(ctx *aflow.Context, state reproduceState, args CoverageFilesArgs) (CoverageFilesResult, error) {
	coverage, err := readCoverage(ctx, args.CoverageID)
	if err != nil {
		return CoverageFilesResult{}, err
	}

	var files []string
	for _, callcov := range coverage {
		for _, frame := range callcov {
			if frame.File != "" {
				files = append(files, frame.File)
			}
		}
	}
	slices.Sort(files)
	files = slices.Compact(files)

	return CoverageFilesResult{Files: files}, nil
}

type FileCoverageArgs struct {
	CoverageID string `jsonschema:"CoverageID returned by the reproduce-crash tool."`
	Filename   string `jsonschema:"Name of the source file to inspect."`
}

type FileCoverageResult struct {
	Snippets []string `jsonschema:"List of formatted code snippets for each executed function in the requested file."`
}

func getFileCoverage(ctx *aflow.Context, state reproduceState, args FileCoverageArgs) (FileCoverageResult, error) {
	if !filepath.IsLocal(args.Filename) {
		return FileCoverageResult{}, aflow.BadCallError("filename must be a safe, local relative path")
	}

	coverage, err := readCoverage(ctx, args.CoverageID)
	if err != nil {
		return FileCoverageResult{}, err
	}

	funcLines := make(map[string][]int)
	for _, callcov := range coverage {
		for _, frame := range callcov {
			if frame.File == args.Filename && frame.Func != "" {
				funcLines[frame.Func] = append(funcLines[frame.Func], frame.Line)
			}
		}
	}

	if len(funcLines) == 0 {
		return FileCoverageResult{}, aflow.BadCallError("no coverage found for file: %v", args.Filename)
	}

	srcBytes, err := os.ReadFile(filepath.Join(state.KernelSrc, args.Filename))
	if err != nil {
		return FileCoverageResult{}, aflow.BadCallError("failed to read source file: %v", err)
	}
	srcLines := strings.Split(string(srcBytes), "\n")

	var res FileCoverageResult

	for fnName, lines := range funcLines {
		if len(lines) == 0 {
			continue
		}
		slices.Sort(lines)
		lines = slices.Compact(lines)
		minLine := lines[0]
		maxLine := lines[len(lines)-1]

		ctxPadding := 10
		start := max(1, minLine-ctxPadding)
		end := min(len(srcLines), maxLine+ctxPadding)

		var out strings.Builder
		fmt.Fprintf(&out, "Function: %v\n", fnName)
		for i := start; i <= end; i++ {
			prefix := "  "
			if _, hit := slices.BinarySearch(lines, i); hit {
				prefix = "* "
			}
			fmt.Fprintf(&out, "%s%4d: %s\n", prefix, i, srcLines[i-1])
		}
		res.Snippets = append(res.Snippets, out.String())
	}
	slices.Sort(res.Snippets)

	return res, nil
}

func readCoverage(ctx *aflow.Context, coverageID string) ([][]symbolizer.Frame, error) {
	if !filepath.IsLocal(coverageID) {
		return nil, aflow.BadCallError("invalid CoverageID: %v", coverageID)
	}
	frames, err := aflow.CacheReadObject[[][]symbolizer.Frame](ctx, "coverage", coverageID, "coverage.json")
	if err != nil {
		return nil, aflow.BadCallError("invalid or missing CoverageID: %v", coverageID)
	}
	return frames, nil
}
