// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package syzlang provides tools for analyzing syzlang coverage, descriptions, and reproduction.
package syzlang

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
)

var (
	coverageFiles = aflow.NewFuncTool("get-coverage-files", getCoverageFiles, `
Tool returns a list of source files that were covered during a crash reproducer run.
The list is deduplicated and sorted, presenting a high-level summary of the covered code regions.
`)

	FileCoverage = aflow.NewFuncTool("get-file-coverage", getFileCoverage, `
Tool evaluates code coverage for a specific file and returns coverage snippets highlighting the executed lines.
By default, it will dump the executed source lines with short context for each function that had hits.
You can use the 'Functions' argument to request snippets for a specific subset of functions.
Covered lines are prefixed with '* '.
If the total output exceeds the maximum line limit, it will be truncated. Use 'Functions' to narrow down your request.
`)

	Coverage = []aflow.Tool{coverageFiles, FileCoverage}
)

type CoverageFilesArgs struct {
	ExecutionCachedID string `jsonschema:"Cached ID returned by the reproduce-crash or execute-seed tool."`
}

type CoverageFilesResult struct {
	Files []string `jsonschema:"List of source files containing coverage."`
}

func getCoverageFiles(ctx *aflow.Context, state reproduceState, args CoverageFilesArgs) (CoverageFilesResult, error) {
	coverage, err := crash.LoadCoverage(ctx, args.ExecutionCachedID)
	if err != nil {
		return CoverageFilesResult{}, aflow.BadCallError("failed to read coverage: %v", err)
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
	ExecutionCachedID string   `jsonschema:"Cached ID returned by the reproduce-crash tool."`
	Filename          string   `jsonschema:"Name of the source file to inspect."`
	Functions         []string `jsonschema:"Optional list of functions. If empty, returns all."`
}

type FileCoverageResult struct {
	CoveredFunctions []string `jsonschema:"List of all executed functions in the requested file."`
	Snippets         []string `jsonschema:"List of formatted code snippets for the requested functions."`
}

const (
	fileCoverageMaxTotalLines = 1000
	fileCoverageCtxPadding    = 10
)

type coverageFormatter struct {
	srcLines       []string
	remainingLines int
	snippets       []string
	truncated      bool
}

func newCoverageFormatter(srcLines []string, maxLines int) *coverageFormatter {
	return &coverageFormatter{
		srcLines:       srcLines,
		remainingLines: maxLines,
	}
}

// addFunction adds a snippet for the given function. Returns true if the global
// limit was reached (truncated).
func (f *coverageFormatter) addFunction(fnName string, coveredLines []int) bool {
	start, end := f.calculateBounds(coveredLines)

	actualEnd := f.applyLimits(start, end)
	snippet := f.buildSnippet(fnName, start, actualEnd, coveredLines)
	if snippet != "" {
		f.snippets = append(f.snippets, snippet)
	}

	return f.truncated
}

// calculateBounds determines the starting and ending lines by adding context
// padding around the minimum and maximum covered lines.
func (f *coverageFormatter) calculateBounds(lines []int) (start, end int) {
	minLine := lines[0]
	maxLine := lines[len(lines)-1]
	end = min(len(f.srcLines), maxLine+fileCoverageCtxPadding)
	start = min(end, max(1, minLine-fileCoverageCtxPadding))
	return start, end
}

// applyLimits computes how many lines can actually be rendered based on the
// remaining lines allowed. It updates the remainingLines state and returns the
// actual end line. It sets f.truncated if truncation occurred.
func (f *coverageFormatter) applyLimits(start, end int) int {
	linesInSnippet := end - start + 1
	consumedLines := linesInSnippet
	if linesInSnippet > f.remainingLines {
		consumedLines = max(0, f.remainingLines)
		f.truncated = true
	}
	f.remainingLines -= consumedLines
	return start + consumedLines - 1
}

// buildSnippet constructs the final formatted snippet string using a
// strings.Builder, prefixing covered lines with a marker and appending a
// truncation message if f.truncated is true.
func (f *coverageFormatter) buildSnippet(fnName string, start, end int, lines []int) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Function: %v\n", fnName)

	for i := start; i <= end; i++ {
		prefix := "  "
		if _, hit := slices.BinarySearch(lines, i); hit {
			prefix = "* "
		}
		fmt.Fprintf(&out, "%s%4d: %s\n", prefix, i, f.srcLines[i-1])
	}

	if f.truncated {
		fmt.Fprintf(&out, "[Truncated due to reaching maximum line limit. Use 'Functions' to narrow your query]\n")
	}

	return out.String()
}

func getFileCoverage(ctx *aflow.Context, state reproduceState, args FileCoverageArgs) (FileCoverageResult, error) {
	if !filepath.IsLocal(args.Filename) {
		return FileCoverageResult{}, aflow.BadCallError("filename must be a safe, local relative path")
	}

	coverage, err := crash.LoadCoverage(ctx, args.ExecutionCachedID)
	if err != nil {
		return FileCoverageResult{}, aflow.BadCallError("failed to read coverage: %v", err)
	}

	funcLines := make(map[string][]int)
	for _, callcov := range coverage {
		for _, frame := range callcov {
			filePath := frame.File
			if filePath == args.Filename && frame.Func != "" {
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

	for fnName := range funcLines {
		res.CoveredFunctions = append(res.CoveredFunctions, fnName)
	}
	slices.Sort(res.CoveredFunctions)

	formatter := newCoverageFormatter(srcLines, fileCoverageMaxTotalLines)

	for _, fnName := range res.CoveredFunctions {
		lines := funcLines[fnName]
		if len(args.Functions) > 0 && !slices.Contains(args.Functions, fnName) {
			continue
		}
		if len(lines) == 0 {
			continue
		}
		slices.Sort(lines)
		lines = slices.Compact(lines)

		if formatter.addFunction(fnName, lines) {
			break
		}
	}

	res.Snippets = formatter.snippets

	if len(args.Functions) > 0 {
		for _, fn := range args.Functions {
			if !slices.Contains(res.CoveredFunctions, fn) {
				msg := fmt.Sprintf("%v: [No coverage found or function does not exist]\n", fn)
				res.Snippets = append(res.Snippets, msg)
			}
		}
	}

	return res, nil
}
