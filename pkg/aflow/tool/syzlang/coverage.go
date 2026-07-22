// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package syzlang provides tools for analyzing syzlang coverage, descriptions, and reproduction.
package syzlang

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/syzlang"
	"github.com/google/syzkaller/pkg/symbolizer"
)

var (
	CoverageFiles = aflow.NewFuncTool("get-coverage-files", getCoverageFiles, `
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

	ExecutionTrace = aflow.NewFuncTool("get-execution-trace", getExecutionTrace, `
Tool returns the execution trace (chain of function calls) triggered by a specific program execution.
Because the raw trace is extremely large, it is compressed by keeping only unique functions
in their order of appearance, and filtering out kernel infrastructure noise.
You MUST provide 'SyscallIndex' (which corresponds to the 0-based line number in the syzlang program)
to get the trace for one specific syscall. Use -1 to get the trace for extra (background) coverage.
You can use 'GrepPattern' to filter trace lines matching a regular expression or substring pattern.
If the trace is too large, it will be truncated. You can use 'Offset' and 'Limit' to paginate through the omitted parts.
`)

	VerifyPCReached = aflow.NewFuncTool("check-pc-coverage", verifyPCReached, `
Tool evaluates whether an exact PC address was executed.
You MUST provide the exact target PC address as a hex string (e.g., '0xffffffff81b43437').
It automatically uses the last execution ID.
`)

	Coverage = []aflow.Tool{CoverageFiles, FileCoverage, ExecutionTrace, VerifyPCReached}
)

type CoverageFilesArgs struct {
	ExecutionCachedID string `jsonschema:"Cached ID returned by the reproduce-crash or execute-seed tool."`
}

type CoverageFilesResult struct {
	Files []string `jsonschema:"List of source files containing coverage."`
}

func getCoverageFiles(ctx *aflow.Context, state reproduceState, args CoverageFilesArgs) (CoverageFilesResult, error) {
	if args.ExecutionCachedID == "" {
		return CoverageFilesResult{}, aflow.BadCallError(
			"no previous execution found. You must execute a seed before requesting coverage.")
	}
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
	ExecutionCachedID string   `jsonschema:"Cached ID returned by the reproduce-crash or execute-seed tool."`
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
	if args.ExecutionCachedID == "" {
		return FileCoverageResult{}, aflow.BadCallError(
			"no previous execution found. You must execute a seed before requesting coverage.")
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

type ExecutionTraceArgs struct {
	ExecutionCachedID string `jsonschema:"Cached ID returned by the reproduce-crash or execute-seed tool."`
	SyscallIndex      int    `jsonschema:"REQUIRED: 0-based syscall index to inspect. Use -1 for extra coverage."`
	FilterSubsystem   string `jsonschema:"Optional: Filter output by file path prefix."`
	GrepPattern       string `jsonschema:"Optional: Regex or substring pattern to filter trace lines."`
	IncludeNoise      bool   `jsonschema:"Optional: Include low-level noisy functions (e.g., locks, allocators)."`
	Offset            int    `jsonschema:"Optional: Starting index for trace lines to return (0-based)."`
	Limit             int    `jsonschema:"Optional: Maximum number of trace lines to return."`
}

type SyscallTrace struct {
	CallIndex int      `jsonschema:"The index of the syscall in the syzkaller program. -1 for extra coverage."`
	Trace     []string `jsonschema:"The chain of function calls for this syscall."`
}

type ExecutionTraceResult struct {
	Traces []SyscallTrace `jsonschema:"The execution traces for the requested syscall(s)."`
}

func getExecutionTrace(
	ctx *aflow.Context, state reproduceState, args ExecutionTraceArgs) (ExecutionTraceResult, error) {
	if args.GrepPattern != "" {
		if _, err := regexp.Compile("(?i)" + args.GrepPattern); err != nil {
			return ExecutionTraceResult{}, aflow.BadCallError("invalid GrepPattern regex: %v", err)
		}
	}

	coverage, err := crash.LoadCoverage(ctx, args.ExecutionCachedID)
	if err != nil {
		return ExecutionTraceResult{}, aflow.BadCallError("failed to read coverage: %v", err)
	}

	baseSeedPath, _, err := crash.LoadSeedProgramDetails(ctx, args.ExecutionCachedID)
	if err != nil {
		return ExecutionTraceResult{}, aflow.BadCallError("failed to load program details: %v", err)
	}

	baseSeed := syzlang.BaseTestSeed{Path: baseSeedPath}
	if err := baseSeed.Load(state.Syzkaller, state.TargetOS); err != nil {
		return ExecutionTraceResult{}, err
	}

	baseCallsCount, err := syzlang.BaseSeedCallCount([]byte(baseSeed.Data), state.TargetArch)
	if err != nil {
		return ExecutionTraceResult{}, aflow.BadCallError("failed to get base test seed calls: %v", err)
	}

	var res ExecutionTraceResult

	idx := args.SyscallIndex
	if idx == -1 {
		idx = len(coverage) - 1
	} else {
		idx += baseCallsCount
	}

	if idx < baseCallsCount || idx >= len(coverage) {
		maxIdx := max(0, len(coverage)-baseCallsCount-2)
		return ExecutionTraceResult{},
			aflow.BadCallError("SyscallIndex %d is out of bounds (0-%d). Use -1 for extra coverage.", args.SyscallIndex, maxIdx)
	}
	res.Traces = append(res.Traces, processSyscallTrace(args.SyscallIndex, coverage[idx], args))
	return res, nil
}

func isNoiseFunction(name string) bool {
	prefixes := []string{
		"trace_",
		"printk_", "vprintk_", "console_",
		"rcu_", "__rcu_", "srcu_",
		"kasan_", "kcsan_", "kmsan_", "__asan_", "__msan_", "__tsan_", "__csan_",
		"arch_",
		"mutex_", "down_read", "up_read", "down_write", "up_write",
		"spin_lock", "spin_unlock", "__mutex_", "__spin_", "rwsem_",
		"lock_acquire", "lock_release",
		"preempt_", "local_irq_", "irq_",
		"fault_in_", "do_user_addr_fault",
		"__mmap_lock_",
		"kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free", "__kmalloc",
		"_copy_from_user", "_copy_to_user", "__arch_copy_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

type traceLine struct {
	Depth       int
	Func        string
	File        string
	ShouldPrint bool
}

func processSyscallTrace(idx int, callcov []symbolizer.Frame, args ExecutionTraceArgs) SyscallTrace {
	maxLines := 1000

	trace := SyscallTrace{CallIndex: idx}
	var stack []string
	var lines []traceLine
	maxDepth := 0

	for _, frame := range callcov {
		if frame.Func == "" {
			continue
		}

		top := len(stack) - 1
		if top >= 0 && stack[top] == frame.Func {
			continue
		}

		if i := slices.Index(stack, frame.Func); i != -1 {
			stack = stack[:i+1]
			continue
		}

		stack = append(stack, frame.Func)
		depth := len(stack)

		maxDepth = max(maxDepth, depth)

		matchesFilter := args.FilterSubsystem == "" || strings.HasPrefix(frame.File, args.FilterSubsystem)
		isNoise := isNoiseFunction(frame.Func) && !args.IncludeNoise

		shouldPrint := matchesFilter
		if isNoise && args.FilterSubsystem == "" {
			shouldPrint = false
		}

		lines = append(lines, traceLine{
			Depth:       depth,
			Func:        frame.Func,
			File:        frame.File,
			ShouldPrint: shouldPrint,
		})
	}

	var grepRe *regexp.Regexp
	if args.GrepPattern != "" {
		grepRe = regexp.MustCompile("(?i)" + args.GrepPattern)
	}

	var out []string
	lastSeenFunc := ""

	for _, line := range lines {
		isConsecutiveDuplicate := (line.Func == lastSeenFunc)
		lastSeenFunc = line.Func

		if isConsecutiveDuplicate {
			continue
		}

		// Provide an "exponential spine" of context and keep dense context at the
		// start of the call chain (setup) and at the very end of the call chain
		// (where the deepest execution / potential crash happened). We show
		// functions whose distance from the absolute maxDepth is a power of 2
		// (e.g., distances 0, 1, 2, 4, 8, 16, 32).
		diff := maxDepth - line.Depth
		isSpine := line.Depth <= 5 || (diff >= 0 && (diff&(diff-1)) == 0)

		if !line.ShouldPrint && !isSpine {
			continue
		}

		if grepRe != nil && !grepRe.MatchString(line.Func) && !grepRe.MatchString(line.File) {
			continue
		}

		suffix := ""
		if !line.ShouldPrint {
			suffix = " (context)"
		}
		out = append(out, fmt.Sprintf("[%d] %s%s", line.Depth, line.Func, suffix))
	}

	if args.Offset > 0 || args.Limit > 0 {
		out = paginateTrace(out, args.Offset, args.Limit, maxLines)
	} else if len(out) > maxLines {
		half := maxLines / 2
		newOut := make([]string, 0, maxLines+1)
		newOut = append(newOut, out[:half]...)

		omitted := len(out) - maxLines
		truncMsg := fmt.Sprintf("... [trace truncated. %d lines omitted (lines %d to %d). "+
			"Use the 'get-execution-trace' tool with Offset=%d and Limit=%d to view the hidden middle section.] ...",
			omitted, half, len(out)-half-1, half, maxLines)
		newOut = append(newOut, truncMsg)

		newOut = append(newOut, out[len(out)-half:]...)
		out = newOut
	}
	trace.Trace = out
	return trace
}

func paginateTrace(out []string, offset, limit, maxLines int) []string {
	if limit <= 0 {
		limit = maxLines
	}
	limit = min(limit, 2000)
	start := min(len(out), max(0, offset))
	end := min(len(out), start+limit)

	newOut := make([]string, 0, end-start+2)
	if start > 0 {
		msg := fmt.Sprintf("... [trace started from line %d. %d lines omitted before this] ...", start, start)
		newOut = append(newOut, msg)
	}

	newOut = append(newOut, out[start:end]...)

	if end < len(out) {
		msg := fmt.Sprintf("... [trace truncated. %d lines remaining. "+
			"Use get-execution-trace with Offset=%d and Limit=%d to view next part] ...",
			len(out)-end, end, limit)
		newOut = append(newOut, msg)
	}
	return newOut
}

type VerifyPCReachedArgs struct {
	ExecutionCachedID string `jsonschema:"Cached ID returned by the reproduce-crash or execute-seed tool."`
	PC                string `jsonschema:"The exact target PC address to verify (e.g., '0x123')."`
}

type VerifyPCReachedResult struct {
	PCReached bool `jsonschema:"True if the target PC was reached, false otherwise."`
}

func verifyPCReached(
	ctx *aflow.Context, state reproduceState, args VerifyPCReachedArgs) (VerifyPCReachedResult, error) {
	if args.ExecutionCachedID == "" {
		return VerifyPCReachedResult{}, aflow.BadCallError(
			"no previous execution found. You must execute a seed before requesting coverage.")
	}

	raw := strings.TrimSpace(args.PC)
	raw = strings.TrimPrefix(raw, "0x")
	pc, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return VerifyPCReachedResult{}, aflow.BadCallError("invalid PC format: %v", err)
	}

	reached, err := crash.CheckPCInCoverage(ctx, args.ExecutionCachedID, pc)
	if err != nil {
		return VerifyPCReachedResult{}, aflow.BadCallError("failed to check PC in coverage: %v", err)
	}

	return VerifyPCReachedResult{PCReached: reached}, nil
}
