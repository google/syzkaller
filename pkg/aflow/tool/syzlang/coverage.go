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
			"No ExecutionCachedID provided. You must execute a seed before " +
				"requesting coverage and provide the ExecutionCachedID.")
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
	GrepPattern       string `jsonschema:"Optional: Filter trace lines by function or file path regex or substring."`
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
	if len(coverage) == 0 {
		return ExecutionTraceResult{}, aflow.BadCallError("no coverage data available")
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
		if idx < baseCallsCount || idx >= len(coverage)-1 {
			maxIdx := max(0, len(coverage)-baseCallsCount-2)
			return ExecutionTraceResult{},
				aflow.BadCallError("SyscallIndex %d is out of bounds (0-%d). Use -1 for extra coverage.", args.SyscallIndex, maxIdx)
		}
	}
	res.Traces = append(res.Traces, processSyscallTrace(args.SyscallIndex, coverage[idx], args))
	return res, nil
}

const executionTraceMaxLines = 1000

var noisePrefixes = []string{
	"trace_",
	"printk_", "vprintk_", "console_",
	"rcu_", "__rcu_", "srcu_",
	"kasan_", "kcsan_", "kmsan_", "__asan_", "__msan_", "__tsan_", "__csan_",
	"arch_spin_", "arch_raw_spin_", "arch_read_lock", "arch_write_lock",
	"arch_mutex_", "arch_local_irq_", "arch_atomic", "arch_cmpxchg",
	"arch_cpu_", "arch_static_branch",
	"mutex_", "down_read", "up_read", "down_write", "up_write",
	"spin_lock", "spin_unlock", "__mutex_", "__spin_", "rwsem_",
	"read_lock", "read_unlock", "write_lock", "write_unlock", "raw_spin_lock", "raw_spin_unlock",
	"lock_acquire", "lock_release",
	"preempt_", "local_irq_", "irq_",
	"fault_in_", "do_user_addr_fault",
	"__mmap_lock_",
	"kmalloc", "kfree", "kmem_cache_alloc", "kmem_cache_free", "__kmalloc",
	"_copy_from_user", "_copy_to_user", "__arch_copy_",
	"cond_resched", "might_sleep", "__might_sleep", "should_resched",
}

func isNoiseFunction(name string) bool {
	for _, p := range noisePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

type traceLine struct {
	PC               uint64
	Func             string
	File             string
	Line             int
	MatchesSubsystem bool
	IsNoise          bool
}

func (line traceLine) shouldPrint(args ExecutionTraceArgs) bool {
	if args.FilterSubsystem == "" {
		return !line.IsNoise || args.IncludeNoise
	}
	return line.MatchesSubsystem
}

func formatTraceLine(line traceLine, suffix string) string {
	var loc string
	if line.File != "" {
		if line.Line > 0 {
			loc = fmt.Sprintf(" (%s:%d)", line.File, line.Line)
		} else {
			loc = fmt.Sprintf(" (%s)", line.File)
		}
	}
	var pcStr string
	if line.PC != 0 {
		pcStr = fmt.Sprintf(" [0x%x]", line.PC)
	}
	return fmt.Sprintf("%s%s%s%s", line.Func, loc, pcStr, suffix)
}

func processSyscallTrace(idx int, callcov []symbolizer.Frame, args ExecutionTraceArgs) SyscallTrace {
	trace := SyscallTrace{CallIndex: idx}
	var lines []traceLine
	var lastFunc string

	for _, frame := range callcov {
		if frame.Func == "" || frame.Func == lastFunc {
			continue
		}
		lastFunc = frame.Func

		matchesSub := args.FilterSubsystem != "" && strings.HasPrefix(frame.File, args.FilterSubsystem)
		isNoise := isNoiseFunction(frame.Func)

		lines = append(lines, traceLine{
			PC:               frame.PC,
			Func:             frame.Func,
			File:             frame.File,
			Line:             frame.Line,
			MatchesSubsystem: matchesSub,
			IsNoise:          isNoise,
		})
	}

	var grepRe *regexp.Regexp
	if args.GrepPattern != "" {
		grepRe = regexp.MustCompile("(?i)" + args.GrepPattern)
	}

	var out []string
	hasFilter := grepRe != nil || args.FilterSubsystem != ""

	if hasFilter {
		out = filterTraceWithContext(lines, grepRe, args)
	} else {
		out = formatDefaultTrace(lines, args)
	}

	if len(out) == 0 {
		if args.SyscallIndex == -1 {
			out = []string{"[no extra background coverage (SyscallIndex: -1) was recorded during this execution run]"}
		} else {
			out = []string{fmt.Sprintf("[no execution trace recorded for syscall index %d]", args.SyscallIndex)}
		}
	}

	if args.Offset > 0 || args.Limit > 0 {
		out = paginateTrace(out, args.Offset, args.Limit, executionTraceMaxLines)
	} else if len(out) > executionTraceMaxLines {
		out = truncateTrace(out, executionTraceMaxLines)
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

func findDirectMatches(lines []traceLine, grepRe *regexp.Regexp, args ExecutionTraceArgs) ([]bool, int) {
	isDirectMatch := make([]bool, len(lines))
	matchCount := 0

	for i, line := range lines {
		matchesGrep := grepRe == nil || grepRe.MatchString(line.Func) || grepRe.MatchString(line.File)

		if line.shouldPrint(args) && matchesGrep {
			isDirectMatch[i] = true
			matchCount++
		}
	}
	return isDirectMatch, matchCount
}

func filterTraceWithContext(lines []traceLine, grepRe *regexp.Regexp, args ExecutionTraceArgs) []string {
	if len(lines) == 0 {
		return nil
	}

	isDirectMatch, matchCount := findDirectMatches(lines, grepRe, args)

	var out []string

	// If no matches found in this trace, return head (10) and tail (10) context frames.
	if matchCount == 0 {
		headCount, tailCount := 10, 10
		if len(lines) <= headCount+tailCount {
			for _, line := range lines {
				out = append(out, formatTraceLine(line, " (context)"))
			}
			return out
		}
		for i := range headCount {
			out = append(out, formatTraceLine(lines[i], " (context)"))
		}
		omitted := len(lines) - (headCount + tailCount)
		out = append(out, fmt.Sprintf("... [no filter match; %d lines omitted] ...", omitted))
		for i := len(lines) - tailCount; i < len(lines); i++ {
			out = append(out, formatTraceLine(lines[i], " (context)"))
		}
		return out
	}

	// Direct matches found: include Syscall Entry Frame (Frame 0), 3 Parents, 3 Children, and Matches.
	keep := make([]bool, len(lines))
	keep[0] = true // Syscall Entry Frame.

	for i := range lines {
		if isDirectMatch[i] {
			keep[i] = true
			for p := max(0, i-3); p < i; p++ {
				keep[p] = true // Up to 3 Parent Callers.
			}
			for c := i + 1; c <= min(len(lines)-1, i+3); c++ {
				keep[c] = true // Up to 3 Child Callees.
			}
		}
	}

	var lastSeenFunc string

	for i, line := range lines {
		if !keep[i] {
			continue
		}
		// Skip low-level noise functions in context frames unless they are direct matches
		// or they belong to the explicitly requested subsystem filter.
		isNoise := line.IsNoise && !args.IncludeNoise
		if isNoise && !line.MatchesSubsystem && !isDirectMatch[i] {
			continue
		}
		// Deduplicate consecutive hits of the same function to compress the trace.
		// However, always print direct matches to ensure matching frames are highlighted.
		if line.Func == lastSeenFunc && !isDirectMatch[i] {
			continue
		}
		lastSeenFunc = line.Func

		if isDirectMatch[i] {
			suffix := ""
			if grepRe != nil {
				suffix = "  <-- MATCH"
			}
			out = append(out, formatTraceLine(line, suffix))
		} else {
			out = append(out, formatTraceLine(line, " (context)"))
		}
	}

	return out
}

func formatDefaultTrace(lines []traceLine, args ExecutionTraceArgs) []string {
	var out []string
	var lastSeenFunc string

	for _, line := range lines {
		if !line.shouldPrint(args) {
			continue
		}
		if line.Func == lastSeenFunc {
			continue
		}
		lastSeenFunc = line.Func

		out = append(out, formatTraceLine(line, ""))
	}
	return out
}

func truncateTrace(out []string, maxLines int) []string {
	half := maxLines / 2
	newOut := make([]string, 0, maxLines+1)
	newOut = append(newOut, out[:half]...)

	omitted := len(out) - maxLines
	truncMsg := fmt.Sprintf("... [trace truncated. %d lines omitted (lines %d to %d). "+
		"Use the 'get-execution-trace' tool with Offset=%d and Limit=%d to view the hidden middle section.] ...",
		omitted, half, len(out)-half-1, half, maxLines)
	newOut = append(newOut, truncMsg)

	newOut = append(newOut, out[len(out)-half:]...)
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
