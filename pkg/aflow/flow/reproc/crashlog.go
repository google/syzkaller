// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	// syzDataRe matches large data in syzkaller programs that can't contain quotes: base64-encoded compressed
	// data (e.g. filesystem images), and hex-encoded data (double-quoted strings in syzlang are always hex).
	syzDataRe = regexp.MustCompile(`"(?:\$[A-Za-z0-9+/=]{64,}|[0-9a-f]{256,})"`)
	// programHeaderRe matches program headers in crash logs, e.g. "1.2s ago: executing program 3 (id=7):".
	programHeaderRe = regexp.MustCompile(`executing program ([0-9]+)`)
	// programLineRe matches lines of serialized syzkaller programs (one call per line).
	programLineRe = regexp.MustCompile(`^(?:r[0-9]+ = )?[a-zA-Z0-9_$]+\(`)
)

type ExtractCrashLogProgramsArgs struct {
	TargetOS   string
	TargetArch string
	CrashLog   string
}

type ExtractCrashLogProgramsResult struct {
	CrashLogPrograms string
}

const (
	// Crash log programs are included into prompts of several agents on every iteration,
	// so keep them small.
	maxCrashLogPrograms     = 10
	maxCrashLogProgramsSize = 16 << 10
	maxCrashLogCallLen      = 2 << 10
	// Only the tail of the crash log is searched for programs.
	maxCrashLogTailSize = 4 << 20
)

// ExtractCrashLogProgramsFunc extracts the last distinct syzkaller programs executed before the crash
// from the crash log. Large data (e.g. filesystem images) and calls that are too long are omitted.
func ExtractCrashLogProgramsFunc(ctx *aflow.Context, args ExtractCrashLogProgramsArgs) (
	ExtractCrashLogProgramsResult, error) {
	if strings.TrimSpace(args.CrashLog) == "" {
		return ExtractCrashLogProgramsResult{}, nil
	}
	target, err := prog.GetTarget(args.TargetOS, args.TargetArch)
	if err != nil {
		// The crash log is just a hint, don't fail the whole workflow.
		ctx.Logf(0, "failed to extract crash log programs: %v", err)
		return ExtractCrashLogProgramsResult{}, nil
	}
	logProgs := splitCrashLog(args.CrashLog)
	var progs []string
	size := 0
	seen := make(map[string]bool)
	// Programs are parsed lazily starting from the last one, since only a few of them are used
	// (parsing may be slow for programs with filesystem images).
	for i := len(logProgs) - 1; i >= 0 && len(progs) < maxCrashLogPrograms; i-- {
		if seen[logProgs[i].text] {
			continue
		}
		seen[logProgs[i].text] = true
		p := parseCrashLogProgram(target, logProgs[i].text)
		if p == nil {
			continue
		}
		text := omitLongCalls(omitProgramData(escapeTags(string(p.Serialize()))))
		header := fmt.Sprintf("# Program executed by proc %v:\n", logProgs[i].proc)
		if size+len(header)+len(text) > maxCrashLogProgramsSize {
			if len(progs) != 0 {
				break
			}
			// Always include the last program, but truncate it to the budget.
			text = truncateProgram(text, maxCrashLogProgramsSize-len(header))
		}
		size += len(header) + len(text)
		progs = append(progs, header+text)
	}
	slices.Reverse(progs)
	return ExtractCrashLogProgramsResult{CrashLogPrograms: strings.Join(progs, "")}, nil
}

var ExtractCrashLogPrograms = aflow.NewFuncAction("extract-crash-log-programs", ExtractCrashLogProgramsFunc)

// parseCrashLogProgram parses a program from the crash log. If the program contains lines that
// can't be parsed (e.g. kernel output that looks like a call), they are skipped (this is slow
// for long programs, so it's used only as a fallback).
func parseCrashLogProgram(target *prog.Target, text string) *prog.Prog {
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		entries := target.ParseLog([]byte(text), prog.NonStrict)
		if len(entries) == 0 {
			return nil
		}
		p = entries[len(entries)-1].P
	}
	if len(p.Calls) == 0 {
		return nil
	}
	return p
}

type crashLogProgram struct {
	proc int
	text string
}

// splitCrashLog returns the programs from the tail of the crash log (in the order of execution).
// Only lines that look like syzkaller calls are kept, so kernel console output and other lines
// interleaved with the programs are dropped.
func splitCrashLog(log string) []crashLogProgram {
	if len(log) > maxCrashLogTailSize {
		log = log[len(log)-maxCrashLogTailSize:]
		log = log[strings.IndexByte(log, '\n')+1:]
	}
	var progs []crashLogProgram
	var cur *crashLogProgram
	var text strings.Builder
	flush := func() {
		if cur != nil && text.Len() != 0 {
			cur.text = text.String()
			progs = append(progs, *cur)
		}
		text.Reset()
	}
	for _, line := range strings.SplitAfter(log, "\n") {
		if programLineRe.MatchString(line) {
			if cur != nil {
				text.WriteString(line)
				if !strings.HasSuffix(line, "\n") {
					text.WriteString("\n")
				}
			}
			continue
		}
		if match := programHeaderRe.FindStringSubmatch(line); match != nil {
			flush()
			proc, _ := strconv.Atoi(match[1])
			cur = &crashLogProgram{proc: proc}
		}
	}
	flush()
	return progs
}

// escapeTags escapes '<' in a serialized program (it can appear only in strings, where "\x3c" means
// the same), so that the program can't close the tag it's embedded into in prompts.
func escapeTags(text string) string {
	return strings.ReplaceAll(text, "<", `\x3c`)
}

// omitProgramData replaces large data (e.g. filesystem images) in a serialized program with markers.
func omitProgramData(text string) string {
	return syzDataRe.ReplaceAllStringFunc(text, func(data string) string {
		return fmt.Sprintf(`"<omitted %v bytes of data>"`, len(data)-2)
	})
}

// omitLongCalls replaces calls that are too long to be included into prompts (e.g. calls with
// huge arrays) with a comment with the beginning of the call.
func omitLongCalls(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) > maxCrashLogCallLen {
			lines[i] = fmt.Sprintf("# [long call (%v bytes) omitted]: %.200s...", len(line), line)
		}
	}
	return strings.Join(lines, "\n")
}

// truncateProgram truncates the program to the size limit on a call boundary.
func truncateProgram(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	// Leave space for the marker.
	cut := strings.LastIndexByte(text[:limit-32], '\n') + 1
	return text[:cut] + fmt.Sprintf("# [%v more calls omitted]\n", strings.Count(text[cut:], "\n"))
}
