// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/tool/toolkit"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// Data blobs are replaced with placeholders in two different formats:
//   - in syzkaller programs (e.g. crash log programs) blobs are syzlang-encoded data
//     (hex or base64-encoded compressed data) or whole calls that are too long, they are
//     shown as "$SYZBLOB_<hash>" and can only be passed back to the syz-prog-to-c tool;
//   - in C programs blobs are C string literals, they are shown as "$BLOB_<hash>"
//     and are expanded before compilation.
//
// Both are stored in the context blob store, which uses the "$BLOB_<hash>" format.
const (
	cBlobPrefix   = `"$BLOB_`
	syzBlobPrefix = `"$SYZBLOB_`
)

var (
	// syzDataRe matches large data in syzkaller programs that can't contain quotes: base64-encoded compressed
	// data (e.g. filesystem images), and hex-encoded data (double-quoted strings in syzlang are always hex).
	syzDataRe = regexp.MustCompile(`"(?:\$[A-Za-z0-9+/=]{64,}|[0-9a-f]{256,})"`)
	// cLiteralRe matches a sequence of adjacent C string literals on a single line.
	cLiteralRe = regexp.MustCompile(`"(?:[^"\\\n]|\\.)*"(?:[ \t]*"(?:[^"\\\n]|\\.)*")*`)
	// syzDataOnlyRe matches strings that consist of syzlang-encoded data only.
	syzDataOnlyRe = regexp.MustCompile(`^(?:` + syzDataRe.String() + `)$`)
	// cBlobRe matches placeholders in C programs.
	cBlobRe = regexp.MustCompile(`"\$BLOB_[a-f0-9]{12}"`)
	// anyBlobRe matches placeholders of both formats (with or without quotes).
	anyBlobRe = regexp.MustCompile(`\$(?:SYZ)?BLOB_[a-f0-9]{12}`)
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
	maxCrashLogProgramBytes = 16 << 10
	maxCrashLogLineLen      = 2 << 10
	// Parse only the part of the crash log with the last programs (with headroom for duplicates
	// and programs that fail to parse).
	maxCrashLogTailPrograms = 4 * maxCrashLogPrograms
	// Limits for the converted and expanded programs: the conversion result stays in the agent's
	// context, and the final reproducer is stored in the dashboard database.
	maxSyzProgToCLen = 64 << 10
	maxExpandedLen   = 6 << 20
)

// consoleLineRe matches kernel console lines (e.g. "[  12.345678][ T1234] ...") in crash logs.
var consoleLineRe = regexp.MustCompile(`^\[ *[0-9]+\.[0-9]+\]`)

// ExtractCrashLogProgramsFunc extracts the last syzkaller programs executed before the crash
// from the crash log. Large data blobs (e.g. filesystem images) are replaced with placeholders.
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
	entries := target.ParseLog(crashLogTail([]byte(args.CrashLog)), prog.NonStrict)
	var progs []string
	size := 0
	seen := make(map[string]bool)
	for i := len(entries) - 1; i >= 0 && len(progs) < maxCrashLogPrograms; i-- {
		serialized := string(entries[i].P.Serialize())
		if seen[serialized] {
			continue
		}
		seen[serialized] = true
		text := replaceLongCalls(ctx, replaceProgramBlobs(ctx, serialized))
		if size+len(text) > maxCrashLogProgramBytes {
			if len(progs) != 0 {
				break
			}
			// Always include the last program, but truncate it to the budget.
			text = truncateProgram(text, maxCrashLogProgramBytes)
		}
		size += len(text)
		progs = append(progs, fmt.Sprintf("# Program executed by proc %v:\n%s", entries[i].Proc, text))
	}
	slices.Reverse(progs)
	return ExtractCrashLogProgramsResult{CrashLogPrograms: strings.Join(progs, "\n")}, nil
}

var ExtractCrashLogPrograms = aflow.NewFuncAction("extract-crash-log-programs", ExtractCrashLogProgramsFunc)

// crashLogTail returns the part of the crash log that contains the last programs, without kernel
// console lines. ParseLog re-parses the current program (and decompresses its images) on every
// following line, so parsing whole logs with console output after large programs takes minutes.
func crashLogTail(data []byte) []byte {
	const header = "executing program "
	start, end := 0, len(data)
	for range maxCrashLogTailPrograms {
		pos := bytes.LastIndex(data[:end], []byte(header))
		if pos == -1 {
			break
		}
		start = bytes.LastIndexByte(data[:pos], '\n') + 1
		end = start
	}
	var b bytes.Buffer
	for _, line := range bytes.SplitAfter(data[start:], []byte("\n")) {
		if consoleLineRe.Match(line) && !bytes.Contains(line, []byte(header)) {
			continue
		}
		b.Write(line)
	}
	return b.Bytes()
}

// replaceProgramBlobs replaces large data blobs in a serialized syzkaller program with "$SYZBLOB_" placeholders.
func replaceProgramBlobs(ctx *aflow.Context, text string) string {
	return syzDataRe.ReplaceAllStringFunc(text, func(data string) string {
		return strings.Replace(ctx.ReplaceBlobs(data), cBlobPrefix, syzBlobPrefix, 1)
	})
}

// restoreProgramBlobs restores "$SYZBLOB_" placeholders in a syzkaller program.
func restoreProgramBlobs(ctx *aflow.Context, text string) (string, error) {
	// Long call placeholders may contain data placeholders, so restore twice.
	for range 2 {
		text = strings.ReplaceAll(text, syzBlobPrefix, cBlobPrefix)
		if err := checkExpandedSize(ctx, text); err != nil {
			return "", err
		}
		text = ctx.RestoreBlobs(text)
	}
	return text, nil
}

// checkExpandedSize checks that text is not too large after restoring "$BLOB_" placeholders
// (placeholders may be repeated, and each of them may stand for megabytes of data).
func checkExpandedSize(ctx *aflow.Context, text string) error {
	size := len(text)
	blobSizes := make(map[string]int)
	for _, placeholder := range cBlobRe.FindAllString(text, -1) {
		blobSize, ok := blobSizes[placeholder]
		if !ok {
			blobSize = len(ctx.RestoreBlobs(placeholder))
			blobSizes[placeholder] = blobSize
		}
		size += blobSize - len(placeholder)
	}
	if size > maxExpandedLen {
		return fmt.Errorf("the program is too large after expanding data placeholders (%v MiB, the limit is "+
			"%v MiB); don't repeat placeholders (e.g. use loops instead), and use smaller data",
			size>>20, maxExpandedLen>>20)
	}
	return nil
}

// replaceLongCalls replaces calls that are too long to be included into prompts (e.g. calls with
// huge arrays) with "$SYZBLOB_" placeholders preceded by a comment with the beginning of the call.
func replaceLongCalls(ctx *aflow.Context, text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) > maxCrashLogLineLen {
			placeholder := strings.Replace(ctx.RegisterBlob(line), cBlobPrefix, syzBlobPrefix, 1)
			// Don't show nested placeholders in the comment, they would be restored as well.
			preview, _, _ := strings.Cut(line, syzBlobPrefix)
			lines[i] = fmt.Sprintf("# [long call (%v bytes) replaced with a placeholder]: %.200s...\n%v",
				len(line), preview, placeholder)
		}
	}
	return strings.Join(lines, "\n")
}

// truncateProgram truncates the program to the size limit on a call boundary.
func truncateProgram(text string, limit int) string {
	lines := strings.SplitAfter(text, "\n")
	size := 0
	for i, line := range lines {
		if size+len(line) > limit {
			return strings.Join(lines[:i], "") + fmt.Sprintf("# [%v more calls omitted]\n", len(lines)-i)
		}
		size += len(line)
	}
	return text
}

type syzProgToCState struct {
	TargetOS   string
	TargetArch string
}

type syzProgToCArgs struct {
	Program string `jsonschema:"Syzkaller program (e.g. a crash log program)."`
}

type syzProgToCResult struct {
	CProgram string `jsonschema:"Standalone C program that executes the syzkaller program."`
}

var ToolSyzProgToC = aflow.NewFuncTool("syz-prog-to-c", syzProgToC,
	"Converts a syzkaller program (e.g. a program from the crash log) into a standalone C program. "+
		"The result contains all helper code required by the program (e.g. to mount filesystem images or "+
		"to emulate USB devices); long helper code is collapsed into a single \"// SYZ_HELPERS\" marker line. "+
		"Large data in the C program is shown as \"$BLOB_<hash>\" placeholders. "+
		"Keep the marker and the placeholders verbatim: they are expanded automatically before compilation.")

func syzProgToC(ctx *aflow.Context, state syzProgToCState, args syzProgToCArgs) (syzProgToCResult, error) {
	target, err := prog.GetTarget(state.TargetOS, state.TargetArch)
	if err != nil {
		return syzProgToCResult{}, err
	}
	text, err := restoreProgramBlobs(ctx, args.Program)
	if err != nil {
		return syzProgToCResult{}, aflow.BadCallError("%v", err)
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		// The error contains the failing line with restored data blobs, which may be huge.
		return syzProgToCResult{}, aflow.BadCallError("failed to parse the program: %v",
			truncateMessage(replaceProgramBlobs(ctx, err.Error())))
	}
	src, err := csource.Write(p, syzProgToCOptions(p))
	if err != nil {
		return syzProgToCResult{}, aflow.BadCallError("failed to convert the program to C: %v", err)
	}
	c := replaceCBlobs(ctx, collapseHelpers(ctx, string(src)))
	if len(c) > maxSyzProgToCLen {
		return syzProgToCResult{}, aflow.BadCallError("the C program is too large (%v KiB, the limit is %v KiB); "+
			"remove calls that are not needed for the reproduction, or reduce large arrays",
			len(c)>>10, maxSyzProgToCLen>>10)
	}
	return syzProgToCResult{CProgram: c}, nil
}

// Keep small data (e.g. USB descriptors, netlink messages) inline, so that agents can modify it.
const minCBlobLen = 1024

// replaceCBlobs replaces large string literals in code (but not in comments) with placeholders.
func replaceCBlobs(ctx *aflow.Context, src string) string {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		lines[i] = cLiteralRe.ReplaceAllStringFunc(line, func(literal string) string {
			if len(literal) < minCBlobLen {
				return literal
			}
			return ctx.ReplaceBlobs(literal)
		})
	}
	return strings.Join(lines, "\n")
}

const (
	helpersMarker = "// SYZ_HELPERS "
	// helpersBlobPrefix distinguishes helper code from data in the blob store.
	helpersBlobPrefix       = "// SYZ_HELPERS CODE\n"
	minCollapsedHelperLines = 50
	helperNamesLineLen      = 100
)

var (
	// helpersMarkerRe matches the marker line produced by collapseHelpers.
	// The marker contains a bare blob hash, so that generic blob restoration never touches it.
	helpersMarkerRe = regexp.MustCompile(`(?m)^[ \t]*// SYZ_HELPERS ([a-f0-9]{12})[ \t]*$`)
	// helperFuncRe matches the first line of a static function definition, e.g.
	// "static long syz_mount_image(" (prototypes end with ';' and are not matched).
	helperFuncRe = regexp.MustCompile(`(?m)^static [^;=\n]*?(\w+)\([^;\n]*$`)
	// programStartRe matches the first line after the helper code in csource output.
	programStartRe = regexp.MustCompile(`(?m)^(uint64_t r\[|void loop\(void\)|void execute_call\(|int main\()`)
)

// collapseHelpers replaces syzkaller helper code (which may be thousands of lines long, e.g. for USB
// emulation) in a C program generated by csource with a single marker line, so that agents don't
// need to reproduce it in their outputs. expandCandidate performs the reverse transformation.
func collapseHelpers(ctx *aflow.Context, src string) string {
	loc := programStartRe.FindStringIndex(src)
	if loc == nil {
		return src
	}
	head := src[:loc[0]]
	// The helper code starts right after the last #include line.
	// Note: the index in "\n"+head of the newline before the line is the index of the line in head.
	incPos := strings.LastIndex("\n"+head, "\n#include ")
	if incPos == -1 {
		return src
	}
	incLineLen := strings.IndexByte(head[incPos:], '\n')
	if incLineLen == -1 {
		return src
	}
	incEnd := incPos + incLineLen + 1
	helpers := head[incEnd:]
	if strings.Count(helpers, "\n") < minCollapsedHelperLines {
		return src
	}
	hash := blobHash(ctx.RegisterBlob(helpersBlobPrefix + helpers))
	var b strings.Builder
	b.WriteString(head[:incEnd])
	fmt.Fprintf(&b, "\n%v%v\n", helpersMarker, hash)
	b.WriteString("// The line above is replaced with syzkaller helper code before compilation, keep it verbatim.\n")
	b.WriteString("// It defines the following static functions:\n//")
	lineLen := 2
	names := helperFuncRe.FindAllStringSubmatch(helpers, -1)
	for i, match := range names {
		item := " " + match[1] + ","
		if i == len(names)-1 {
			item = " " + match[1] + "."
		}
		if lineLen+len(item) > helperNamesLineLen {
			b.WriteString("\n//")
			lineLen = 2
		}
		b.WriteString(item)
		lineLen += len(item)
	}
	b.WriteString("\n\n")
	b.WriteString(src[loc[0]:])
	return b.String()
}

// blobHash extracts the hash from a "$BLOB_<hash>" placeholder.
func blobHash(placeholder string) string {
	return strings.TrimSuffix(strings.TrimPrefix(placeholder, cBlobPrefix), `"`)
}

// expandCandidate expands the race toolkit include, the helper code marker and data blob placeholders
// in a candidate C program.
func expandCandidate(ctx *aflow.Context, src string) (string, error) {
	if hashes := helpersMarkerRe.FindAllStringSubmatch(src, -1); len(hashes) > 1 {
		for _, h := range hashes[1:] {
			if h[1] != hashes[0][1] {
				return "", fmt.Errorf("the program contains several different \"// SYZ_HELPERS\" markers; " +
					"merge the calls of all required syzkaller programs into a single program, convert it " +
					"with a single syz-prog-to-c call and keep only its marker")
			}
		}
	}
	if err := checkCBlobs(ctx, src); err != nil {
		return "", err
	}
	var b strings.Builder
	insert := func(code string) {
		b.WriteString(code)
		if !strings.HasSuffix(code, "\n") {
			b.WriteString("\n")
		}
	}
	helpersInserted := false
	for _, line := range strings.SplitAfter(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == raceToolkitInclude {
			insert(toolkit.GetRaceToolkit())
			continue
		}
		if match := helpersMarkerRe.FindStringSubmatch(strings.TrimRight(line, "\n")); match != nil {
			if helpersInserted {
				continue
			}
			placeholder := cBlobPrefix + match[1] + `"`
			code, ok := strings.CutPrefix(ctx.RestoreBlobs(placeholder), helpersBlobPrefix)
			if !ok {
				return "", fmt.Errorf("unknown \"// SYZ_HELPERS\" marker %v; use only markers returned by "+
					"the tools verbatim", match[1])
			}
			insert(code)
			helpersInserted = true
			continue
		}
		b.WriteString(strings.ReplaceAll(line, raceToolkitInclude, toolkit.GetRaceToolkit()))
	}
	if err := checkExpandedSize(ctx, b.String()); err != nil {
		return "", err
	}
	expanded := ctx.RestoreBlobs(b.String())
	if unknown := anyBlobRe.FindAllString(expanded, -1); len(unknown) != 0 {
		return "", fmt.Errorf("unknown or misplaced data blob placeholders: %v; use only \"$BLOB_<hash>\" "+
			"placeholders returned by syz-prog-to-c verbatim (including the quotes); \"$SYZBLOB_<hash>\" "+
			"placeholders can't be used in C, convert the program with syz-prog-to-c instead",
			strings.Join(slices.Compact(slices.Sorted(slices.Values(unknown))), ", "))
	}
	return expanded, nil
}

// checkCBlobs checks that "$BLOB_" placeholders in a C program refer to C data blobs
// (and not to syzlang data, long calls, or helper code that share the blob store).
func checkCBlobs(ctx *aflow.Context, src string) error {
	for _, placeholder := range cBlobRe.FindAllString(src, -1) {
		restored := ctx.RestoreBlobs(placeholder)
		if restored != placeholder && (!strings.HasPrefix(restored, `"`) || syzDataOnlyRe.MatchString(restored)) {
			return fmt.Errorf("placeholder %v does not refer to C data; use only \"$BLOB_<hash>\" "+
				"placeholders returned by syz-prog-to-c verbatim; \"$SYZBLOB_<hash>\" placeholders "+
				"can't be used in C, convert the program with syz-prog-to-c instead", placeholder)
		}
	}
	return nil
}

const (
	maxErrorLen     = 16 << 10
	maxErrorLineLen = 200
)

// compilerError returns compiler diagnostics without the program source that csource includes
// into the error (the source may contain expanded helper code and data blobs).
func compilerError(err error, src string) string {
	return truncateMessage(strings.Replace(err.Error(), src, "", 1))
}

// truncateMessage truncates long lines and the total length of an error message.
func truncateMessage(msg string) string {
	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		if len(line) > maxErrorLineLen {
			lines[i] = line[:maxErrorLineLen] + " ... [truncated]"
		}
	}
	msg = strings.Join(lines, "\n")
	if len(msg) > maxErrorLen {
		msg = msg[:maxErrorLen] + "\n... [truncated]"
	}
	return msg
}

// RunCandidate runs the candidate reproducer after expanding helper code and data blobs.
// The expansion is done here (rather than kept in the workflow state) to avoid recording
// potentially multi-megabyte programs in every trajectory span.
var RunCandidate = aflow.NewFuncAction("run-c-candidate",
	func(ctx *aflow.Context, args crash.RunCReproArgs) (crash.RunCReproResult, error) {
		expanded, err := expandCandidate(ctx, args.FormattedReproC)
		if err != nil {
			return crash.RunCReproResult{}, err
		}
		args.FormattedReproC = expanded
		return crash.RunCReproFunc(ctx, args)
	})

func syzProgToCOptions(p *prog.Prog) csource.Options {
	opts := csource.Options{
		Procs:      1,
		Slowdown:   1,
		Sandbox:    "none",
		UseTmpDir:  true,
		HandleSegv: true,
	}
	for _, c := range p.Calls {
		name := c.Meta.CallName
		switch {
		case strings.HasPrefix(name, "syz_usb_"):
			opts.USB = true
		case name == "syz_emit_ethernet" || name == "syz_extract_tcp_res":
			opts.NetInjection = true
		case name == "syz_emit_vhci":
			opts.VhciInjection = true
		case strings.HasPrefix(name, "syz_80211_"):
			opts.Wifi = true
		}
	}
	return opts
}
