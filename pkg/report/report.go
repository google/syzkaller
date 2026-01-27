// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package report contains functions that process kernel output,
// detect/extract crash messages, symbolize them, etc.
package report

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
	"github.com/ianlancetaylor/demangle"
)

type reporterImpl interface {
	// ContainsCrash searches kernel console output for oops messages.
	ContainsCrash(output []byte) bool

	// Parse extracts information about oops from console output.
	// Returns nil if no oops found.
	Parse(output []byte) *Report

	// Symbolize symbolizes rep.Report and fills in Maintainers.
	Symbolize(rep *Report) error
}

type Reporter struct {
	typ          string
	impl         reporterImpl
	suppressions []*regexp.Regexp
	interests    []*regexp.Regexp
}

type Report struct {
	// Title contains a representative description of the first oops.
	Title string
	// Alternative titles, used for better deduplication.
	// If two crashes have a non-empty intersection of Title/AltTitles, they are considered the same bug.
	AltTitles []string
	// Bug type (e.g. hang, memory leak, etc).
	Type crash.Type
	// The indicative function name.
	Frame string
	// Report contains whole oops text.
	Report []byte
	// Output contains whole raw console output as passed to Reporter.Parse.
	Output []byte
	// StartPos/EndPos denote region of output with oops message(s).
	StartPos int
	EndPos   int
	// SkipPos is position in output where parsing for the next report should start.
	SkipPos int
	// Suppressed indicates whether the report should not be reported to user.
	Suppressed bool
	// Corrupted indicates whether the report is truncated of corrupted in some other way.
	Corrupted bool
	// CorruptedReason contains reason why the report is marked as corrupted.
	CorruptedReason string
	// Recipients is a list of RecipientInfo with Email, Display Name, and type.
	Recipients vcs.Recipients
	// GuiltyFile is the source file that we think is to blame for the crash  (filled in by Symbolize).
	GuiltyFile string
	// Arbitrary information about the test VM, may be attached to the report by users of the package.
	MachineInfo []byte
	// If the crash happened in the context of the syz-executor process, Executor will hold more info.
	Executor *ExecutorInfo
	// Whether the kernel has panicked after the report (Linux-specific).
	Panicked bool
	// reportPrefixLen is length of additional prefix lines that we added before actual crash report.
	reportPrefixLen int
	// symbolized is set if the report is symbolized. It prevents double symbolization.
	symbolized bool
}

type ExecutorInfo struct {
	ProcID int // ID of the syz-executor proc mentioned in the crash report.
	ExecID int // The program the syz-executor was executing.
}

func (rep *Report) String() string {
	return fmt.Sprintf("crash: %v\n%s", rep.Title, rep.Report)
}

// NewReporter creates reporter for the specified OS/Type.
func NewReporter(cfg *mgrconfig.Config) (*Reporter, error) {
	var localModules []*vminfo.KernelModule
	if cfg.KernelObj != "" {
		var err error
		localModules, err = backend.DiscoverModules(cfg.SysTarget, cfg.KernelObj, cfg.ModuleObj)
		if err != nil {
			return nil, err
		}
		cfg.LocalModules = localModules
	}
	typ := cfg.TargetOS
	if cfg.Type == targets.GVisor || cfg.Type == targets.Starnix {
		typ = cfg.Type
	}
	ctor := ctors[typ]
	if ctor == nil {
		return nil, fmt.Errorf("unknown OS: %v", typ)
	}
	ignores, err := compileRegexps(cfg.Ignores)
	if err != nil {
		return nil, err
	}
	interests, err := compileRegexps(cfg.Interests)
	if err != nil {
		return nil, err
	}
	config := &config{
		target:        cfg.SysTarget,
		vmType:        cfg.Type,
		kernelDirs:    *cfg.KernelDirs(),
		ignores:       ignores,
		kernelModules: localModules,
	}
	rep, suppressions, err := ctor(config)
	if err != nil {
		return nil, err
	}
	suppressions = append(suppressions, []string{
		// Go runtime OOM messages:
		"fatal error: runtime: out of memory",
		"fatal error: runtime: cannot allocate memory",
		"fatal error: out of memory",
		"fatal error: newosproc",
		// Panic with ENOMEM err:
		"panic: .*cannot allocate memory",
	}...)
	suppressions = append(suppressions, cfg.Suppressions...)
	supps, err := compileRegexps(suppressions)
	if err != nil {
		return nil, err
	}
	reporter := &Reporter{
		typ:          typ,
		impl:         rep,
		suppressions: supps,
		interests:    interests,
	}
	return reporter, nil
}

const (
	corruptedNoFrames = "extracted no frames"
)

var ctors = map[string]fn{
	targets.Linux:   ctorLinux,
	targets.Starnix: ctorFuchsia,
	targets.GVisor:  ctorGvisor,
	targets.FreeBSD: ctorFreebsd,
	targets.Darwin:  ctorDarwin,
	targets.NetBSD:  ctorNetbsd,
	targets.OpenBSD: ctorOpenbsd,
	targets.Fuchsia: ctorFuchsia,
	targets.Windows: ctorStub,
}

type config struct {
	target        *targets.Target
	vmType        string
	kernelDirs    mgrconfig.KernelDirs
	ignores       []*regexp.Regexp
	kernelModules []*vminfo.KernelModule
}

type fn func(cfg *config) (reporterImpl, []string, error)

func compileRegexps(list []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, len(list))
	for i, str := range list {
		re, err := regexp.Compile(str)
		if err != nil {
			return nil, fmt.Errorf("failed to compile %q: %w", str, err)
		}
		compiled[i] = re
	}
	return compiled, nil
}

func (reporter *Reporter) Parse(output []byte) *Report {
	return reporter.ParseFrom(output, 0)
}

func (reporter *Reporter) ParseFrom(output []byte, minReportPos int) *Report {
	rep := reporter.impl.Parse(output[minReportPos:])
	if rep == nil {
		return nil
	}
	rep.Output = output
	rep.StartPos += minReportPos
	rep.EndPos += minReportPos
	rep.Title = sanitizeTitle(replaceTable(dynamicTitleReplacement, rep.Title))
	for i, title := range rep.AltTitles {
		rep.AltTitles[i] = sanitizeTitle(replaceTable(dynamicTitleReplacement, title))
	}
	rep.Suppressed = matchesAny(rep.Output, reporter.suppressions)
	if bytes.Contains(rep.Output, gceConsoleHangup) {
		rep.Corrupted = true
	}
	if match := reportFrameRe.FindStringSubmatch(rep.Title); match != nil {
		rep.Frame = match[1]
	}
	rep.SkipPos = len(output)
	if pos := bytes.IndexByte(rep.Output[rep.StartPos:], '\n'); pos != -1 {
		rep.SkipPos = rep.StartPos + pos
	}
	// This generally should not happen.
	// But openbsd does some hacks with /r/n which may lead to off-by-one EndPos.
	rep.EndPos = max(rep.EndPos, rep.SkipPos)
	return rep
}

func (reporter *Reporter) ContainsCrash(output []byte) bool {
	return reporter.impl.ContainsCrash(output)
}

func (reporter *Reporter) Symbolize(rep *Report) error {
	if rep.symbolized {
		panic("Symbolize is called twice")
	}
	rep.symbolized = true
	if err := reporter.impl.Symbolize(rep); err != nil {
		return err
	}
	if !reporter.isInteresting(rep) {
		rep.Suppressed = true
	}
	return nil
}

func (reporter *Reporter) isInteresting(rep *Report) bool {
	if len(reporter.interests) == 0 {
		return true
	}
	if matchesAnyString(rep.Title, reporter.interests) ||
		matchesAnyString(rep.GuiltyFile, reporter.interests) {
		return true
	}
	for _, title := range rep.AltTitles {
		if matchesAnyString(title, reporter.interests) {
			return true
		}
	}
	for _, recipient := range rep.Recipients {
		if matchesAnyString(recipient.Address.Address, reporter.interests) {
			return true
		}
	}
	return false
}

// There are cases when we need to extract a guilty file, but have no ability to do it the
// proper way -- parse and symbolize the raw console output log. One of such cases is
// the syz-fillreports tool, which only has access to the already symbolized logs.
// ReportToGuiltyFile does its best to extract the data.
func (reporter *Reporter) ReportToGuiltyFile(title string, report []byte) string {
	ii, ok := reporter.impl.(interface {
		extractGuiltyFileRaw(title string, report []byte) string
	})
	if !ok {
		return ""
	}
	return ii.extractGuiltyFileRaw(title, report)
}

func IsSuppressed(reporter *Reporter, output []byte) bool {
	return matchesAny(output, reporter.suppressions) ||
		bytes.Contains(output, gceConsoleHangup)
}

// ParseAll returns all successive reports in output.
func ParseAll(reporter *Reporter, output []byte) (reports []*Report) {
	skipPos := 0
	for {
		rep := reporter.ParseFrom(output, skipPos)
		if rep == nil {
			return
		}
		reports = append(reports, rep)
		skipPos = rep.SkipPos
	}
}

// GCE console connection sometimes fails with this message.
// The message frequently happens right after a kernel panic.
// So if we see it in output where we recognized a crash, we mark the report as corrupted
// because the crash message is usually truncated (maybe we don't even have the title line).
// If we see it in no output/lost connection reports then we mark them as suppressed instead
// because the crash itself may have been caused by the console connection error.
var gceConsoleHangup = []byte("serialport: VM disconnected.")

type replacement struct {
	match       *regexp.Regexp
	replacement string
}

func replaceTable(replacements []replacement, str string) string {
	for _, repl := range replacements {
		for stop := false; !stop; {
			newStr := repl.match.ReplaceAllString(str, repl.replacement)
			stop = newStr == str
			str = newStr
		}
	}
	return str
}

var dynamicTitleReplacement = []replacement{
	{
		// Executor PIDs are not interesting.
		regexp.MustCompile(`syz-executor\.?[0-9]+((/|:)[0-9]+)?`),
		"syz-executor",
	},
	{
		// Executor process IDs are dynamic and are not interesting.
		regexp.MustCompile(`syzkaller[0-9]+((/|:)[0-9]+)?`),
		"syzkaller",
	},
	{
		// Replace that everything looks like an address with "ADDR",
		// addresses in descriptions can't be good regardless of the oops regexps.
		regexp.MustCompile(`([^a-zA-Z0-9])(?:0x)?[0-9a-f]{6,}`),
		"${1}ADDR",
	},
	{
		// Replace IP addresses.
		regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`),
		"IP",
	},
	{
		// Replace that everything looks like a file line number with "LINE".
		regexp.MustCompile(`(\.\w+)(:[0-9]+)+`),
		"${1}:LINE",
	},
	{
		// Replace all raw references to runctions (e.g. "ip6_fragment+0x1052/0x2d80")
		// with just function name ("ip6_fragment"). Offsets and sizes are not stable.
		regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9_.]+)\+0x[0-9a-z]+/0x[0-9a-z]+`),
		"${1}",
	},
	{
		// CPU numbers are not interesting.
		regexp.MustCompile(`CPU#[0-9]+`),
		"CPU",
	},
	{
		// Replace with "NUM" everything that looks like a decimal number and has not
		// been replaced yet. It might require multiple replacement executions as the
		// matching substrings may overlap (e.g. "0,1,2").
		regexp.MustCompile(`(\W)(\d+)(\W|$)`),
		"${1}NUM${3}",
	},
	{
		// Some decimal numbers can be a part of a function name,
		// we need to preserve them (e.g. cfg80211* or nl802154*).
		// However, if the number is too long, it's probably something else.
		regexp.MustCompile(`(\d+){7,}`),
		"NUM",
	},
}

func sanitizeTitle(title string) string {
	const maxTitleLen = 120 // Corrupted/intermixed lines can be very long.
	res := make([]byte, 0, len(title))
	prev := byte(' ')
	for i := 0; i < len(title) && i < maxTitleLen; i++ {
		ch := title[i]
		switch {
		case ch == '\t':
			ch = ' '
		case ch < 0x20 || ch >= 0x7f:
			continue
		}
		if ch == ' ' && prev == ' ' {
			continue
		}
		res = append(res, ch)
		prev = ch
	}
	return strings.TrimSpace(string(res))
}

type oops struct {
	header       []byte
	formats      []oopsFormat
	suppressions []*regexp.Regexp
}

type oopsFormat struct {
	title *regexp.Regexp
	// If title is matched but report is not, the report is considered corrupted.
	report *regexp.Regexp
	// Format string to create report title.
	// Strings captured by title (or by report if present) are passed as input.
	// If stack is not nil, extracted function name is passed as an additional last argument.
	fmt string
	// Alternative titles used for better crash deduplication.
	// Format is the same as for fmt.
	alt []string
	// If not nil, a function name is extracted from the report and passed to fmt.
	// If not nil but frame extraction fails, the report is considered corrupted.
	stack *stackFmt
	// Disable stack report corruption checking as it would expect one of stackStartRes to be
	// present, but this format does not comply with that.
	noStackTrace bool
	corrupted    bool
}

type stackFmt struct {
	// parts describe how guilty stack frame must be extracted from the report.
	// parts are matched consecutively potentially capturing frames.
	// parts can be of 3 types:
	//  - non-capturing regexp, matched against report and advances current position
	//  - capturing regexp, same as above, but also yields a frame
	//  - special value parseStackTrace means that a stack trace must be parsed
	//    starting from current position
	parts []*regexp.Regexp
	// If parts2 is present it is tried when parts matching fails.
	parts2 []*regexp.Regexp
	// Skip these functions in stack traces (matched as substring).
	skip []string
	// Custom frame extractor (optional).
	// Accepts set of all frames, returns guilty frame and corruption reason.
	extractor frameExtractor
}

type frameExtractor func(frames []string) (string, int)

var parseStackTrace *regexp.Regexp

func compile(re string) *regexp.Regexp {
	re = strings.ReplaceAll(re, "{{ADDR}}", "0x[0-9a-f]+")
	re = strings.ReplaceAll(re, "{{PC}}", "\\[\\<?(?:0x)?[0-9a-f]+\\>?\\]")
	re = strings.ReplaceAll(re, "{{FUNC}}", "([a-zA-Z0-9_]+)(?:\\.|\\+)")
	re = strings.ReplaceAll(re, "{{SRC}}", "([a-zA-Z0-9-_/.]+\\.[a-z]+:[0-9]+)")
	return regexp.MustCompile(re)
}

func containsCrash(output []byte, oopses []*oops, ignores []*regexp.Regexp) bool {
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops := range oopses {
			if matchOops(output[pos:next], oops, ignores) {
				return true
			}
		}
		pos = next + 1
	}
	return false
}

func matchOops(line []byte, oops *oops, ignores []*regexp.Regexp) bool {
	match := bytes.Index(line, oops.header)
	if match == -1 {
		return false
	}
	if matchesAny(line, oops.suppressions) {
		return false
	}
	if matchesAny(line, ignores) {
		return false
	}
	return true
}

func extractDescription(output []byte, oops *oops, params *stackParams) (
	desc, corrupted string, altTitles []string, format oopsFormat) {
	startPos := len(output)
	matchedTitle := false
	for _, f := range oops.formats {
		match := f.title.FindSubmatchIndex(output)
		if match == nil || match[0] > startPos {
			continue
		}
		if match[0] == startPos && desc != "" {
			continue
		}
		if match[0] < startPos {
			desc = ""
			format = oopsFormat{}
			startPos = match[0]
		}
		matchedTitle = true
		if f.report != nil {
			match = f.report.FindSubmatchIndex(output)
			if match == nil {
				continue
			}
		}
		var argPrefix []any
		for i := 2; i < len(match); i += 2 {
			argPrefix = append(argPrefix, string(output[match[i]:match[i+1]]))
		}
		var frames []extractedFrame
		corrupted = ""
		if f.stack != nil {
			var ok bool
			frames, ok = extractStackFrame(params, f.stack, output[match[0]:])
			if !ok {
				corrupted = corruptedNoFrames
			}
		}
		args := canonicalArgs(argPrefix, frames)
		desc = fmt.Sprintf(f.fmt, args...)
		for _, alt := range f.alt {
			altTitles = append(altTitles, fmt.Sprintf(alt, args...))
		}

		// Also consider partially stripped prefixes - these will help us
		// better deduplicate the reports.
		argSequences := partiallyStrippedArgs(argPrefix, frames, params)
		for _, args := range argSequences {
			altTitle := fmt.Sprintf(f.fmt, args...)
			if altTitle != desc {
				altTitles = append(altTitles, altTitle)
			}
			for _, alt := range f.alt {
				altTitles = append(altTitles, fmt.Sprintf(alt, args...))
			}
		}
		altTitles = uniqueStrings(altTitles)
		format = f
	}
	if desc == "" {
		// If we are here and matchedTitle is set, it means that we've matched
		// a title of an oops but not full report regexp or stack trace,
		// which means the report was corrupted.
		if matchedTitle {
			corrupted = "matched title but not report regexp"
		}
		pos := bytes.Index(output, oops.header)
		if pos == -1 {
			return
		}
		end := bytes.IndexByte(output[pos:], '\n')
		if end == -1 {
			end = len(output)
		} else {
			end += pos
		}
		desc = string(output[pos:end])
	}
	if corrupted == "" && format.corrupted {
		corrupted = "report format is marked as corrupted"
	}
	return
}

type stackParams struct {
	// stackStartRes matches start of stack traces.
	stackStartRes []*regexp.Regexp
	// frameRes match different formats of lines containing kernel frames (capture function name).
	frameRes []*regexp.Regexp
	// skipPatterns match functions that must be unconditionally skipped.
	skipPatterns []string
	// If we looked at any lines that match corruptedLines during report analysis,
	// then the report is marked as corrupted.
	corruptedLines []*regexp.Regexp
	// Prefixes that need to be removed from frames.
	// E.g. syscall prefixes as different arches have different prefixes.
	stripFramePrefixes []string
}

func (sp *stackParams) stripFrames(frames []string) []string {
	var ret []string
	for _, origFrame := range frames {
		// Pick the shortest one.
		frame := origFrame
		for _, prefix := range sp.stripFramePrefixes {
			newFrame := strings.TrimPrefix(origFrame, prefix)
			if len(newFrame) < len(frame) {
				frame = newFrame
			}
		}
		ret = append(ret, frame)
	}
	return ret
}

type extractedFrame struct {
	canonical string
	raw       string
}

func extractStackFrame(params *stackParams, stack *stackFmt, output []byte) ([]extractedFrame, bool) {
	skip := append([]string{}, params.skipPatterns...)
	skip = append(skip, stack.skip...)
	var skipRe *regexp.Regexp
	if len(skip) != 0 {
		skipRe = regexp.MustCompile(strings.Join(skip, "|"))
	}
	extractor := func(rawFrames []string) extractedFrame {
		if len(rawFrames) == 0 {
			return extractedFrame{}
		}
		stripped := params.stripFrames(rawFrames)
		if stack.extractor == nil {
			return extractedFrame{stripped[0], rawFrames[0]}
		}
		frame, idx := stack.extractor(stripped)
		if frame != "" {
			return extractedFrame{frame, rawFrames[idx]}
		}
		return extractedFrame{}
	}
	frames, ok := extractStackFrameImpl(params, output, skipRe, stack.parts, extractor)
	if ok || len(stack.parts2) == 0 {
		return frames, ok
	}
	return extractStackFrameImpl(params, output, skipRe, stack.parts2, extractor)
}

func lines(text []byte) [][]byte {
	return bytes.Split(text, []byte("\n"))
}

func extractStackFrameImpl(params *stackParams, output []byte, skipRe *regexp.Regexp,
	parts []*regexp.Regexp, extractor func([]string) extractedFrame) ([]extractedFrame, bool) {
	lines := lines(output)
	var rawFrames []string
	var results []extractedFrame
	ok := true
	numStackTraces := 0
nextPart:
	for partIdx := 0; ; partIdx++ {
		if partIdx == len(parts) || parts[partIdx] == parseStackTrace && numStackTraces > 0 {
			keyFrame := extractor(rawFrames)
			if keyFrame.canonical == "" {
				keyFrame, ok = extractedFrame{"corrupted", "corrupted"}, false
			}
			results = append(results, keyFrame)
			rawFrames = nil
		}
		if partIdx == len(parts) {
			break
		}
		part := parts[partIdx]
		if part == parseStackTrace {
			numStackTraces++
			var ln []byte
			for len(lines) > 0 {
				ln, lines = lines[0], lines[1:]
				if matchesAny(ln, params.corruptedLines) {
					ok = false
					continue nextPart
				}
				if matchesAny(ln, params.stackStartRes) {
					continue nextPart
				}

				if partIdx != len(parts)-1 {
					match := parts[partIdx+1].FindSubmatch(ln)
					if match != nil {
						rawFrames = appendStackFrame(rawFrames, match, skipRe)
						partIdx++
						continue nextPart
					}
				}
				var match [][]byte
				for _, re := range params.frameRes {
					match = re.FindSubmatch(ln)
					if match != nil {
						break
					}
				}
				rawFrames = appendStackFrame(rawFrames, match, skipRe)
			}
		} else {
			var ln []byte
			for len(lines) > 0 {
				ln, lines = lines[0], lines[1:]
				if matchesAny(ln, params.corruptedLines) {
					ok = false
					continue nextPart
				}
				match := part.FindSubmatch(ln)
				if match == nil {
					continue
				}
				rawFrames = appendStackFrame(rawFrames, match, skipRe)
				break
			}
		}
	}
	return results, ok
}

func appendStackFrame(frames []string, match [][]byte, skipRe *regexp.Regexp) []string {
	if len(match) < 2 {
		return frames
	}
	for _, frame := range match[1:] {
		if frame == nil {
			continue
		}
		frame := demangle.Filter(string(frame), demangle.NoParams)
		if skipRe == nil || !skipRe.MatchString(frame) {
			frames = append(frames, frame)
		}
	}
	return frames
}

func canonicalArgs(prefix []any, frames []extractedFrame) []any {
	ret := append([]any{}, prefix...)
	for _, frame := range frames {
		ret = append(ret, frame.canonical)
	}
	return ret
}

func partiallyStrippedArgs(prefix []any, frames []extractedFrame, params *stackParams) [][]any {
	if params == nil {
		return nil
	}
	ret := [][]any{}
	for i := 0; i <= len(params.stripFramePrefixes); i++ {
		var list []any
		add := true

		// Also include the raw frames.
		stripPrefix := ""
		if i > 0 {
			stripPrefix, add = params.stripFramePrefixes[i-1], false
		}
		for _, frame := range frames {
			trimmed := strings.TrimPrefix(frame.raw, stripPrefix)
			if trimmed != frame.raw {
				add = true
			}
			list = append(list, trimmed)
		}
		if add {
			list = append(append([]any{}, prefix...), list...)
			ret = append(ret, list)
		}
	}
	return ret
}

func uniqueStrings(source []string) []string {
	dup := map[string]struct{}{}
	var ret []string
	for _, item := range source {
		if _, ok := dup[item]; ok {
			continue
		}
		dup[item] = struct{}{}
		ret = append(ret, item)
	}
	return ret
}

func simpleLineParser(output []byte, oopses []*oops, params *stackParams, ignores []*regexp.Regexp) *Report {
	rep := &Report{
		Output: output,
	}
	var oops *oops
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		line := output[pos:next]
		for _, oops1 := range oopses {
			if matchOops(line, oops1, ignores) {
				oops = oops1
				rep.StartPos = pos
				rep.EndPos = next
				break
			}
		}
		if oops != nil {
			break
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, altTitles, _ := extractDescription(output[rep.StartPos:], oops, params)
	rep.Title = title
	rep.AltTitles = altTitles
	rep.Report = output[rep.StartPos:]
	rep.Corrupted = corrupted != ""
	rep.CorruptedReason = corrupted
	rep.Type = crash.TitleToType(rep.Title)
	return rep
}

func matchesAny(line []byte, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.Match(line) {
			return true
		}
	}
	return false
}

func matchesAnyString(str string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.MatchString(str) {
			return true
		}
	}
	return false
}

// replace replaces [start:end] in where with what, inplace.
func replace(where []byte, start, end int, what []byte) []byte {
	if len(what) >= end-start {
		where = append(where, what[end-start:]...)
		copy(where[start+len(what):], where[end:])
		copy(where[start:], what)
	} else {
		copy(where[start+len(what):], where[end:])
		where = where[:len(where)-(end-start-len(what))]
		copy(where[start:], what)
	}
	return where
}

// Truncate leaves up to `begin` bytes at the beginning of log and
// up to `end` bytes at the end of the log.
func Truncate(log []byte, begin, end int) []byte {
	if begin+end >= len(log) {
		return log
	}
	var b bytes.Buffer
	b.Write(log[:begin])
	if begin > 0 {
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "<<cut %d bytes out>>",
		len(log)-begin-end,
	)
	if end > 0 {
		b.WriteString("\n\n")
	}
	b.Write(log[len(log)-end:])
	return b.Bytes()
}

var (
	filenameRe    = regexp.MustCompile(`([a-zA-Z0-9_\-\./]*[a-zA-Z0-9_\-]+\.(c|h)):[0-9]+`)
	reportFrameRe = regexp.MustCompile(`.* in ((?:<[a-zA-Z0-9_: ]+>)?[a-zA-Z0-9_:]+)`)
	// Matches a slash followed by at least one directory nesting before .c/.h file.
	deeperPathRe = regexp.MustCompile(`^/[a-zA-Z0-9_\-\./]+/[a-zA-Z0-9_\-]+\.(c|h)$`)
)

// These are produced by syzkaller itself.
// But also catches crashes in Go programs in gvisor/fuchsia.
var commonOopses = []*oops{
	{
		// Errors produced by executor's fail function.
		[]byte("SYZFAIL:"),
		[]oopsFormat{
			{
				title:        compile("SYZFAIL:(.*)"),
				fmt:          "SYZFAIL:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// Errors produced by log.Fatal functions.
		[]byte("SYZFATAL:"),
		[]oopsFormat{
			{
				title:        compile("SYZFATAL:(.*)()"),
				alt:          []string{"SYZFATAL%[2]s"},
				fmt:          "SYZFATAL:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic:"),
		[]oopsFormat{
			{
				// This is gvisor-specific, but we need to handle it here since we handle "panic:" here.
				title:        compile("panic: Sentry detected .* stuck task"),
				fmt:          "panic: Sentry detected stuck tasks",
				noStackTrace: true,
			},
			{
				title:        compile("panic:(.*)"),
				fmt:          "panic:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{
			// This can match some kernel functions (skb_panic, skb_over_panic).
			compile("_panic:"),
			// Android prints this sometimes during boot.
			compile("xlog_status:"),
			compile(`ddb\.onpanic:`),
			compile(`evtlog_status:`),
		},
	},
}

var groupGoRuntimeErrors = oops{
	[]byte("fatal error:"),
	[]oopsFormat{
		{
			title:        compile("fatal error:"),
			fmt:          "go runtime error",
			noStackTrace: true,
		},
	},
	[]*regexp.Regexp{
		compile("ALSA"),
		compile("fatal error: cannot create timer"),
	},
}

const reportSeparator = "\n<<<<<<<<<<<<<<< tail report >>>>>>>>>>>>>>>\n\n"

func MergeReportBytes(reps []*Report) []byte {
	var res []byte
	for _, rep := range reps {
		res = append(res, rep.Report...)
		res = append(res, []byte(reportSeparator)...)
	}
	return res
}

func SplitReportBytes(data []byte) [][]byte {
	return bytes.Split(data, []byte(reportSeparator))
}
