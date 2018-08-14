// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"fmt"
	"net/mail"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type linux struct {
	kernelSrc             string
	kernelObj             string
	vmlinux               string
	symbols               map[string][]symbolizer.Symbol
	ignores               []*regexp.Regexp
	consoleOutputRe       *regexp.Regexp
	questionableRe        *regexp.Regexp
	guiltyFileBlacklist   []*regexp.Regexp
	reportStartIgnores    [][]byte
	infoMessagesWithStack [][]byte
	eoi                   []byte
}

func ctorLinux(kernelSrc, kernelObj string, ignores []*regexp.Regexp) (Reporter, []string, error) {
	vmlinux := ""
	var symbols map[string][]symbolizer.Symbol
	if kernelObj != "" {
		vmlinux = filepath.Join(kernelObj, "vmlinux")
		var err error
		symbols, err = symbolizer.ReadSymbols(vmlinux)
		if err != nil {
			return nil, nil, err
		}
	}
	ctx := &linux{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		vmlinux:   vmlinux,
		symbols:   symbols,
		ignores:   ignores,
	}
	ctx.consoleOutputRe = regexp.MustCompile(`^(?:\*\* [0-9]+ printk messages dropped \*\* )?(?:.* login: )?(?:\<[0-9]+\>)?\[ *[0-9]+\.[0-9]+\] `)
	ctx.questionableRe = regexp.MustCompile(`(?:\[\<[0-9a-f]+\>\])? \? +[a-zA-Z0-9_.]+\+0x[0-9a-f]+/[0-9a-f]+`)
	ctx.eoi = []byte("<EOI>")
	ctx.guiltyFileBlacklist = []*regexp.Regexp{
		regexp.MustCompile(`.*\.h`),
		regexp.MustCompile(`^lib/.*`),
		regexp.MustCompile(`^virt/lib/.*`),
		regexp.MustCompile(`^mm/kasan/.*`),
		regexp.MustCompile(`^mm/kmsan/.*`),
		regexp.MustCompile(`^kernel/kcov.c`),
		regexp.MustCompile(`^mm/sl.b.c`),
		regexp.MustCompile(`^mm/percpu.*`),
		regexp.MustCompile(`^mm/vmalloc.c`),
		regexp.MustCompile(`^mm/page_alloc.c`),
		regexp.MustCompile(`^mm/util.c`),
		regexp.MustCompile(`^kernel/rcu/.*`),
		regexp.MustCompile(`^arch/.*/kernel/traps.c`),
		regexp.MustCompile(`^arch/.*/mm/fault.c`),
		regexp.MustCompile(`^kernel/locking/.*`),
		regexp.MustCompile(`^kernel/panic.c`),
		regexp.MustCompile(`^kernel/softirq.c`),
		regexp.MustCompile(`^kernel/kthread.c`),
		regexp.MustCompile(`^kernel/sched/.*.c`),
		regexp.MustCompile(`^kernel/time/timer.c`),
		regexp.MustCompile(`^kernel/workqueue.c`),
		regexp.MustCompile(`^net/core/dev.c`),
		regexp.MustCompile(`^net/core/sock.c`),
		regexp.MustCompile(`^net/core/skbuff.c`),
		regexp.MustCompile(`^fs/proc/generic.c`),
	}
	// These pattern do _not_ start a new report, i.e. can be in a middle of another report.
	ctx.reportStartIgnores = [][]byte{
		[]byte("invalid opcode: 0000"),
		[]byte("Kernel panic - not syncing: panic_on_warn set"),
		[]byte("unregister_netdevice: waiting for"),
	}
	// These pattern math kernel reports which are not bugs in itself but contain stack traces.
	// If we see them in the middle of another report, we know that the report is potentially corrupted.
	ctx.infoMessagesWithStack = [][]byte{
		[]byte("vmalloc: allocation failure:"),
		[]byte("FAULT_INJECTION: forcing a failure"),
		[]byte("FAULT_FLAG_ALLOW_RETRY missing"),
	}
	suppressions := []string{
		"fatal error: runtime: out of memory",
		"fatal error: runtime: cannot allocate memory",
		"panic: failed to start executor binary",
		"panic: executor failed: pthread_create failed",
		"panic: failed to create temp dir",
		"fatal error: unexpected signal during runtime execution", // presubmably OOM turned into SIGBUS
		"signal SIGBUS: bus error",                                // presubmably OOM turned into SIGBUS
		"Out of memory: Kill process .* \\(syz-fuzzer\\)",
		"Out of memory: Kill process .* \\(sshd\\)",
		"Killed process .* \\(syz-fuzzer\\)",
		"Killed process .* \\(sshd\\)",
		"lowmemorykiller: Killing 'syz-fuzzer'",
		"lowmemorykiller: Killing 'sshd'",
		"INIT: PANIC: segmentation violation!",
	}
	return ctx, suppressions, nil
}

func (ctx *linux) ContainsCrash(output []byte) bool {
	return containsCrash(output, linuxOopses, ctx.ignores)
}

func (ctx *linux) Parse(output []byte) *Report {
	oops, startPos, endPos, logReport, consoleReport, consoleReportReliable,
		logReportPrefix, consoleReportPrefix := ctx.parseOutput(output)
	if oops == nil {
		return nil
	}
	rep := &Report{
		Output:   output,
		StartPos: startPos,
		EndPos:   endPos,
	}
	var report []byte
	var reportPrefix [][]byte
	// Try extracting report from console output only.
	title, corrupted, format := extractDescription(consoleReportReliable, oops, linuxStackParams)
	if title != "" {
		report = consoleReport
		reportPrefix = consoleReportPrefix
	} else {
		// Failure. Try extracting report from the whole log.
		report = logReport
		reportPrefix = logReportPrefix
		title, corrupted, format = extractDescription(report, oops, linuxStackParams)
		if title == "" {
			panic(fmt.Sprintf("non matching oops for %q in:\n%s\n\nconsole:\n%s\n"+
				"output [range:%v-%v]:\n%s\n",
				oops.header, report, consoleReportReliable,
				rep.StartPos, rep.StartPos+len(report), output))
		}
	}
	rep.Title = title
	rep.Corrupted = corrupted != ""
	rep.CorruptedReason = corrupted
	// Prepend 5 lines preceding start of the report,
	// they can contain additional info related to the report.
	for _, prefix := range reportPrefix {
		rep.Report = append(rep.Report, prefix...)
		rep.Report = append(rep.Report, '\n')
	}
	rep.Report = append(rep.Report, report...)
	if !rep.Corrupted {
		rep.Corrupted, rep.CorruptedReason = ctx.isCorrupted(title, report, format)
	}
	return rep
}

// Yes, it is complex, but all state and logic are tightly coupled. It's unclear how to simplify it.
// nolint: gocyclo
func (ctx *linux) parseOutput(output []byte) (
	oops *oops, startPos, endPos int,
	logReport, consoleReport, consoleReportReliable []byte,
	logReportPrefix, consoleReportPrefix [][]byte) {
	firstReportEnd := 0
	secondReportPos := 0
	textLines := 0
	skipText := false
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		line := output[pos:next]
		for _, oops1 := range linuxOopses {
			match := matchOops(line, oops1, ctx.ignores)
			if match == -1 {
				if oops != nil && secondReportPos == 0 {
					for _, pattern := range ctx.infoMessagesWithStack {
						if bytes.Contains(line, pattern) {
							secondReportPos = pos
							break
						}
					}
				}
				continue
			}
			endPos = next
			if oops == nil {
				oops = oops1
				startPos = pos
				break
			} else if secondReportPos == 0 {
				ignored := false
				for _, ignore := range ctx.reportStartIgnores {
					if bytes.Contains(line, ignore) {
						ignored = true
						break
					}
				}
				if !ignored {
					secondReportPos = pos
				}
			}
		}
		if oops == nil {
			logReportPrefix = append(logReportPrefix, append([]byte{}, line...))
			if len(logReportPrefix) > 5 {
				logReportPrefix = logReportPrefix[1:]
			}
		}
		if ctx.consoleOutputRe.Match(line) &&
			(!ctx.questionableRe.Match(line) || bytes.Contains(line, ctx.eoi)) {
			lineStart := bytes.Index(line, []byte("] ")) + pos + 2
			lineEnd := next
			if lineEnd != 0 && output[lineEnd-1] == '\r' {
				lineEnd--
			}
			if oops == nil {
				consoleReportPrefix = append(consoleReportPrefix,
					append([]byte{}, output[lineStart:lineEnd]...))
				if len(consoleReportPrefix) > 5 {
					consoleReportPrefix = consoleReportPrefix[1:]
				}
			} else {
				textLines++
				ln := output[lineStart:lineEnd]
				skipLine := skipText
				if bytes.Contains(ln, []byte("Disabling lock debugging due to kernel taint")) {
					skipLine = true
				} else if textLines > 25 &&
					bytes.Contains(ln, []byte("Kernel panic - not syncing")) {
					// If panic_on_warn set, then we frequently have 2 stacks:
					// one for the actual report (or maybe even more than one),
					// and then one for panic caused by panic_on_warn. This makes
					// reports unnecessary long and the panic (current) stack
					// is always present in the actual report. So we strip the
					// panic message. However, we check that we have enough lines
					// before the panic, because sometimes we have, for example,
					// a single WARNING line without a stack and then the panic
					// with the stack.
					skipText = true
					skipLine = true
				}
				if !skipLine {
					consoleReport = append(consoleReport, ln...)
					consoleReport = append(consoleReport, '\n')
					if secondReportPos == 0 {
						firstReportEnd = len(consoleReport)
					}
				}
			}
		}
		pos = next + 1
	}
	if oops == nil {
		return
	}
	if secondReportPos == 0 {
		secondReportPos = len(output)
	}
	logReport = output[startPos:secondReportPos]
	consoleReportReliable = consoleReport[:firstReportEnd]
	return
}

func (ctx *linux) Symbolize(rep *Report) error {
	if ctx.vmlinux == "" {
		return nil
	}
	symbolized, err := ctx.symbolize(rep.Report)
	if err != nil {
		return err
	}
	rep.Report = symbolized
	guiltyFile := ctx.extractGuiltyFile(rep.Report)
	if guiltyFile != "" {
		rep.Maintainers, err = ctx.getMaintainers(guiltyFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ctx *linux) symbolize(text []byte) ([]byte, error) {
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()
	strip := ctx.stripPrefix(symb)
	var symbolized []byte
	s := bufio.NewScanner(bytes.NewReader(text))
	for s.Scan() {
		line := append([]byte{}, s.Bytes()...)
		line = append(line, '\n')
		line = symbolizeLine(symb.Symbolize, ctx.symbols, ctx.vmlinux, strip, line)
		symbolized = append(symbolized, line...)
	}
	return symbolized, nil
}

func (ctx *linux) stripPrefix(symb *symbolizer.Symbolizer) string {
	// Vmlinux may have been moved, so check if we can find debug info
	// for some known functions and infer correct strip prefix from it.
	knownSymbols := []struct {
		symbol string
		file   string
	}{
		{"__sanitizer_cov_trace_pc", "kernel/kcov.c"},
		{"__asan_load1", "mm/kasan/kasan.c"},
		{"start_kernel", "init/main.c"},
	}
	for _, s := range knownSymbols {
		for _, covSymb := range ctx.symbols[s.symbol] {
			frames, _ := symb.Symbolize(ctx.vmlinux, covSymb.Addr)
			if len(frames) > 0 {
				file := frames[len(frames)-1].File
				if idx := strings.Index(file, s.file); idx != -1 {
					return file[:idx]
				}
			}
		}
	}
	// Strip vmlinux location from all paths.
	strip, _ := filepath.Abs(ctx.vmlinux)
	return filepath.Dir(strip) + string(filepath.Separator)
}

func symbolizeLine(symbFunc func(bin string, pc uint64) ([]symbolizer.Frame, error),
	symbols map[string][]symbolizer.Symbol, vmlinux, strip string, line []byte) []byte {
	match := linuxSymbolizeRe.FindSubmatchIndex(line)
	if match == nil {
		return line
	}
	fn := line[match[2]:match[3]]
	off, err := strconv.ParseUint(string(line[match[4]:match[5]]), 16, 64)
	if err != nil {
		return line
	}
	size, err := strconv.ParseUint(string(line[match[6]:match[7]]), 16, 64)
	if err != nil {
		return line
	}
	symb := symbols[string(fn)]
	if len(symb) == 0 {
		return line
	}
	var funcStart uint64
	for _, s := range symb {
		if funcStart == 0 || int(size) == s.Size {
			funcStart = s.Addr
		}
	}
	frames, err := symbFunc(vmlinux, funcStart+off-1)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	for _, frame := range frames {
		file := frame.File
		file = strings.TrimPrefix(file, strip)
		file = strings.TrimPrefix(file, "./")
		info := fmt.Sprintf(" %v:%v", file, frame.Line)
		modified := append([]byte{}, line...)
		modified = replace(modified, match[7], match[7], []byte(info))
		if frame.Inline {
			end := match[7] + len(info)
			modified = replace(modified, end, end, []byte(" [inline]"))
			modified = replace(modified, match[2], match[7], []byte(frame.Func))
		}
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}

func (ctx *linux) extractGuiltyFile(report []byte) string {
	if linuxRcuStall.Match(report) {
		// Special case for rcu stalls.
		// There are too many frames that we want to skip before actual guilty frames,
		// we would need to blacklist too many files and that would be fragile.
		// So instead we try to extract guilty file starting from the known
		// interrupt entry point first.
		if pos := bytes.Index(report, []byte(" apic_timer_interrupt+0x")); pos != -1 {
			if file := ctx.extractGuiltyFileImpl(report[pos:]); file != "" {
				return file
			}
		}
	}
	return ctx.extractGuiltyFileImpl(report)
}

func (ctx *linux) extractGuiltyFileImpl(report []byte) string {
	files := ctx.extractFiles(report)
nextFile:
	for _, file := range files {
		for _, re := range ctx.guiltyFileBlacklist {
			if re.MatchString(file) {
				continue nextFile
			}
		}
		return file
	}
	return ""
}

func (ctx *linux) getMaintainers(file string) ([]string, error) {
	mtrs, err := ctx.getMaintainersImpl(file, false)
	if err != nil {
		return nil, err
	}
	if len(mtrs) <= 1 {
		mtrs, err = ctx.getMaintainersImpl(file, true)
		if err != nil {
			return nil, err
		}
	}
	return mtrs, nil
}

func (ctx *linux) getMaintainersImpl(file string, blame bool) ([]string, error) {
	args := []string{"--no-n", "--no-rolestats"}
	if blame {
		args = append(args, "--git-blame")
	}
	args = append(args, file)
	output, err := osutil.RunCmd(time.Minute, ctx.kernelSrc, filepath.FromSlash("scripts/get_maintainer.pl"), args...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	var mtrs []string
	for _, line := range lines {
		addr, err := mail.ParseAddress(line)
		if err != nil {
			continue
		}
		mtrs = append(mtrs, addr.Address)
	}
	return mtrs, nil
}

func (ctx *linux) extractFiles(report []byte) []string {
	matches := filenameRe.FindAll(report, -1)
	var files []string
	for _, match := range matches {
		f := string(bytes.Split(match, []byte{':'})[0])
		files = append(files, filepath.Clean(f))
	}
	return files
}

func (ctx *linux) isCorrupted(title string, report []byte, format oopsFormat) (bool, string) {
	// Check if the report contains stack trace.
	if !format.noStackTrace && !bytes.Contains(report, []byte("Call Trace")) &&
		!bytes.Contains(report, []byte("backtrace")) {
		return true, "no stack trace in report"
	}
	// Check for common title corruptions.
	for _, re := range linuxCorruptedTitles {
		if re.MatchString(title) {
			return true, "title matches corrupted regexp"
		}
	}
	// When a report contains 'Call Trace', 'backtrace', 'Allocated' or 'Freed' keywords,
	// it must also contain at least a single stack frame after each of them.
	for _, key := range linuxStackKeywords {
		match := key.FindSubmatchIndex(report)
		if match == nil {
			continue
		}
		frames := bytes.Split(report[match[0]:], []byte{'\n'})
		if len(frames) < 4 {
			return true, "call trace is missed"
		}
		frames = frames[1:]
		corrupted := true
		// Check that at least one of the next few lines contains a frame.
	outer:
		for i := 0; i < 15 && i < len(frames); i++ {
			for _, key1 := range linuxStackKeywords {
				// Next stack trace starts.
				if key1.Match(frames[i]) {
					break outer
				}
			}
			if bytes.Contains(frames[i], []byte("(stack is not available)")) ||
				stackFrameRe.Match(frames[i]) {
				corrupted = false
				break
			}
		}
		if corrupted {
			return true, "no frames in a stack trace"
		}
	}
	return false, ""
}

var (
	linuxSymbolizeRe = regexp.MustCompile(`(?:\[\<(?:[0-9a-f]+)\>\])?[ \t]+(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	stackFrameRe     = regexp.MustCompile(`^ *(?:\[\<(?:[0-9a-f]+)\>\])?[ \t]+(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	linuxRcuStall    = compile("INFO: rcu_(?:preempt|sched|bh) (?:self-)?detected(?: expedited)? stall")
	linuxRipFrame    = compile(`IP: (?:(?:[0-9]+:)?(?:{{PC}} +){0,2}{{FUNC}}|[0-9]+:0x[0-9a-f]+|(?:[0-9]+:)?{{PC}} +\[< *\(null\)>\] +\(null\)|[0-9]+: +\(null\))`)
)

var linuxCorruptedTitles = []*regexp.Regexp{
	// Sometimes timestamps get merged into the middle of report description.
	regexp.MustCompile(`\[ *[0-9]+\.[0-9]+\]`),
}

var linuxStackKeywords = []*regexp.Regexp{
	regexp.MustCompile(`Call Trace`),
	regexp.MustCompile(`Allocated`),
	regexp.MustCompile(`Freed`),
	// Match 'backtrace:', but exclude 'stack backtrace:'
	regexp.MustCompile(`[^k] backtrace:`),
}

var linuxStackParams = &stackParams{
	stackStartRes: linuxStackKeywords,
	frameRes: []*regexp.Regexp{
		compile("^ +(?:{{PC}} )?{{FUNC}}"),
	},
	skipPatterns: []string{
		"__sanitizer",
		"__asan",
		"kasan",
		"check_memory_region",
		"print_address_description",
		"panic",
		"invalid_op",
		"report_bug",
		"fixup_bug",
		"do_error",
		"invalid_op",
		"_trap",
		"dump_stack",
		"warn_slowpath",
		"warn_alloc",
		"__warn",
		"debug_object",
		"work_is_static_object",
		"lockdep",
		"perf_trace",
		"lock_acquire",
		"lock_release",
		"register_lock_class",
		"spin_lock",
		"spin_unlock",
		"raw_read_lock",
		"raw_write_lock",
		"down_read",
		"down_write",
		"down_read_trylock",
		"down_write_trylock",
		"up_read",
		"up_write",
		"mutex_lock",
		"mutex_unlock",
		"memcpy",
		"memcmp",
		"memset",
		"strcmp",
		"strcpy",
		"strlen",
		"copy_to_user",
		"copy_from_user",
		"put_user",
		"get_user",
		"might_fault",
		"might_sleep",
		"list_add",
		"list_del",
		"list_replace",
		"list_move",
		"list_splice",
	},
	corruptedLines: []*regexp.Regexp{
		// Fault injection stacks are frequently intermixed with crash reports.
		compile(`^ should_fail(\.[a-z]+\.[0-9]+)?\+0x`),
		compile(`^ should_failslab(\.[a-z]+\.[0-9]+)?\+0x`),
	},
}

func warningStackFmt(skip ...string) *stackFmt {
	return &stackFmt{
		// In newer kernels WARNING traps and actual stack starts after invalid_op frame,
		// older kernels just print stack.
		parts: []*regexp.Regexp{
			linuxRipFrame,
			parseStackTrace,
		},
		parts2: []*regexp.Regexp{
			compile("Call Trace:"),
			parseStackTrace,
		},
		skip: skip,
	}
}

var linuxOopses = []*oops{
	{
		[]byte("BUG:"),
		[]oopsFormat{
			{
				title:  compile("BUG: KASAN:"),
				report: compile("BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+?.*(Read|Write) of size (?:[0-9]+)"),

				fmt: "KASAN: %[1]v %[3]v in %[4]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("BUG: KASAN: (?:[a-z\\-]+) in {{FUNC}}"),
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				title:  compile("BUG: KASAN:"),
				report: compile("BUG: KASAN: double-free or invalid-free in {{FUNC}}"),
				fmt:    "KASAN: invalid-free in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("BUG: KASAN: double-free or invalid-free in {{FUNC}}"),
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"kmem_", "slab_", "kfree", "vunmap", "vfree"},
				},
			},
			{
				title: compile("BUG: KASAN: ([a-z\\-]+) on address(?:.*\\n)+?.*(Read|Write) of size ([0-9]+)"),
				fmt:   "KASAN: %[1]v %[2]v",
			},
			{
				title:     compile("BUG: KASAN: (.*)"),
				fmt:       "KASAN: %[1]v",
				corrupted: true,
			},
			{
				title: compile("BUG: KMSAN: (.*)"),
				fmt:   "KMSAN: %[1]v",
			},
			{
				title: compile("BUG: unable to handle kernel paging request"),
				fmt:   "BUG: unable to handle kernel paging request in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				title: compile("BUG: unable to handle kernel NULL pointer dereference"),
				fmt:   "BUG: unable to handle kernel NULL pointer dereference in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				// Sometimes with such BUG failures, the second part of the header doesn't get printed
				// or gets corrupted, because kernel prints it as two separate printk() calls.
				title:     compile("BUG: unable to handle kernel"),
				fmt:       "BUG: unable to handle kernel",
				corrupted: true,
			},
			{
				title: compile("BUG: spinlock (lockup suspected|already unlocked|recursion|bad magic|wrong owner|wrong CPU)"),
				fmt:   "BUG: spinlock %[1]v in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"spin_"},
				},
			},
			{
				title: compile("BUG: soft lockup"),
				fmt:   "BUG: soft lockup in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				title:  compile("BUG: .*still has locks held!"),
				report: compile("BUG: .*still has locks held!(?:.*\\n)+?.*{{PC}} +{{FUNC}}"),
				fmt:    "BUG: still has locks held in %[1]v",
			},
			{
				title:        compile("BUG: lock held when returning to user space"),
				report:       compile("BUG: lock held when returning to user space(?:.*\\n)+?.*leaving the kernel with locks still held(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:          "BUG: lock held when returning to user space in %[1]v",
				noStackTrace: true,
			},
			{
				title:  compile("BUG: bad unlock balance detected!"),
				report: compile("BUG: bad unlock balance detected!(?:.*\\n){0,15}?.*is trying to release lock(?:.*\\n){0,15}?.*{{PC}} +{{FUNC}}"),
				fmt:    "BUG: bad unlock balance in %[1]v",
			},
			{
				title:  compile("BUG: held lock freed!"),
				report: compile("BUG: held lock freed!(?:.*\\n)+?.*{{PC}} +{{FUNC}}"),
				fmt:    "BUG: held lock freed in %[1]v",
			},
			{
				title:        compile("BUG: Bad rss-counter state"),
				fmt:          "BUG: Bad rss-counter state",
				noStackTrace: true,
			},
			{
				title:        compile("BUG: non-zero nr_ptes on freeing mm"),
				fmt:          "BUG: non-zero nr_ptes on freeing mm",
				noStackTrace: true,
			},
			{
				title:        compile("BUG: non-zero nr_pmds on freeing mm"),
				fmt:          "BUG: non-zero nr_pmds on freeing mm",
				noStackTrace: true,
			},
			{
				title: compile("BUG: Dentry .* still in use \\([0-9]+\\) \\[unmount of ([^\\]]+)\\]"),
				fmt:   "BUG: Dentry still in use [unmount of %[1]v]",
			},
			{
				title: compile("BUG: Bad page state"),
				fmt:   "BUG: Bad page state",
			},
			{
				title: compile("BUG: Bad page map"),
				fmt:   "BUG: Bad page map",
			},
			{
				title:        compile("BUG: workqueue lockup"),
				fmt:          "BUG: workqueue lockup",
				noStackTrace: true,
			},
			{
				title: compile("BUG: sleeping function called from invalid context (.*)"),
				fmt:   "BUG: sleeping function called from invalid context %[1]v",
			},
			{
				title: compile("BUG: using __this_cpu_([a-z_]+)\\(\\) in preemptible"),
				fmt:   "BUG: using __this_cpu_%[1]v() in preemptible code in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"dump_stack", "preemption", "preempt"},
				},
			},
			{
				title: compile("BUG: workqueue leaked lock or atomic"),
				report: compile("BUG: workqueue leaked lock or atomic(?:.*\\n)+?" +
					".*last function: ([a-zA-Z0-9_]+)\\n"),
				fmt:          "BUG: workqueue leaked lock or atomic in %[1]v",
				noStackTrace: true,
			},
			{
				title:        compile("BUG: executor-detected bug"),
				fmt:          "BUG: executor-detected bug",
				noStackTrace: true,
			},
			{
				title: compile("BUG: memory leak"),
				fmt:   "memory leak in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("backtrace:"),
						parseStackTrace,
					},
					skip: []string{"kmemleak", "kmalloc", "kcalloc", "kzalloc",
						"vmalloc", "kmem", "slab", "alloc", "create_object"},
				},
			},
		},
		[]*regexp.Regexp{
			// CONFIG_DEBUG_OBJECTS output.
			compile("ODEBUG:"),
			// Android prints this sometimes during boot.
			compile("Boot_DEBUG:"),
			// pkg/host output in debug mode.
			compile("BUG: no syscalls can create resource"),
		},
	},
	{
		[]byte("WARNING:"),
		[]oopsFormat{
			{
				title: compile("WARNING: .*lib/debugobjects\\.c.* debug_print_object"),
				fmt:   "WARNING: ODEBUG bug in %[1]v",
				// Skip all users of ODEBUG as well.
				stack: warningStackFmt("debug_", "rcu", "hrtimer_", "timer_",
					"work_", "percpu_", "kmem_", "slab_", "kfree", "vunmap", "vfree"),
			},
			{
				title: compile("WARNING: .*mm/usercopy\\.c.* usercopy_warn"),
				fmt:   "WARNING: bad usercopy in %[1]v",
				stack: warningStackFmt("usercopy", "__check"),
			},
			{
				title: compile("WARNING: .*lib/kobject\\.c.* kobject_"),
				fmt:   "WARNING: kobject bug in %[1]v",
				stack: warningStackFmt("kobject_"),
			},
			{
				title: compile("WARNING: .*fs/proc/generic\\.c.* proc_register"),
				fmt:   "WARNING: proc registration bug in %[1]v",
				stack: warningStackFmt("proc_"),
			},
			{
				title: compile("WARNING: .*lib/refcount\\.c.* refcount_"),
				fmt:   "WARNING: refcount bug in %[1]v",
				stack: warningStackFmt("refcount"),
			},
			{
				title: compile("WARNING: .*kernel/locking/lockdep\\.c.*lock_"),
				fmt:   "WARNING: locking bug in %[1]v",
				stack: warningStackFmt(),
			},
			{
				title:        compile("WARNING: lock held when returning to user space"),
				report:       compile("WARNING: lock held when returning to user space(?:.*\\n)+?.*leaving the kernel with locks still held(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:          "WARNING: lock held when returning to user space in %[1]v",
				noStackTrace: true,
			},
			{
				title: compile("WARNING: .*mm/.*\\.c.* k?.?malloc"),
				fmt:   "WARNING: kmalloc bug in %[1]v",
				stack: warningStackFmt("kmalloc", "kcalloc", "kzalloc", "krealloc",
					"vmalloc", "slab", "kmem"),
			},
			{
				title: compile("WARNING: .* at {{SRC}} {{FUNC}}"),
				fmt:   "WARNING in %[2]v",
			},
			{
				title:  compile("WARNING: possible circular locking dependency detected"),
				report: compile("WARNING: possible circular locking dependency detected(?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("WARNING: possible irq lock inversion dependency detected"),
				report: compile("WARNING: possible irq lock inversion dependency detected(?:.*\\n)+?.*just changed the state of lock(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detecte"),
				report: compile("WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected(?:.*\\n)+?.*is trying to acquire(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("WARNING: possible recursive locking detected"),
				report: compile("WARNING: possible recursive locking detected(?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("WARNING: inconsistent lock state"),
				report: compile("WARNING: inconsistent lock state(?:.*\\n)+?.*takes(?:.*\\n)+?.*at: (?:{{PC}} +)?{{FUNC}}"),
				fmt:    "inconsistent lock state in %[1]v",
			},
			{
				title:  compile("WARNING: suspicious RCU usage"),
				report: compile("WARNING: suspicious RCU usage(?:.*\n)+?.*?{{SRC}}"),
				fmt:    "WARNING: suspicious RCU usage in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"rcu", "kmem", "slab", "kmalloc",
						"vmalloc", "kcalloc", "kzalloc"},
				},
			},
			{
				title:        compile("WARNING: kernel stack regs at [0-9a-f]+ in [^ ]* has bad '([^']+)' value"),
				fmt:          "WARNING: kernel stack regs has bad '%[1]v' value",
				noStackTrace: true,
			},
			{
				title:        compile("WARNING: kernel stack frame pointer at [0-9a-f]+ in [^ ]* has bad value"),
				fmt:          "WARNING: kernel stack frame pointer has bad value",
				noStackTrace: true,
			},
			{
				title:  compile("WARNING: bad unlock balance detected!"),
				report: compile("WARNING: bad unlock balance detected!(?:.*\\n){0,15}?.*is trying to release lock(?:.*\\n){0,15}?.*{{PC}} +{{FUNC}}"),
				fmt:    "WARNING: bad unlock balance in %[1]v",
			},
			{
				title:  compile("WARNING: held lock freed!"),
				report: compile("WARNING: held lock freed!(?:.*\\n)+?.*{{PC}} +{{FUNC}}"),
				fmt:    "WARNING: held lock freed in %[1]v",
			},
			{
				title:        compile("WARNING: kernel stack regs .* has bad 'bp' value"),
				fmt:          "WARNING: kernel stack regs has bad value",
				noStackTrace: true,
			},
			{
				title:        compile("WARNING: kernel stack frame pointer .* has bad value"),
				fmt:          "WARNING: kernel stack regs has bad value",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{
			compile("WARNING: /etc/ssh/moduli does not exist, using fixed modulus"), // printed by sshd
		},
	},
	{
		[]byte("INFO:"),
		[]oopsFormat{
			{
				title:  compile("INFO: possible circular locking dependency detected"),
				report: compile("INFO: possible circular locking dependency detected \\](?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("INFO: possible irq lock inversion dependency detected"),
				report: compile("INFO: possible irq lock inversion dependency detected \\](?:.*\\n)+?.*just changed the state of lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("INFO: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected"),
				report: compile("INFO: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected \\](?:.*\\n)+?.*is trying to acquire(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("INFO: possible recursive locking detected"),
				report: compile("INFO: possible recursive locking detected \\](?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:    "possible deadlock in %[1]v",
			},
			{
				title:  compile("INFO: inconsistent lock state"),
				report: compile("INFO: inconsistent lock state \\](?:.*\\n)+?.*takes(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:    "inconsistent lock state in %[1]v",
			},
			{
				title: linuxRcuStall,
				fmt:   "INFO: rcu detected stall in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("apic_timer_interrupt"),
						parseStackTrace,
					},
					skip: []string{"apic_timer_interrupt", "rcu"},
				},
			},
			{
				title: linuxRcuStall,
				fmt:   "INFO: rcu detected stall in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
						parseStackTrace,
					},
					skip: []string{"apic_timer_interrupt", "rcu"},
				},
			},
			{
				title: compile("INFO: trying to register non-static key"),
				fmt:   "INFO: trying to register non-static key in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"stack", "lock", "IRQ"},
				},
			},
			{
				title:  compile("INFO: suspicious RCU usage"),
				report: compile("INFO: suspicious RCU usage(?:.*\n)+?.*?{{SRC}}"),
				fmt:    "INFO: suspicious RCU usage in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"rcu", "kmem", "slab", "kmalloc",
						"vmalloc", "kcalloc", "kzalloc"},
				},
			},
			{
				title: compile("INFO: task .* blocked for more than [0-9]+ seconds"),
				fmt:   "INFO: task hung in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"sched", "_lock", "down", "completion", "kthread",
						"wait", "synchronize"},
				},
			},
			{
				// This gets captured for corrupted old-style KASAN reports.
				title:     compile("INFO: (Freed|Allocated) in (.*)"),
				fmt:       "INFO: %[1]v in %[2]v",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{
			compile("INFO: lockdep is turned off"),
			compile("INFO: Stall ended before state dump start"),
			compile("INFO: NMI handler"),
			compile("(handler|interrupt).*took too long"),
			compile("_INFO::"),                                       // Android can print this during boot.
			compile("INFO: sys_.* is not present in /proc/kallsyms"), // pkg/host output in debug mode
			compile("INFO: no syscalls can create resource"),         // pkg/host output in debug mode
		},
	},
	{
		[]byte("Unable to handle kernel paging request"),
		[]oopsFormat{
			{
				title:  compile("Unable to handle kernel paging request"),
				report: compile("Unable to handle kernel paging request(?:.*\\n)+?.*PC is at {{FUNC}}"),
				fmt:    "unable to handle kernel paging request in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("general protection fault:"),
		[]oopsFormat{
			{
				title: compile("general protection fault:"),
				fmt:   "general protection fault in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("Kernel panic"),
		[]oopsFormat{
			{
				title: compile("Kernel panic - not syncing: Attempted to kill init!"),
				fmt:   "kernel panic: Attempted to kill init!",
			},
			{
				title: compile("Kernel panic - not syncing: Couldn't open N_TTY ldisc for [^ ]+ --- error -[0-9]+"),
				fmt:   "kernel panic: Couldn't open N_TTY ldisc",
			},
			{
				// 'kernel panic: Fatal exception' is usually printed after BUG,
				// so if we captured it as a report description, that means the
				// report got truncated and we missed the actual BUG header.
				title:     compile("Kernel panic - not syncing: Fatal exception"),
				fmt:       "kernel panic: Fatal exception",
				corrupted: true,
			},
			{
				// Same, but for WARNINGs and KASAN reports.
				title:     compile("Kernel panic - not syncing: panic_on_warn set"),
				fmt:       "kernel panic: panic_on_warn set",
				corrupted: true,
			},
			{
				// Same, but for task hung reports.
				title:     compile("Kernel panic - not syncing: hung_task: blocked tasks"),
				fmt:       "kernel panic: hung_task: blocked tasks",
				corrupted: true,
			},
			{
				title: compile("Kernel panic - not syncing: (.*)"),
				fmt:   "kernel panic: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("kernel BUG"),
		[]oopsFormat{
			{
				title: compile("kernel BUG at mm/usercopy.c"),
				fmt:   "BUG: bad usercopy in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				title: compile("kernel BUG at lib/list_debug.c"),
				fmt:   "BUG: corrupted list in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("Kernel BUG"),
		[]oopsFormat{
			{
				title: compile("Kernel BUG (.*)"),
				fmt:   "kernel BUG %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("BUG kmalloc-"),
		[]oopsFormat{
			{
				title: compile("BUG kmalloc-.*: Object already free"),
				fmt:   "BUG: Object already free",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("divide error:"),
		[]oopsFormat{
			{
				title:  compile("divide error: "),
				report: compile("divide error: (?:.*\\n)+?.*RIP: [0-9]+:(?:{{PC}} +{{PC}} +)?{{FUNC}}"),
				fmt:    "divide error in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("invalid opcode:"),
		[]oopsFormat{
			{
				title:  compile("invalid opcode: "),
				report: compile("invalid opcode: (?:.*\\n)+?.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				fmt:    "invalid opcode in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("UBSAN:"),
		[]oopsFormat{
			{
				title: compile("UBSAN: (.*)"),
				fmt:   "UBSAN: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("Booting the kernel."),
		[]oopsFormat{
			{
				title:        compile("Booting the kernel."),
				fmt:          "unexpected kernel reboot",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("unregister_netdevice: waiting for"),
		[]oopsFormat{
			{
				title:        compile("unregister_netdevice: waiting for (?:.*) to become free"),
				fmt:          "unregister_netdevice: waiting for DEV to become free",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
