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
	kernelSrc           string
	kernelObj           string
	vmlinux             string
	symbols             map[string][]symbolizer.Symbol
	ignores             []*regexp.Regexp
	consoleOutputRe     *regexp.Regexp
	questionableRe      *regexp.Regexp
	guiltyFileBlacklist []*regexp.Regexp
	eoi                 []byte
}

func ctorLinux(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	vmlinux := ""
	if kernelObj != "" {
		vmlinux = filepath.Join(kernelObj, "vmlinux")
		if symbols == nil {
			var err error
			symbols, err = symbolizer.ReadSymbols(vmlinux)
			if err != nil {
				return nil, err
			}
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
		regexp.MustCompile(`^mm/sl.b.c`),
		regexp.MustCompile(`^mm/percpu.*`),
		regexp.MustCompile(`^mm/vmalloc.c`),
		regexp.MustCompile(`^mm/page_alloc.c`),
		regexp.MustCompile(`^kernel/rcu/.*`),
		regexp.MustCompile(`^arch/.*/kernel/traps.c`),
		regexp.MustCompile(`^arch/.*/mm/fault.c`),
		regexp.MustCompile(`^kernel/locking/*`),
		regexp.MustCompile(`^kernel/panic.c`),
		regexp.MustCompile(`^kernel/softirq.c`),
		regexp.MustCompile(`^kernel/kthread.c`),
		regexp.MustCompile(`^kernel/sched/*.c`),
		regexp.MustCompile(`^kernel/time/timer.c`),
		regexp.MustCompile(`^net/core/dev.c`),
		regexp.MustCompile(`^net/core/sock.c`),
		regexp.MustCompile(`^net/core/skbuff.c`),
	}
	return ctx, nil
}

func (ctx *linux) ContainsCrash(output []byte) bool {
	return containsCrash(output, linuxOopses, ctx.ignores)
}

func (ctx *linux) Parse(output []byte) *Report {
	rep := &Report{
		Output: output,
	}
	var oops *oops
	var logReportPrefix [][]byte
	var consoleReportPrefix [][]byte
	var consoleReport []byte
	textLines := 0
	skipText := false
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops1 := range linuxOopses {
			match := matchOops(output[pos:next], oops1, ctx.ignores)
			if match == -1 {
				continue
			}
			if oops == nil {
				oops = oops1
				rep.StartPos = pos
				rep.Title = string(output[pos+match : next])
			}
			rep.EndPos = next
		}
		if oops == nil {
			logReportPrefix = append(logReportPrefix, append([]byte{}, output[pos:next]...))
			if len(logReportPrefix) > 5 {
				logReportPrefix = logReportPrefix[1:]
			}
		}
		if ctx.consoleOutputRe.Match(output[pos:next]) &&
			(!ctx.questionableRe.Match(output[pos:next]) ||
				bytes.Index(output[pos:next], ctx.eoi) != -1) {
			lineStart := bytes.Index(output[pos:next], []byte("] ")) + pos + 2
			lineEnd := next
			if lineEnd != 0 && output[lineEnd-1] == '\r' {
				lineEnd--
			}
			if oops == nil {
				consoleReportPrefix = append(consoleReportPrefix, append([]byte{}, output[lineStart:lineEnd]...))
				if len(consoleReportPrefix) > 5 {
					consoleReportPrefix = consoleReportPrefix[1:]
				}
			} else {
				textLines++
				ln := output[lineStart:lineEnd]
				skipLine := skipText
				if bytes.Contains(ln, []byte("Disabling lock debugging due to kernel taint")) {
					skipLine = true
				} else if textLines > 40 && bytes.Contains(ln, []byte("Kernel panic - not syncing")) {
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
				}
			}
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	var report []byte
	var reportPrefix [][]byte
	// Try extracting report from console output only.
	title, format := extractDescription(consoleReport, oops)
	if len(title) != 0 {
		// Success.
		report = consoleReport
		reportPrefix = consoleReportPrefix
	} else {
		// Failure. Try extracting report from the whole log.
		report = output[rep.StartPos:]
		reportPrefix = logReportPrefix
		title, format = extractDescription(report, oops)
		if len(title) == 0 {
			panic(fmt.Sprintf("non matching oops for %q in:\n%s", oops.header, report))
		}
	}
	rep.Title = title
	// Prepend 5 lines preceding start of the report,
	// they can contain additional info related to the report.
	for _, prefix := range reportPrefix {
		rep.Report = append(rep.Report, prefix...)
		rep.Report = append(rep.Report, '\n')
	}
	rep.Report = append(rep.Report, report...)
	rep.Corrupted = ctx.isCorrupted(title, report, format)
	// Executor PIDs are not interesting.
	rep.Title = executorRe.ReplaceAllLiteralString(rep.Title, "syz-executor")
	// Replace that everything looks like an address with "ADDR",
	// addresses in descriptions can't be good regardless of the oops regexps.
	rep.Title = addrRe.ReplaceAllString(rep.Title, "${1}ADDR")
	// Replace that everything looks like a decimal number with "NUM".
	rep.Title = decNumRe.ReplaceAllString(rep.Title, "${1}NUM")
	// Replace that everything looks like a file line number with "LINE".
	rep.Title = lineNumRe.ReplaceAllLiteralString(rep.Title, ":LINE")
	// Replace all raw references to runctions (e.g. "ip6_fragment+0x1052/0x2d80")
	// with just function name ("ip6_fragment"). Offsets and sizes are not stable.
	rep.Title = funcRe.ReplaceAllString(rep.Title, "$1")
	// CPU numbers are not interesting.
	rep.Title = cpuRe.ReplaceAllLiteralString(rep.Title, "CPU")
	return rep
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
	// Strip vmlinux location from all paths.
	strip, _ := filepath.Abs(ctx.vmlinux)
	strip = filepath.Dir(strip) + string(filepath.Separator)
	// Vmlinux may have been moved, so check if we can find debug info
	// for __sanitizer_cov_trace_pc. We know where it is located,
	// so we can infer correct strip prefix from it.
	if covSymbols := ctx.symbols["__sanitizer_cov_trace_pc"]; len(covSymbols) != 0 {
		for _, covSymb := range covSymbols {
			frames, _ := symb.Symbolize(ctx.vmlinux, covSymb.Addr)
			if len(frames) > 0 {
				file := frames[len(frames)-1].File
				if idx := strings.Index(file, "kernel/kcov.c"); idx != -1 {
					strip = file[:idx]
					break
				}
			}
		}
	}
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
		if strings.HasPrefix(file, strip) {
			file = file[len(strip):]
		}
		if strings.HasPrefix(file, "./") {
			file = file[2:]
		}
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
		files = append(files, string(bytes.Split(match, []byte{':'})[0]))
	}
	return files
}

func (ctx *linux) isCorrupted(title string, report []byte, format oopsFormat) bool {
	// Check if this crash format is marked as corrupted.
	if format.corrupted {
		return true
	}
	// Check that the report matches report regexp.
	if format.report != nil && !format.report.Match(report) {
		return true
	}
	// Check if the report contains stack trace.
	if !format.noStackTrace && !bytes.Contains(report, []byte("Call Trace")) && !bytes.Contains(report, []byte("backtrace")) {
		return true
	}
	// Check for common title corruptions.
	for _, re := range linuxCorruptedTitles {
		if re.MatchString(title) {
			return true
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
			return true
		}
		frames = frames[1:]
		corrupted := true
		// Check that at least one of the next 10 lines contains a frame.
	outer:
		for i := 0; i < 10 && i < len(frames); i++ {
			for _, key1 := range linuxStackKeywords {
				// Next stack trace starts.
				if key1.Match(frames[i]) {
					break outer
				}
			}
			if bytes.Contains(frames[i], []byte("(stack is not available)")) || stackFrameRe.Match(frames[i]) {
				corrupted = false
				break
			}
		}
		if corrupted {
			return true
		}
	}
	return false
}

var (
	filenameRe       = regexp.MustCompile(`[a-zA-Z0-9_\-\./]*[a-zA-Z0-9_\-]+\.(c|h):[0-9]+`)
	linuxSymbolizeRe = regexp.MustCompile(`(?:\[\<(?:[0-9a-f]+)\>\])?[ \t]+(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	stackFrameRe     = regexp.MustCompile(`^ *(?:\[\<(?:[0-9a-f]+)\>\])?[ \t]+(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	lineNumRe        = regexp.MustCompile(`(:[0-9]+)+`)
	addrRe           = regexp.MustCompile(`([^a-zA-Z])(?:0x)?[0-9a-f]{8,}`)
	decNumRe         = regexp.MustCompile(`([^a-zA-Z])[0-9]{5,}`)
	funcRe           = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9_.]+)\+0x[0-9a-z]+/0x[0-9a-z]+`)
	cpuRe            = regexp.MustCompile(`CPU#[0-9]+`)
	executorRe       = regexp.MustCompile(`syz-executor[0-9]+((/|:)[0-9]+)?`)
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

func stacktraceRe(frameBlacklist ...string) string {
	consumeRe := "(?:[^ ].*\\n)*"
	if len(frameBlacklist) > 0 {
		blacklistRe := "(?:" + strings.Join(frameBlacklist, "|") + ")"
		blacklistFrameRe := "(?:.*" + blacklistRe + ".*\\n)"
		consumeRe = "(?:" + blacklistFrameRe + "|" + "(?:[^ ].*\\n)" + ")*"
	}
	return consumeRe + " (?:{{PC}} )?{{FUNC}}"
}

var linuxOopses = []*oops{
	&oops{
		[]byte("BUG:"),
		[]oopsFormat{
			{
				title: compile("BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+?.*(Read|Write) of size ([0-9]+)"),
				fmt:   "KASAN: %[1]v %[3]v in %[2]v",
			},
			{
				title: compile("BUG: KASAN: ([a-z\\-]+) on address(?:.*\\n)+?.*(Read|Write) of size ([0-9]+)"),
				fmt:   "KASAN: %[1]v %[2]v",
			},
			{
				title: compile("BUG: KASAN: (.*)"),
				fmt:   "KASAN: %[1]v",
			},
			{
				title: compile("BUG: unable to handle kernel paging request(?:.*\\n)+?.*IP: (?:{{PC}} +)?{{FUNC}}"),
				fmt:   "BUG: unable to handle kernel paging request in %[1]v",
			},
			{
				title: compile("BUG: unable to handle kernel paging request"),
				fmt:   "BUG: unable to handle kernel paging request",
			},
			{
				title: compile("BUG: unable to handle kernel NULL pointer dereference(?:.*\\n)+?.*IP: (?:{{PC}} +)?{{FUNC}}"),
				fmt:   "BUG: unable to handle kernel NULL pointer dereference in %[1]v",
			},
			{
				// Happens when the kernel tries to execute code at NULL.
				title: compile("BUG: unable to handle kernel NULL pointer dereference"),
				fmt:   "BUG: unable to handle kernel NULL pointer dereference",
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
				fmt:   "BUG: spinlock %[1]v",
			},
			{
				title: compile("BUG: soft lockup"),
				fmt:   "BUG: soft lockup",
			},
			{
				title: compile("BUG: .*still has locks held!(?:.*\\n)+?.*{{PC}} +{{FUNC}}"),
				fmt:   "BUG: still has locks held in %[1]v",
			},
			{
				title:  compile("BUG: bad unlock balance detected!(?:.*\\n)+?.*{{PC}} +{{FUNC}}"),
				report: compile("BUG: bad unlock balance detected!(?:.*\\n){0,5}?.*is trying to release lock"),
				fmt:    "BUG: bad unlock balance in %[1]v",
			},
			{
				// If we failed to extract function name where the fault happened, the report is most likely truncated.
				title:     compile("BUG: bad unlock balance detected!"),
				fmt:       "BUG: bad unlock balance",
				corrupted: true,
			},
			{
				title: compile("BUG: held lock freed!(?:.*\\n)+?.*{{PC}} +{{FUNC}}"),
				fmt:   "BUG: held lock freed in %[1]v",
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
				title: compile("BUG: Bad page state.*"),
				fmt:   "BUG: Bad page state",
			},
			{
				title: compile("BUG: Bad page map.*"),
				fmt:   "BUG: Bad page map",
			},
			{
				title: compile("BUG: spinlock bad magic.*"),
				fmt:   "BUG: spinlock bad magic",
			},
			{
				title:        compile("BUG: workqueue lockup.*"),
				fmt:          "BUG: workqueue lockup",
				noStackTrace: true,
			},
			{
				title: compile("BUG: sleeping function called from invalid context (.*)"),
				fmt:   "BUG: sleeping function called from invalid context %[1]v",
			},
			{
				title: compile("BUG: using __this_cpu_add\\(\\) in preemptible (.*)"),
				fmt:   "BUG: using __this_cpu_add() in preemptible %[1]v",
			},
			{
				title:        compile("BUG: executor-detected bug"),
				fmt:          "BUG: executor-detected bug",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{
			// Android prints this sometimes during boot.
			compile("Boot_DEBUG:"),
		},
	},
	&oops{
		[]byte("WARNING:"),
		[]oopsFormat{
			{
				title: compile("WARNING: .* at {{SRC}} {{FUNC}}"),
				fmt:   "WARNING in %[2]v",
			},
			{
				title: compile("WARNING: possible circular locking dependency detected(?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("WARNING: possible circular locking dependency detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("WARNING: possible irq lock inversion dependency detected(?:.*\\n)+?.*just changed the state of lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("WARNING: possible irq lock inversion dependency detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected(?:.*\\n)+?.*is trying to acquire(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("WARNING: possible recursive locking detected(?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("WARNING: possible recursive locking detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("WARNING: inconsistent lock state(?:.*\\n)+?.*takes(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "inconsistent lock state in %[1]v",
			},
			{
				title: compile("WARNING: suspicious RCU usage(?:.*\n)+?.*?{{SRC}}"),
				fmt:   "suspicious RCU usage at %[1]v",
			},
			{
				title:     compile("WARNING: suspicious RCU usage"),
				fmt:       "suspicious RCU usage",
				corrupted: true,
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
		},
		[]*regexp.Regexp{
			compile("WARNING: /etc/ssh/moduli does not exist, using fixed modulus"), // printed by sshd
		},
	},
	&oops{
		[]byte("INFO:"),
		[]oopsFormat{
			{
				title: compile("INFO: possible circular locking dependency detected \\](?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("INFO: possible circular locking dependency detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("INFO: possible irq lock inversion dependency detected \\](?:.*\\n)+?.*just changed the state of lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("INFO: possible irq lock inversion dependency detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("INFO: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected \\](?:.*\\n)+?.*is trying to acquire(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("INFO: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("INFO: possible recursive locking detected \\](?:.*\\n)+?.*is trying to acquire lock(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "possible deadlock in %[1]v",
			},
			{
				title: compile("INFO: possible recursive locking detected"),
				fmt:   "possible deadlock",
			},
			{
				title: compile("INFO: inconsistent lock state \\](?:.*\\n)+?.*takes(?:.*\\n)+?.*at: {{PC}} +{{FUNC}}"),
				fmt:   "inconsistent lock state in %[1]v",
			},
			{
				title: compile("INFO: rcu_(?:preempt|sched|bh) detected(?: expedited)? stalls(?:.*\\n)+?.*</IRQ>.*\\n" + stacktraceRe("rcu")),
				fmt:   "INFO: rcu detected stall in %[1]v",
			},
			{
				title: compile("INFO: rcu_(?:preempt|sched|bh) detected(?: expedited)? stalls"),
				fmt:   "INFO: rcu detected stall",
			},
			{
				title: compile("INFO: rcu_(?:preempt|sched|bh) self-detected stall on CPU(?:.*\\n)+?.*</IRQ>.*\\n" + stacktraceRe("rcu")),
				fmt:   "INFO: rcu detected stall in %[1]v",
			},
			{
				title: compile("INFO: rcu_(?:preempt|sched|bh) self-detected stall on CPU"),
				fmt:   "INFO: rcu detected stall",
			},
			{
				title: compile("INFO: trying to register non-static key(?:.*\\n){0,10}Call Trace:\\n" + stacktraceRe("stack", "lock", "IRQ")),
				fmt:   "INFO: trying to register non-static key in %[1]v",
			},
			{
				title: compile("INFO: trying to register non-static key"),
				fmt:   "INFO: trying to register non-static key",
			},
			{
				title: compile("INFO: suspicious RCU usage(?:.*\n)+?.*?{{SRC}}"),
				fmt:   "suspicious RCU usage at %[1]v",
			},
			{
				title:     compile("INFO: suspicious RCU usage"),
				fmt:       "suspicious RCU usage",
				corrupted: true,
			},
			{
				title: compile("INFO: task .* blocked for more than [0-9]+ seconds(?:.*\\n){0,10}Call Trace:\\n" + stacktraceRe("sched", "_lock", "completion", "kthread")),
				fmt:   "INFO: task hung in %[1]v",
			},
			{
				title: compile("INFO: task .* blocked for more than [0-9]+ seconds"),
				fmt:   "INFO: task hung",
			},
		},
		[]*regexp.Regexp{
			compile("INFO: lockdep is turned off"),
			compile("INFO: Stall ended before state dump start"),
			compile("INFO: NMI handler .* took too long to run"),
			compile("_INFO::"), // Android can print this during boot.
		},
	},
	&oops{
		[]byte("Unable to handle kernel paging request"),
		[]oopsFormat{
			{
				title: compile("Unable to handle kernel paging request(?:.*\\n)+?.*PC is at {{FUNC}}"),
				fmt:   "unable to handle kernel paging request in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("general protection fault:"),
		[]oopsFormat{
			{
				title: compile("general protection fault:(?:.*\\n)+?.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				fmt:   "general protection fault in %[1]v",
			},
			{
				title: compile("general protection fault:(?:.*\\n)+?.*RIP: [0-9]+:{{FUNC}}"),
				fmt:   "general protection fault in %[1]v",
			},
			{
				// If we failed to extract function name where the fault happened, the report is most likely truncated.
				title:     compile("general protection fault"),
				fmt:       "general protection fault",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
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
				title: compile("Kernel panic - not syncing: (.*)"),
				fmt:   "kernel panic: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("kernel BUG"),
		[]oopsFormat{
			{
				title: compile("kernel BUG at mm/usercopy.c(?:.*\\n)+?Call Trace:\\n" + stacktraceRe()),
				fmt:   "BUG: bad usercopy in %[1]v",
			},
			{
				title: compile("kernel BUG (.*)"),
				fmt:   "kernel BUG %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("Kernel BUG"),
		[]oopsFormat{
			{
				title: compile("Kernel BUG (.*)"),
				fmt:   "kernel BUG %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("BUG kmalloc-"),
		[]oopsFormat{
			{
				title: compile("BUG kmalloc-.*: Object already free"),
				fmt:   "BUG: Object already free",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("divide error:"),
		[]oopsFormat{
			{
				title: compile("divide error: (?:.*\\n)+?.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				fmt:   "divide error in %[1]v",
			},
			{
				title: compile("divide error: (?:.*\\n)+?.*RIP: [0-9]+:{{FUNC}}"),
				fmt:   "divide error in %[1]v",
			},
			{
				// If we failed to extract function name where the fault happened, the report is most likely truncated.
				title:     compile("divide error"),
				fmt:       "divide error",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("invalid opcode:"),
		[]oopsFormat{
			{
				title: compile("invalid opcode: (?:.*\\n)+?.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				fmt:   "invalid opcode in %[1]v",
			},
			{
				title: compile("invalid opcode: (?:.*\\n)+?.*RIP: [0-9]+:{{FUNC}}"),
				fmt:   "invalid opcode in %[1]v",
			},
			{
				// If we failed to extract function name where the fault happened, the report is most likely truncated.
				title:     compile("invalid opcode"),
				fmt:       "invalid opcode",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("unreferenced object"),
		[]oopsFormat{
			{
				title: compile("unreferenced object {{ADDR}} \\(size ([0-9]+)\\):(?:.*\n.*)+backtrace:.*\n.*{{PC}}.*\n.*{{PC}}.*\n.*{{PC}} {{FUNC}}"),
				fmt:   "memory leak in %[2]v (size %[1]v)",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("UBSAN:"),
		[]oopsFormat{
			{
				title: compile("UBSAN: (.*)"),
				fmt:   "UBSAN: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
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
}
