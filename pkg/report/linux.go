// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/pkg/vcs"
)

type linux struct {
	*config
	vmlinux               string
	symbols               map[string][]symbolizer.Symbol
	consoleOutputRe       *regexp.Regexp
	taskContext           *regexp.Regexp
	cpuContext            *regexp.Regexp
	questionableFrame     *regexp.Regexp
	guiltyFileIgnores     []*regexp.Regexp
	reportStartIgnores    []*regexp.Regexp
	infoMessagesWithStack [][]byte
	eoi                   []byte
}

func ctorLinux(cfg *config) (Reporter, []string, error) {
	var symbols map[string][]symbolizer.Symbol
	vmlinux := ""
	if cfg.kernelObj != "" {
		vmlinux = filepath.Join(cfg.kernelObj, cfg.target.KernelObject)
		var err error
		symb := symbolizer.NewSymbolizer(cfg.target)
		symbols, err = symb.ReadTextSymbols(vmlinux)
		if err != nil {
			return nil, nil, err
		}
	}
	ctx := &linux{
		config:  cfg,
		vmlinux: vmlinux,
		symbols: symbols,
	}
	// nolint: lll
	ctx.consoleOutputRe = regexp.MustCompile(`^(?:\*\* [0-9]+ printk messages dropped \*\* )?(?:.* login: )?(?:\<[0-9]+\>)?\[ *[0-9]+\.[0-9]+\](\[ *(?:C|T)[0-9]+\])? `)
	ctx.taskContext = regexp.MustCompile(`\[ *T[0-9]+\]`)
	ctx.cpuContext = regexp.MustCompile(`\[ *C[0-9]+\]`)
	ctx.questionableFrame = regexp.MustCompile(`(\[\<[0-9a-f]+\>\])? \? `)
	ctx.eoi = []byte("<EOI>")
	ctx.guiltyFileIgnores = []*regexp.Regexp{
		regexp.MustCompile(`.*\.h`),
		regexp.MustCompile(`^lib/.*`),
		regexp.MustCompile(`^virt/lib/.*`),
		regexp.MustCompile(`^mm/kasan/.*`),
		regexp.MustCompile(`^mm/kmsan/.*`),
		regexp.MustCompile(`^kernel/kcov.c`),
		regexp.MustCompile(`^mm/sl.b.c`),
		regexp.MustCompile(`^mm/memory.c`),
		regexp.MustCompile(`^mm/percpu.*`),
		regexp.MustCompile(`^mm/vmalloc.c`),
		regexp.MustCompile(`^mm/page_alloc.c`),
		regexp.MustCompile(`^mm/util.c`),
		regexp.MustCompile(`^kernel/rcu/.*`),
		regexp.MustCompile(`^arch/.*/kernel/traps.c`),
		regexp.MustCompile(`^arch/.*/mm/fault.c`),
		regexp.MustCompile(`^arch/.*/mm/physaddr.c`),
		regexp.MustCompile(`^kernel/locking/.*`),
		regexp.MustCompile(`^kernel/panic.c`),
		regexp.MustCompile(`^kernel/printk/printk.*.c`),
		regexp.MustCompile(`^kernel/softirq.c`),
		regexp.MustCompile(`^kernel/kthread.c`),
		regexp.MustCompile(`^kernel/sched/.*.c`),
		regexp.MustCompile(`^kernel/time/timer.c`),
		regexp.MustCompile(`^kernel/workqueue.c`),
		regexp.MustCompile(`^net/core/dev.c`),
		regexp.MustCompile(`^net/core/sock.c`),
		regexp.MustCompile(`^net/core/skbuff.c`),
		regexp.MustCompile(`^fs/proc/generic.c`),
		regexp.MustCompile(`^trusty/`), // Trusty sources are not in linux kernel tree.
	}
	// These pattern do _not_ start a new report, i.e. can be in a middle of another report.
	ctx.reportStartIgnores = []*regexp.Regexp{
		compile(`invalid opcode: 0000`),
		compile(`Kernel panic - not syncing`),
		compile(`unregister_netdevice: waiting for`),
		// Double fault can happen during handling of paging faults
		// if memory is badly corrupted. Also it usually happens
		// synchronously, which means that maybe the report is not corrupted.
		// But of course it can come from another CPU as well.
		compile(`PANIC: double fault`),
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

const contextConsole = "console"

func (ctx *linux) ContainsCrash(output []byte) bool {
	return containsCrash(output, linuxOopses, ctx.ignores)
}

func (ctx *linux) Parse(output []byte) *Report {
	oops, startPos, context := ctx.findFirstOops(output)
	if oops == nil {
		return nil
	}
	for questionable := false; ; questionable = true {
		rep := &Report{
			Output:   output,
			StartPos: startPos,
		}
		endPos, reportEnd, report, prefix := ctx.findReport(output, oops, startPos, context, questionable)
		rep.EndPos = endPos
		title, corrupted, format := extractDescription(report[:reportEnd], oops, linuxStackParams)
		if title == "" {
			prefix = nil
			report = output[rep.StartPos:rep.EndPos]
			title, corrupted, format = extractDescription(report, oops, linuxStackParams)
			if title == "" {
				panic(fmt.Sprintf("non matching oops for %q context=%q in:\n%s\n",
					oops.header, context, report))
			}
		}
		rep.Title = title
		rep.Corrupted = corrupted != ""
		rep.CorruptedReason = corrupted
		for _, line := range prefix {
			rep.Report = append(rep.Report, line...)
			rep.Report = append(rep.Report, '\n')
		}
		rep.reportPrefixLen = len(rep.Report)
		rep.Report = append(rep.Report, report...)
		if !rep.Corrupted {
			rep.Corrupted, rep.CorruptedReason = ctx.isCorrupted(title, report, format)
		}
		if rep.CorruptedReason == corruptedNoFrames && context != contextConsole && !questionable {
			// We used to look at questionable frame with the following incentive:
			// """
			// Some crash reports have all frames questionable.
			// So if we get a corrupted report because there are no frames,
			// try again now looking at questionable frames.
			// Only do this if we have a real context (CONFIG_PRINTK_CALLER=y),
			// to be on the safer side. Without context it's too easy to use
			// a stray frame from a wrong context.
			// """
			// Most likely reports without proper stack traces were caused by a bug
			// in the unwinder and are now fixed in 187b96db5ca7 "x86/unwind/orc:
			// Fix unwind_get_return_address_ptr() for inactive tasks".
			// Disable trying to use questionable frames for now.
			useQuestionableFrames := false
			if useQuestionableFrames {
				continue
			}
		}
		return rep
	}
}

func (ctx *linux) findFirstOops(output []byte) (oops *oops, startPos int, context string) {
	for pos, next := 0, 0; pos < len(output); pos = next + 1 {
		next = bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		line := output[pos:next]
		for _, oops1 := range linuxOopses {
			if matchOops(line, oops1, ctx.ignores) {
				oops = oops1
				startPos = pos
				context = ctx.extractContext(line)
				return
			}
		}
	}
	return
}

// Yes, it is complex, but all state and logic are tightly coupled. It's unclear how to simplify it.
// nolint: gocyclo, gocognit
func (ctx *linux) findReport(output []byte, oops *oops, startPos int, context string, useQuestionable bool) (
	endPos, reportEnd int, report []byte, prefix [][]byte) {
	// Prepend 5 lines preceding start of the report,
	// they can contain additional info related to the report.
	maxPrefix := 5
	if ctx.taskContext.MatchString(context) {
		// If we have CONFIG_PRINTK_CALLER, we collect more b/c it comes from the same task.
		maxPrefix = 50
	}
	secondReportPos := 0
	textLines := 0
	skipText, cpuTraceback := false, false
	for pos, next := 0, 0; pos < len(output); pos = next + 1 {
		next = bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		line := output[pos:next]
		context1 := ctx.extractContext(line)
		stripped, questionable := ctx.stripLinePrefix(line, context1, useQuestionable)
		if pos < startPos {
			if context1 == context && len(stripped) != 0 && !questionable {
				prefix = append(prefix, append([]byte{}, stripped...))
				if len(prefix) > maxPrefix {
					prefix = prefix[1:]
				}
			}
			continue
		}
		oopsLine := pos == startPos
		for _, oops1 := range linuxOopses {
			if !matchOops(line, oops1, ctx.ignores) {
				if !oopsLine && secondReportPos == 0 {
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
			if !oopsLine && secondReportPos == 0 {
				if !matchesAny(line, ctx.reportStartIgnores) {
					secondReportPos = pos
				}
			}
		}
		if !oopsLine && (questionable ||
			context1 != context && (!cpuTraceback || !ctx.cpuContext.MatchString(context1))) {
			continue
		}
		textLines++
		skipLine := skipText
		if bytes.Contains(line, []byte("Disabling lock debugging due to kernel taint")) {
			skipLine = true
		} else if bytes.Contains(line, []byte("Sending NMI from CPU")) {
			// If we are doing traceback of all CPUs, then we also need to preserve output
			// from other CPUs regardless of what is the current context.
			// Otherwise we will throw traceback away because it does not match the oops context.
			cpuTraceback = true
		} else if textLines > 22 &&
			(bytes.Contains(line, []byte("Kernel panic - not syncing")) ||
				bytes.Contains(line, []byte("WARNING: possible circular locking dependency detected"))) {
			// If panic_on_warn set, then we frequently have 2 stacks:
			// one for the actual report (or maybe even more than one),
			// and then one for panic caused by panic_on_warn. This makes
			// reports unnecessary long and the panic (current) stack
			// is always present in the actual report. So we strip the
			// panic message. However, we check that we have enough lines
			// before the panic, because sometimes we have, for example,
			// a single WARNING line without a stack and then the panic
			// with the stack.
			// Oops messages frequently induce possible deadlock reports
			// because oops reporting introduces unexpected locking chains.
			// So if we have enough of the actual oops, strip the deadlock message.
			skipText = true
			skipLine = true
		}
		if !oopsLine && skipLine {
			continue
		}
		report = append(report, stripped...)
		report = append(report, '\n')
		if secondReportPos == 0 || context != "" && context != contextConsole {
			reportEnd = len(report)
		}
	}
	return
}

func (ctx *linux) stripLinePrefix(line []byte, context string, useQuestionable bool) ([]byte, bool) {
	if last := len(line) - 1; last >= 0 && line[last] == '\r' {
		line = line[:last]
	}
	if context == "" {
		return line, false
	}
	start := bytes.Index(line, []byte("] "))
	line = line[start+2:]
	if !bytes.Contains(line, ctx.eoi) {
		// x86_64 prefix.
		if ctx.questionableFrame.Match(line) {
			pos := bytes.Index(line, []byte(" ? "))
			return line[pos+2:], !useQuestionable
		}
		// PowerPC suffix.
		if bytes.HasSuffix(line, []byte(" (unreliable)")) {
			return line[:len(line)-13], !useQuestionable
		}
	}
	return line, false
}

func (ctx *linux) extractContext(line []byte) string {
	match := ctx.consoleOutputRe.FindSubmatchIndex(line)
	if match == nil {
		return ""
	}
	if match[2] == -1 {
		return contextConsole
	}
	return string(line[match[2]:match[3]])
}

func (ctx *linux) Symbolize(rep *Report) error {
	if ctx.vmlinux != "" {
		if err := ctx.symbolize(rep); err != nil {
			return err
		}
	}
	// We still do this even if we did not symbolize,
	// because tests pass in already symbolized input.
	rep.guiltyFile = ctx.extractGuiltyFile(rep)
	if rep.guiltyFile != "" {
		maintainers, err := ctx.getMaintainers(rep.guiltyFile)
		if err != nil {
			return err
		}
		rep.Recipients = maintainers
	}
	return nil
}

func (ctx *linux) symbolize(rep *Report) error {
	symb := symbolizer.NewSymbolizer(ctx.config.target)
	defer symb.Close()
	var symbolized []byte
	s := bufio.NewScanner(bytes.NewReader(rep.Report))
	prefix := rep.reportPrefixLen
	for s.Scan() {
		line := append([]byte{}, s.Bytes()...)
		line = append(line, '\n')
		newLine := symbolizeLine(symb.Symbolize, ctx.symbols, ctx.vmlinux, ctx.kernelBuildSrc, line)
		if prefix > len(symbolized) {
			prefix += len(newLine) - len(line)
		}
		symbolized = append(symbolized, newLine...)
	}
	rep.Report = symbolized
	rep.reportPrefixLen = prefix
	return nil
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
	pc := funcStart + off
	if !bytes.HasPrefix(line, []byte("IP:")) && !bytes.HasPrefix(line, []byte("RIP:")) {
		// Usually we have return PCs, so we need to look at the previous instruction.
		// But RIP lines contain the exact faulting PC.
		pc--
	}
	frames, err := symbFunc(vmlinux, pc)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	for _, frame := range frames {
		file := frame.File
		file = strings.TrimPrefix(file, strip)
		file = strings.TrimLeft(file, "./")
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

func (ctx *linux) extractGuiltyFile(rep *Report) string {
	report := rep.Report[rep.reportPrefixLen:]
	if strings.HasPrefix(rep.Title, "INFO: rcu detected stall") {
		// Special case for rcu stalls.
		// There are too many frames that we want to skip before actual guilty frames,
		// we would need to ignore too many files and that would be fragile.
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
		for _, re := range ctx.guiltyFileIgnores {
			if re.MatchString(file) {
				continue nextFile
			}
		}
		return file
	}
	// Avoid producing no guilty file at all, otherwise we mail the report to nobody.
	// It's unclear if it's better to return the first one or the last one.
	// So far the only test we have has only one file anyway.
	if len(files) != 0 {
		return files[0]
	}
	return ""
}

func (ctx *linux) getMaintainers(file string) (vcs.Recipients, error) {
	if ctx.kernelSrc == "" {
		return nil, nil
	}
	return GetLinuxMaintainers(ctx.kernelSrc, file)
}

func GetLinuxMaintainers(kernelSrc, file string) (vcs.Recipients, error) {
	mtrs, err := getMaintainersImpl(kernelSrc, file, false)
	if err != nil {
		return nil, err
	}
	if len(mtrs) <= 1 {
		mtrs, err = getMaintainersImpl(kernelSrc, file, true)
		if err != nil {
			return nil, err
		}
	}
	return mtrs, nil
}

func getMaintainersImpl(kernelSrc, file string, blame bool) (vcs.Recipients, error) {
	// See #1441 re --git-min-percent.
	args := []string{"--git-min-percent=15"}
	if blame {
		args = append(args, "--git-blame")
	}
	args = append(args, "-f", file)
	script := filepath.FromSlash("scripts/get_maintainer.pl")
	output, err := osutil.RunCmd(time.Minute, kernelSrc, script, args...)
	if err != nil {
		return nil, err
	}
	return vcs.ParseMaintainersLinux(output), nil
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
	// Check for common title corruptions.
	for _, re := range linuxCorruptedTitles {
		if re.MatchString(title) {
			return true, "title matches corrupted regexp"
		}
	}
	// If the report hasn't matched any of the oops titles, don't mark it as corrupted.
	if format.title == nil {
		return false, ""
	}
	// Check if the report contains stack trace.
	if !format.noStackTrace && !bytes.Contains(report, []byte("Call Trace")) &&
		!bytes.Contains(report, []byte("backtrace")) {
		return true, "no stack trace in report"
	}
	if format.noStackTrace {
		return false, ""
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
				linuxStackFrameRe.Match(frames[i]) {
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

func linuxStallFrameExtractor(frames []string) (string, string) {
	// During rcu stalls and cpu lockups kernel loops in some part of code,
	// usually across several functions. When the stall is detected, traceback
	// points to a random stack within the looping code. We generally take
	// the top function in the stack (with few exceptions) as the bug identity.
	// As the result stalls with the same root would produce multiple reports
	// in different functions, which is bad.
	// Instead we identify a representative function deeper in the stack.
	// For most syscalls it can be the syscall entry function (e.g. SyS_timer_create).
	// However, for highly discriminated functions syscalls like ioctl/read/write/connect
	// we take the previous function (e.g. for connect the one that points to exact
	// protocol, or for ioctl the one that is related to the device).
	prev := frames[0]
	for _, frame := range frames {
		if matchesAny([]byte(frame), linuxStallAnchorFrames) {
			if strings.Contains(frame, "smp_call_function") {
				// In this case we want this function rather than the previous one
				// (there can be several variations on the next one).
				prev = "smp_call_function"
			}
			for _, prefix := range []string{
				"__x64_",
				"SYSC_",
				"SyS_",
				"compat_SYSC_",
				"compat_SyS_",
				"__ia32_sys_",
			} {
				prev = strings.TrimPrefix(prev, prefix)
			}
			return prev, ""
		}
		prev = frame
	}
	return "", "did not find any anchor frame"
}

func linuxHangTaskFrameExtractor(frames []string) (string, string) {
	// The problem with task hung reports is that they manifest at random victim stacks,
	// rather at the root cause stack. E.g. if there is something wrong with RCU subsystem,
	// we are getting hangs all over the kernel on all synchronize_* calls.
	// So before resotring to the common logic of skipping some common frames,
	// we look for 2 common buckets: hangs on synchronize_rcu and hangs on rtnl_lock
	// and group these together.
	const synchronizeRCU = "synchronize_rcu"
	anchorFrames := map[string]string{
		"rtnl_lock":         "",
		"synchronize_rcu":   synchronizeRCU,
		"synchronize_srcu":  synchronizeRCU,
		"synchronize_net":   synchronizeRCU,
		"synchronize_sched": synchronizeRCU,
	}
	for _, frame := range frames {
		for anchor, replacement := range anchorFrames {
			if strings.Contains(frame, anchor) {
				if replacement != "" {
					frame = replacement
				}
				return frame, ""
			}
		}
	}
	skip := []string{"sched", "_lock", "_slowlock", "down", "rwsem", "completion", "kthread",
		"wait", "synchronize", "context_switch", "__switch_to", "cancel_delayed_work"}
nextFrame:
	for _, frame := range frames {
		for _, ignore := range skip {
			if strings.Contains(frame, ignore) {
				continue nextFrame
			}
		}
		return frame, ""
	}
	return "", "all frames are skipped"
}

var linuxStallAnchorFrames = []*regexp.Regexp{
	// Various generic functions that dispatch work.
	// We also include some of their callers, so that if some names change
	// we don't skip whole stacks and proceed parsing the next one.
	compile("process_one_work"),  // workqueue callback
	compile("do_syscall_"),       // syscall entry
	compile("do_fast_syscall_"),  // syscall entry
	compile("sysenter_dispatch"), // syscall entry
	compile("tracesys_phase2"),   // syscall entry
	compile("netif_receive_skb"), // net receive entry point
	compile("do_softirq"),
	compile("call_timer_fn"),
	compile("_run_timers"),
	compile("run_timer_softirq"),
	compile("run_ksoftirqd"),
	compile("smpboot_thread_fn"),
	compile("kthread"),
	compile("start_secondary"),
	compile("cpu_startup_entry"),
	compile("ret_from_fork"),
	// Important discriminated syscalls (file_operations callbacks, etc):
	compile("vfs_write"),
	compile("vfs_read"),
	compile("vfs_iter_read"),
	compile("vfs_iter_write"),
	compile("do_iter_read"),
	compile("do_iter_write"),
	compile("vfs_ioctl"),
	compile("ksys_ioctl"), // vfs_ioctl may be inlined
	compile("compat_ioctl"),
	compile("compat_sys_ioctl"),
	compile("blkdev_driver_ioctl"),
	compile("blkdev_ioctl"),
	compile("^call_read_iter"),
	compile("^call_write_iter"),
	compile("do_iter_readv_writev"),
	compile("^call_mmap"),
	compile("mmap_region"),
	compile("do_mmap"),
	compile("do_dentry_open"),
	compile("vfs_open"),
	// Socket operations:
	compile("^sock_sendmsg"),
	compile("^sock_recvmsg"),
	compile("^sock_release"),
	compile("^__sock_release"),
	compile("__sys_setsockopt"),
	compile("kernel_setsockopt"),
	compile("sock_common_setsockopt"),
	compile("__sys_listen"),
	compile("kernel_listen"),
	compile("sk_common_release"),
	compile("^sock_mmap"),
	compile("__sys_accept"),
	compile("kernel_accept"),
	compile("^sock_do_ioctl"),
	compile("^sock_ioctl"),
	compile("^compat_sock_ioctl"),
	compile("^nfnetlink_rcv_msg"),
	compile("^rtnetlink_rcv_msg"),
	compile("^(compat_)?(SYSC|SyS|__sys|___sys|__do_sys|__se_sys|__x64_sys)_(socketpair|connect|ioctl)"),
	// Page fault entry points:
	compile("__do_fault"),
	compile("handle_mm_fault"),
	compile("do_page_fault"),
	compile("^page_fault$"),
	// exit_to_usermode_loop callbacks:
	compile("__fput"),
	compile("task_work_run"),
	compile("exit_to_usermode"),
	compile("smp_call_function"),
}

// nolint: lll
var (
	linuxSymbolizeRe  = regexp.MustCompile(`(?:\[\<(?:[0-9a-f]+)\>\])?[ \t]+(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	linuxStackFrameRe = regexp.MustCompile(`^ *(?:\[\<?(?:[0-9a-f]+)\>?\] ?){0,2}[ \t]+(?:[0-9]+:)?([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	linuxRipFrame     = compile(`N?IP:? (?:(?:[0-9]+:)?(?:{{PC}} +){0,2}{{FUNC}}|[0-9]+:0x[0-9a-f]+|(?:[0-9]+:)?{{PC}} +\[< *\(null\)>\] +\(null\)|[0-9]+: +\(null\))`)
)

var linuxCorruptedTitles = []*regexp.Regexp{
	// Sometimes timestamps get merged into the middle of report description.
	regexp.MustCompile(`\[ *[0-9]+\.[0-9]+\]`),
}

var linuxStackKeywords = []*regexp.Regexp{
	regexp.MustCompile(`Call Trace`),
	regexp.MustCompile(`Allocated:`),
	regexp.MustCompile(`Allocated by task [0-9]+:`),
	regexp.MustCompile(`Freed:`),
	regexp.MustCompile(`Freed by task [0-9]+:`),
	// Match 'backtrace:', but exclude 'stack backtrace:'
	regexp.MustCompile(`[^k] backtrace:`),
}

var linuxStackParams = &stackParams{
	stackStartRes: linuxStackKeywords,
	frameRes: []*regexp.Regexp{
		compile("^ *(?:{{PC}} ){0,2}{{FUNC}}"),
	},
	skipPatterns: []string{
		"__sanitizer",
		"__asan",
		"kasan",
		"__msan",
		"kmsan",
		"check_memory_region",
		"read_word_at_a_time",
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
		"timer_is_static_object",
		"work_is_static_object",
		"lockdep",
		"perf_trace",
		"lock_acquire",
		"lock_release",
		"lock_class",
		"reacquire_held_locks",
		"spin_lock",
		"spin_trylock",
		"spin_unlock",
		"raw_read_lock",
		"raw_read_trylock",
		"raw_write_lock",
		"raw_write_trylock",
		"down",
		"down_read",
		"down_write",
		"down_read_trylock",
		"down_write_trylock",
		"up_read",
		"up_write",
		"mutex_lock",
		"mutex_trylock",
		"mutex_unlock",
		"mutex_remove_waiter",
		"osq_lock",
		"osq_unlock",
		"__wake_up",
		"refcount_add",
		"refcount_sub",
		"refcount_inc",
		"refcount_dec",
		"refcount_set",
		"refcount_read",
		"memcpy",
		"memcmp",
		"memset",
		"memchr",
		"memmove",
		"strcmp",
		"strncmp",
		"strcpy",
		"strlcpy",
		"strncpy",
		"strscpy",
		"strlen",
		"strnstr",
		"strnlen",
		"strchr",
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
		"_indirect_thunk_", // retpolines
		"string",
		"pointer",
		"snprintf",
		"scnprintf",
		"kasprintf",
		"kvasprintf",
		"printk",
		"va_format",
		"dev_info",
		"dev_notice",
		"dev_warn",
		"dev_err",
		"dev_alert",
		"dev_crit",
		"dev_emerg",
		"program_check_exception",
		"program_check_common",
		"del_timer",
		"flush_work",
		"__cancel_work_timer",
		"cancel_work_sync",
		"try_to_grab_pending",
		"flush_workqueue",
		"drain_workqueue",
		"destroy_workqueue",
		"finish_wait",
		"kthread_stop",
		"kobject_del",
		"kobject_put",
		"kobject_uevent_env",
		"add_uevent_var",
		"get_device_parent",
		"device_add",
		"device_del",
		"device_unregister",
		"device_destroy",
		"device_release",
		"devres_release_all",
		"hwrng_unregister",
		"i2c_del_adapter",
		"__unregister_client",
		"device_for_each_child",
		"rollback_registered",
		"unregister_netdev",
		"sysfs_remove",
		"device_remove_file",
		"tty_unregister_device",
		"dummy_urb_enqueue",
		"usb_kill_urb",
		"usb_kill_anchored_urbs",
		"usb_control_msg",
		"usb_hcd_submit_urb",
		"usb_submit_urb",
		"^complete$",
		"wait_for_completion",
		"^kfree$",
		"kfree_skb",
	},
	corruptedLines: []*regexp.Regexp{
		// Fault injection stacks are frequently intermixed with crash reports.
		// Note: the actual symbol can have all kinds of weird suffixes like ".isra.7", ".cold" or ".isra.56.cold.74".
		compile(`^( \[\<?(?:0x)?[0-9a-f]+\>?\])? should_fail(slab)?(\.[a-z0-9.]+)?\+0x`),
	},
}

func warningStackFmt(skip ...string) *stackFmt {
	return &stackFmt{
		// In newer kernels WARNING traps and actual stack starts after invalid_op frame,
		// older kernels just print stack.
		parts: []*regexp.Regexp{
			// x86_64 warning stack starts with "RIP:" line,
			// while powerpc64 starts with "--- interrupt:".
			compile("(?:" + linuxRipFrame.String() + "|--- interrupt: [0-9]+ at {{FUNC}})"),
			parseStackTrace,
		},
		parts2: []*regexp.Regexp{
			compile("Call Trace:"),
			parseStackTrace,
		},
		skip: skip,
	}
}

// nolint: lll
var linuxOopses = append([]*oops{
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
				title:  compile("BUG: KMSAN: kernel-usb-infoleak"),
				report: compile("BUG: KMSAN: kernel-usb-infoleak in {{FUNC}}"),
				fmt:    "KMSAN: kernel-usb-infoleak in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"usb_submit_urb", "usb_start_wait_urb", "usb_bulk_msg", "usb_interrupt_msg", "usb_control_msg"},
				},
			},
			{
				title:  compile("BUG: KMSAN:"),
				report: compile("BUG: KMSAN: ([a-z\\-]+) in {{FUNC}}"),
				fmt:    "KMSAN: %[1]v in %[3]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("BUG: KCSAN:"),
				report:       compile("BUG: KCSAN: (.*)"),
				fmt:          "KCSAN: %[1]v",
				noStackTrace: true,
			},
			{
				title: compile("BUG: (?:unable to handle kernel paging request|unable to handle page fault for address|Unable to handle kernel data access)"),
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
				title: compile("BUG: (?:unable to handle kernel NULL pointer dereference|kernel NULL pointer dereference|Kernel NULL pointer dereference)"),
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
				title:     compile("BUG: (?:unable to handle kernel|Unable to handle kernel)"),
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
						linuxRipFrame,
						compile("Call Trace:"),
						parseStackTrace,
					},
					extractor: linuxStallFrameExtractor,
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
				title: compile("BUG: sleeping function called from invalid context at (.*)"),
				fmt:   "BUG: sleeping function called from invalid context in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
				},
			},
			{
				title: compile("BUG: using ([a-z_]+)\\(\\) in preemptible"),
				fmt:   "BUG: using %[1]v() in preemptible code in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"dump_stack", "preemption", "preempt", "debug_",
						"processor_id", "this_cpu"},
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
				title: compile("BUG: memory leak"),
				fmt:   memoryLeakPrefix + "%[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("backtrace:"),
						parseStackTrace,
					},
					skip: []string{"kmemleak", "kmalloc", "kcalloc", "kzalloc",
						"vmalloc", "mmap", "kmem", "slab", "alloc", "create_object",
						"idr_get", "list_lru_init", "kasprintf", "kvasprintf",
						"pcpu_create", "strdup", "strndup", "memdup"},
				},
			},
			{
				title: compile("BUG: stack guard page was hit at"),
				fmt:   "BUG: stack guard page was hit in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
					},
				},
				noStackTrace: true,
			},
			{
				title:     compile(`BUG:[[:space:]]*(?:\n|$)`),
				fmt:       "BUG: corrupted",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{
			// CONFIG_DEBUG_OBJECTS output.
			compile("ODEBUG:"),
			// Android prints this sometimes during boot.
			compile("Boot_DEBUG:"),
			compile("xlog_status:"),
			// Android ART debug output.
			compile("DEBUG:"),
			// pkg/host output in debug mode.
			compile("BUG: no syscalls can create resource"),
		},
	},
	{
		[]byte("WARNING:"),
		[]oopsFormat{
			{
				title: compile("WARNING: .*lib/debugobjects\\.c.* (?:debug_print|debug_check)"),
				fmt:   "WARNING: ODEBUG bug in %[1]v",
				// Skip all users of ODEBUG as well.
				stack: warningStackFmt("debug_", "rcu", "hrtimer_", "timer_",
					"work_", "percpu_", "kmem_", "slab_", "kfree", "vunmap",
					"vfree", "__free_", "debug_check", "kobject_"),
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
				stack: warningStackFmt("refcount", "kobject_"),
			},
			{
				title: compile("WARNING: .*kernel/locking/lockdep\\.c.*lock_"),
				fmt:   "WARNING: locking bug in %[1]v",
				stack: warningStackFmt("lock_sock", "release_sock"),
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
				title: compile("WARNING: .* usb_submit_urb"),
				fmt:   "WARNING in %[1]v/usb_submit_urb",
				stack: warningStackFmt("usb_submit_urb", "usb_start_wait_urb", "usb_bulk_msg", "usb_interrupt_msg", "usb_control_msg"),
			},
			{
				title: compile("WARNING: .* at {{SRC}} {{FUNC}}"),
				fmt:   "WARNING in %[3]v",
				stack: warningStackFmt(),
			},
			{
				title:  compile("WARNING: possible circular locking dependency detected"),
				report: compile("WARNING: possible circular locking dependency detected(?:.*\\n)+?.*is trying to acquire lock"),
				fmt:    "possible deadlock in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("at: (?:{{PC}} +)?{{FUNC}}"),
						compile("at: (?:{{PC}} +)?{{FUNC}}"),
						parseStackTrace,
					},
					// These workqueue functions take locks associated with work items.
					// All deadlocks observed in these functions are
					// work-item-subsystem-related.
					skip: []string{"process_one_work", "flush_workqueue",
						"drain_workqueue", "destroy_workqueue"},
				},
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
				report: compile("WARNING: held lock freed!(?:.*\\n)+?.*at:(?: {{PC}})? +{{FUNC}}"),
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
			{
				title:     compile(`WARNING:[[:space:]]*(?:\n|$)`),
				fmt:       "WARNING: corrupted",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{
			compile("WARNING: /etc/ssh/moduli does not exist, using fixed modulus"), // printed by sshd
			compile("WARNING: workqueue cpumask: online intersect > possible intersect"),
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
				title: compile("INFO: rcu_(?:preempt|sched|bh) (?:self-)?detected(?: expedited)? stall"),
				fmt:   "INFO: rcu detected stall in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("apic_timer_interrupt"),
						linuxRipFrame,
						parseStackTrace,
					},
					parts2: []*regexp.Regexp{
						compile("apic_timer_interrupt"),
						parseStackTrace,
					},
					skip:      []string{"apic_timer_interrupt", "rcu"},
					extractor: linuxStallFrameExtractor,
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
					extractor: linuxHangTaskFrameExtractor,
				},
			},
			{
				title: compile("INFO: task .* can't die for more than .* seconds"),
				fmt:   "INFO: task can't die in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"schedule"},
				},
			},
			{
				// This gets captured for corrupted old-style KASAN reports.
				title:     compile("INFO: (Freed|Allocated) in (.*)"),
				fmt:       "INFO: %[1]v in %[2]v",
				corrupted: true,
			},
			{
				title:     compile(`INFO:[[:space:]]*(?:\n|$)`),
				fmt:       "INFO: corrupted",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{
			compile("INFO: lockdep is turned off"),
			compile("INFO: Stall ended before state dump start"),
			compile("INFO: NMI handler"),
			compile("INFO: recovery required on readonly filesystem"),
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
		[]byte("general protection fault"),
		[]oopsFormat{
			{
				title: compile("general protection fault.*:"),
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
		[]byte("stack segment: "),
		[]oopsFormat{
			{
				title: compile("stack segment: "),
				fmt:   "stack segment fault in %[1]v",
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
			// Note: for stack corruption reports kernel may fail
			// to print function symbol name and/or unwind stack.
			{
				title:        compile("Kernel panic - not syncing: stack-protector:"),
				report:       compile("Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: {{FUNC}}"),
				fmt:          "kernel panic: stack is corrupted in %[1]v",
				noStackTrace: true,
			},
			{
				title:  compile("Kernel panic - not syncing: stack-protector:"),
				report: compile("Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: [a-f0-9]+"),
				fmt:    "kernel panic: stack is corrupted in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"stack_chk"},
				},
			},
			{
				title:  compile("Kernel panic - not syncing: corrupted stack end"),
				report: compile("Kernel panic - not syncing: corrupted stack end detected inside scheduler"),
				fmt:    "kernel panic: corrupted stack end in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip:      []string{"schedule", "retint_kernel"},
					extractor: linuxStallFrameExtractor,
				},
			},
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
		[]byte("PANIC: double fault"),
		[]oopsFormat{
			{
				title: compile("PANIC: double fault"),
				fmt:   "PANIC: double fault in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
					},
				},
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
					skip: []string{"usercopy", "__check"},
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
			{
				title: compile("kernel BUG at (.*)"),
				fmt:   "kernel BUG at %[1]v",
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
				title: compile("divide error: "),
				fmt:   "divide error in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
					},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("invalid opcode:"),
		[]oopsFormat{
			{
				title: compile("invalid opcode: "),
				fmt:   "invalid opcode in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						linuxRipFrame,
					},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("UBSAN:"),
		[]oopsFormat{
			{
				title:  compile("UBSAN:"),
				report: compile("UBSAN: Undefined behaviour in"),
				fmt:    "UBSAN: undefined-behaviour in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						compile("Call Trace:"),
						parseStackTrace,
					},
					skip: []string{"ubsan", "overflow"},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("Booting the kernel."),
		[]oopsFormat{
			{
				title:        compile("Booting the kernel."),
				fmt:          unexpectedKernelReboot,
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
	{
		[]byte("trusty: panic"),
		[]oopsFormat{
			{
				title:        compile("trusty: panic.* ASSERT FAILED"),
				report:       compile("trusty: panic \\(.*?\\):(?: DEBUG)? ASSERT FAILED at \\(.*?\\): (.+)"),
				fmt:          "trusty: ASSERT FAILED: %[1]v",
				noStackTrace: true,
			},
			{
				title:     compile("trusty: panic.* ASSERT FAILED.*: *(.*)"),
				fmt:       "trusty: ASSERT FAILED: %[1]v",
				corrupted: true,
			},
			{
				title:        compile("trusty: panic"),
				report:       compile("trusty: panic \\(.*?\\): (.+)"),
				fmt:          "trusty: panic: %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
