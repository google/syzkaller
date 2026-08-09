// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
)

func ctorOpenbsd(cfg *config) (reporterImpl, []string, error) {
	symbolizeRes := []*regexp.Regexp{
		// stack
		regexp.MustCompile(` at ([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
		// witness
		regexp.MustCompile(`#[0-9]+ +([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
	}
	ctx, err := ctorBSD(cfg, openbsdOopses, symbolizeRes)
	if err != nil {
		return nil, nil, err
	}
	suppressions := []string{
		"panic: vop_generic_badop",
		"witness: lock order reversal:\\n(.*\\n)*.*[0-9stnd]+ 0x[0-9a-f]+ inode(.*\\n)*.*lock order .* first seen at",
		"panic:.*send disconnect: Broken pipe",
	}
	return ctx, suppressions, nil
}

// Title a trap panic from its backtrace rather than from ddb's "Stopped at"
// line. On an MP kernel ddb attaches on a CPU that did not fault, so that
// line reads savectx and the very same defect buckets separately on GENERIC
// and on GENERIC.MP. Seen for real: one NULL dereference in dovutimens() is
// open three times over - as "uvm_fault: dovutimens", as "uvm_fault:
// savectx", and as a third bug whose title is the raw ddb line with two CPUs'
// printf output interleaved character by character into it.
//
// The backtrace sits in one of two places depending on the trap: inside a
// "Starting stack trace..." block, or directly after ddb's process table.
// Anchor on neither, and take the first frame-shaped line instead.
//
// Frames to walk past: the trap plumbing that got us into the report, and the
// sanitizer trampolines and byte helpers, which are never themselves the bug
// (so strlcpy attributes to its caller). Kept in step with the KASAN skip
// list used elsewhere in this file. Walking past all of them can leave
// nothing to capture - an MP report in which only the wrong CPU's savectx
// frame survived - and then this format does not match at all and the
// "Stopped at" formats below still apply.
const openbsdSkipFrames = `(?:(?:panic|kerntrap|usertrap|alltraps\w*|savectx|db_enter|` +
	`__asan_(?:load|store)\w*|kasan_mem\w+|memcpy|memmove|memset|memcmp|bcmp|bcopy|` +
	`bzero|kcopy|strcmp|strncmp|strlcpy|strlcat|strlen|strnlen|strncpy|copyin\w*|` +
	`copyout\w*)\([^\n]*\) at [^\n]*\n)*`

// The first frame of that backtrace which is actually a candidate for the bug.
// It has to resolve to a symbol: a jump through a bad pointer prints
// "fffffd802ea85278(...) at 0xfffffd802ea85278", which names nothing, so skip
// it and title by the frame below -- the code that made the bad call.
const openbsdPanicFrame = `(?:.*\n)+?` + openbsdSkipFrames +
	`([A-Za-z0-9_]+)\([^\n]*\) at [A-Za-z_]`

var openbsdOopses = append([]*oops{
	{
		[]byte("cleaned vnode"),
		[]oopsFormat{
			{
				title: compile("cleaned vnode: "),
				fmt:   "panic: cleaned vnode isn't",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic:"),
		[]oopsFormat{
			{
				// A KASAN fault reaches panic() through one of two frame shapes,
				// both skipped here so the title names the real faulting function
				// on the next frame:
				//   - a compiler-inserted access check: __asan_{load,store}N_noabort
				//   - the mem/str interceptors, which call kasan_shadow_check and
				//     panic directly with NO __asan_ frame: kasan_mem{cpy,move,set,cmp}
				// Plus the byte helpers (memcpy/strlcpy/copyin/...) that are callees,
				// never the bug themselves.
				// On MP the initial console panic line can be interleaved
				// character-by-character with another CPU's printf, leaving the
				// only clean "Caught invalid memory access" inside the "show
				// panic" output. The optional prefix lets this format start its
				// match at the same position as the generic "show panic" format
				// below, so it wins the position tie by list order instead of
				// losing by one line.
				title: compile(`(?:\nddb\{\d+\}> show panic(?Us:.*)[*]cpu\d+: )?` +
					`Caught invalid memory access(?Us:.*)\n(?:[^\n]* at ` +
					`(?:__asan_(?:load|store)(?:[0-9]+|N)+_noabort|` +
					`kasan_mem(?:cpy|move|set|cmp)|` +
					`memcpy|memmove|memset|memcmp|` +
					`bcmp|bcopy|bzero|kcopy|strcmp|strncmp|strlcpy|strlcat|strlen|strnlen|` +
					`strncpy|copyin|copyinstr|copyout|copyoutstr)` +
					`\+0x[0-9a-f]+[^\n]*\n)+([A-Za-z0-9_]+)`),
				fmt: "KASAN: invalid memory access in %[1]v",
			},
			{
				title: compile(`\nddb\{\d+\}> show panic(?Us:.*)[*]cpu\d+: ([^\n]+)(?Us:.*)\nddb\{\d+\}> trace`),
				fmt:   "panic: %[1]v",
			},
			{
				title: compile("panic: kernel diagnostic assertion (.+) failed: file \".*/([^\"]+)"),
				fmt:   "assert %[1]v failed in %[2]v",
			},
			{
				title: compile("panic: Data modified on freelist: .* previous type ([^ ]+)"),
				fmt:   "malloc: free list modified: %[1]v",
			},
			{
				title: compile("panic: pool_cache_item_magic_check: ([^ ]+) cpu free list modified"),
				fmt:   "pool: cpu free list modified: %[1]v",
			},
			{
				title: compile("panic: pool_do_put: ([^:]+): double pool_put"),
				fmt:   "pool: double put: %[1]v",
			},
			{
				title: compile("panic: pool_do_get: ([^:]+) free list modified"),
				fmt:   "pool: free list modified: %[1]v",
			},
			{
				title: compile("panic: pool_p_free: ([^:]+) free list modified"),
				fmt:   "pool: free list modified: %[1]v",
			},
			{
				title: compile("panic: timeout_add: to_ticks \\(.+\\) < 0"),
				fmt:   "panic: timeout_add: to_ticks < 0",
			},
			{
				title: compile("panic: attempt to execute user address {{ADDR}} in supervisor mode"),
				fmt:   "panic: attempt to execute user address",
			},
			{
				title: compile("panic: unhandled af"),
				fmt:   "panic: unhandled af",
			},
			{
				title: compile("panic: (kqueue|knote).* ([a-z]+ .*)"),
				fmt:   "kqueue: %[2]v",
			},
			{
				title: compile("panic: receive ([0-9][a-z]*):"),
				fmt:   "soreceive %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("lock order reversal:"),
		[]oopsFormat{
			{
				title: compile("lock order reversal:\\n(?:.*\\n)*lock order data .* missing"),
				fmt:   "witness: reversal: lock order data missing",
			},
			{
				title: compile("lock order reversal:\\n+.*1st {{ADDR}} ([^\\ ]+).*\\n.*2nd {{ADDR}} ([^\\ ]+)"),
				fmt:   "witness: reversal: %[1]v %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("witness:"),
		[]oopsFormat{
			{
				title: compile("witness: thread {{ADDR}} exiting with the following locks held:"),
				fmt:   "witness: thread exiting with locks held",
			},
			{
				title: compile("witness: userret: returning with the following locks held:(.*\\n)+?.*sys_([a-z0-9_]+)\\+"),
				fmt:   "witness: userret: %[2]v",
			},
			{
				title: compile("(witness: .*)"),
				fmt:   "%[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("uvm_fault("),
		[]oopsFormat{
			{
				title: compile("uvm_fault\\(" + openbsdPanicFrame),
				// The report regexp supplies the format arguments when it is
				// set, so it has to carry the same capture group.
				report: compile("uvm_fault\\(" + openbsdPanicFrame +
					"(?:.*\\n)+?.*end trace frame"),
				fmt: "uvm_fault: %[1]v",
			},
			{
				title:  compile("uvm_fault\\((?:.*\\n)+?.*Stopped at[ ]+{{ADDR}}"),
				report: compile("uvm_fault\\((?:.*\\n)+?.*end trace frame"),
				fmt:    "uvm_fault",
			},
			{
				title:  compile("uvm_fault\\((?:.*\\n)+?.*Stopped at[ ]+([^\\+]+)"),
				report: compile("uvm_fault(?:.*\\n)+?.*Stopped at[ ]+([^\\+]+)(?:.*\\n)+?.*end trace frame"),
				fmt:    "uvm_fault: %[1]v",
			},
			{
				title:     compile("uvm_fault\\("),
				fmt:       "uvm_fault",
				corrupted: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("kernel:"),
		[]oopsFormat{
			{
				title: compile("kernel: page fault trap" + openbsdPanicFrame),
				fmt:   "uvm_fault: %[1]v",
			},
			{
				title: compile("kernel: protection fault trap" + openbsdPanicFrame),
				fmt:   "protection_fault: %[1]v",
			},
			{
				title: compile("kernel: page fault trap, code=0.*\\nStopped at[ ]+([^\\+]+)"),
				fmt:   "uvm_fault: %[1]v",
			},
			{
				title: compile("kernel: protection fault trap, code=0.*\\nStopped at[ ]+([^\\+]+)"),
				fmt:   "protection_fault: %[1]v",
			},
		},
		[]*regexp.Regexp{
			compile("reorder_kernel"),
		},
	},
	&groupGoRuntimeErrors,
}, commonOopses...)
