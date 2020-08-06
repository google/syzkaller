// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
)

func ctorOpenbsd(cfg *config) (Reporter, []string, error) {
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
		"panic: fifo_badop called",
	}
	return ctx, suppressions, nil
}

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
		[]byte("panic"),
		[]oopsFormat{
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
				title: compile("kernel: page fault trap, code=0.*\\nStopped at[ ]+([^\\+]+)"),
				fmt:   "uvm_fault: %[1]v",
			},
		},
		[]*regexp.Regexp{
			compile("reorder_kernel"),
		},
	},
}, commonOopses...)
