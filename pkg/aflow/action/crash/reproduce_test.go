// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFaultInjectionInfo(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "empty output",
			output: "",
			want:   "",
		},
		{
			name:   "no fault injection",
			output: "BUG: KASAN: slab-use-after-free in foo\nCall Trace:\n foo+0x123\n",
			want:   "",
		},
		{
			name: "single fault injection block",
			output: "[  602.265237] FAULT_INJECTION: forcing a failure.\n" +
				"[  602.265237] name failslab, interval 1, probability 0, space 0, times 0\n" +
				"[  602.267142] CPU: 1 PID: 27130 Comm: syz-executor2 Not tainted\n" +
				"[  602.269685] Call Trace:\n" +
				"[  602.270155]  dump_stack+0x1db/0x2d0\n" +
				"[  602.272981]  should_fail.cold+0xa/0x14\n" +
				"[  602.277933]  __should_failslab+0x121/0x190\n" +
				"[  602.278628]  should_failslab+0x9/0x14\n" +
				"[  602.279253]  kmem_cache_alloc_trace+0x2d1/0x760\n" +
				"[  602.281722]  netdevice_event+0x353/0x1100\n" +
				"\n" +
				"[  560.713151] WARNING: CPU: 2 PID: 1194 at net/xfrm/xfrm_state.c:2381\n",
			want: "[  602.265237] FAULT_INJECTION: forcing a failure.\n" +
				"[  602.265237] name failslab, interval 1, probability 0, space 0, times 0\n" +
				"[  602.267142] CPU: 1 PID: 27130 Comm: syz-executor2 Not tainted\n" +
				"[  602.269685] Call Trace:\n" +
				"[  602.270155]  dump_stack+0x1db/0x2d0\n" +
				"[  602.272981]  should_fail.cold+0xa/0x14\n" +
				"[  602.277933]  __should_failslab+0x121/0x190\n" +
				"[  602.278628]  should_failslab+0x9/0x14\n" +
				"[  602.279253]  kmem_cache_alloc_trace+0x2d1/0x760\n" +
				"[  602.281722]  netdevice_event+0x353/0x1100",
		},
		{
			name: "multiple fault injection blocks",
			output: "[1] FAULT_INJECTION: forcing a failure.\n" +
				"[1] name failslab\n" +
				"[1]  should_fail+0x1/0x2\n" +
				"\n" +
				"some other output\n" +
				"[2] FAULT_INJECTION: forcing a failure.\n" +
				"[2] name fail_page_alloc\n" +
				"[2]  should_fail+0x3/0x4\n" +
				"\n",
			want: "[1] FAULT_INJECTION: forcing a failure.\n" +
				"[1] name failslab\n" +
				"[1]  should_fail+0x1/0x2\n" +
				"\n" +
				"[2] FAULT_INJECTION: forcing a failure.\n" +
				"[2] name fail_page_alloc\n" +
				"[2]  should_fail+0x3/0x4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFaultInjectionInfo([]byte(tt.output))
			assert.Equal(t, tt.want, got)
		})
	}
}
