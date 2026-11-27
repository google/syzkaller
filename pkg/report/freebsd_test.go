// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreebsdSymbolizeLine(t *testing.T) {
	fbsd, symb := testFreebsdSymbolizer(t)
	tests := []struct {
		name   string
		line   string
		result string
	}{
		{
			name: "trap_rip_inline",
			line: "instruction pointer\t= 0x20:0xffffffff8202f244\n",
			result: `instruction pointer	= 0x20:0xffffffff8202f244 cache_uz_flags sys/vm/uma_int.h:303 [inline]
instruction pointer	= 0x20:0xffffffff8202f244 uma_zfree_arg sys/vm/uma_core.c:4536
`,
		},
		{
			name: "kdb_stack_pc_inline",
			line: "#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91\n",
			result: `#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91 xpt_free_ccb sys/cam/cam_xpt.c:4561 [inline]
#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91 sys/cam/cam_xpt.c:3850
`,
		},
		{
			name: "ddb_stack_frame",
			line: "sctp_sosend() at sctp_sosend+0x157/frame 0xfffffe009524a7a0\n",
			result: "sctp_sosend() at sctp_sosend+0x157/frame 0xfffffe009524a7a0 " +
				"sys/netinet/sctp_output.c:1234\n",
		},
		{
			name: "ddb_stack_frame_inline_vm_build_path",
			line: "sofree() at sofree+0x42c/frame 0xfffffe001fa0e6b0\n",
			result: `sofree() at sofree+0x42c/frame 0xfffffe001fa0e6b0 sorele_locked sys/kern/uipc_socket.c:910 [inline]
sofree() at sofree+0x42c/frame 0xfffffe001fa0e6b0 sys/kern/uipc_socket.c:1280
`,
		},
		{
			name:   "ddb_stopped_at_padded",
			line:   "Stopped at      kdb_enter+0x6a: movq    $0,kdb_why\n",
			result: "Stopped at      kdb_enter+0x6a sys/kern/subr_kdb.c:556: movq    $0,kdb_why\n",
		},
		{
			name:   "ddb_stopped_at_single_space",
			line:   "Stopped at kdb_enter+0x6a: movq $0,kdb_why\n",
			result: "Stopped at kdb_enter+0x6a sys/kern/subr_kdb.c:556: movq $0,kdb_why\n",
		},
		{
			name:   "static_symbol_disambiguated_by_size",
			line:   "filt_read() at filt_read+0x150/frame 0xfffffe001facc8b0\n",
			result: "filt_read() at filt_read+0x150/frame 0xfffffe001facc8b0 sys/kern/sys_pipe.c:1750\n",
		},
		{
			name:   "ambiguous_static_symbol",
			line:   "filt_read() at filt_read+0x20/frame 0xfffffe001facc8b0\n",
			result: "filt_read() at filt_read+0x20/frame 0xfffffe001facc8b0\n",
		},
		{
			name:   "offset_out_of_bounds",
			line:   "kdb_enter() at kdb_enter+0x500/frame 0xfffffe001facc8b0\n",
			result: "kdb_enter() at kdb_enter+0x500/frame 0xfffffe001facc8b0\n",
		},
		{
			name:   "return_pc_zero_offset",
			line:   "kdb_enter() at kdb_enter+0x0/frame 0xfffffe001facc8b0\n",
			result: "kdb_enter() at kdb_enter+0x0/frame 0xfffffe001facc8b0\n",
		},
		{
			name:   "missing_symbol",
			line:   "unknown_fn() at unknown_fn+0x10/frame 0xfffffe001facc8b0\n",
			result: "unknown_fn() at unknown_fn+0x10/frame 0xfffffe001facc8b0\n",
		},
		{
			name:   "non_frame_prose_with_at",
			line:   "panic: unexpected fault at kdb_enter+0x6a\n",
			result: "panic: unexpected fault at kdb_enter+0x6a\n",
		},
		{
			name:   "plain_line",
			line:   "panic: page fault\n",
			result: "panic: page fault\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := string(fbsd.symbolizeLine(symb, []byte(test.line)))
			assert.Equal(t, test.result, got)
		})
	}
}

func TestFreebsdSymbolizeReport(t *testing.T) {
	t.Run("no_kernel_object", func(t *testing.T) {
		reporter, _, err := ctorFreebsd(&config{})
		require.NoError(t, err)
		orig := "panic: page fault\n#0 0xffffffff8039e2f1 at xpt_release_ccb+0x91\n"
		rep := &Report{Report: []byte(orig)}
		require.NoError(t, reporter.Symbolize(rep))
		assert.Equal(t, orig, string(rep.Report))
	})

	t.Run("updates_prefix_len", func(t *testing.T) {
		fbsd, symb := testFreebsdSymbolizer(t)
		prefix := "#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91\n"
		body := "panic: page fault\nStopped at kdb_enter+0x6a: movq $0,kdb_why\n"
		rep := &Report{
			Report:          []byte(prefix + body),
			reportPrefixLen: len(prefix),
		}
		symbolizeReportLines(rep, symb, fbsd.symbolizeLine)
		wantPrefix := `#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91 xpt_free_ccb sys/cam/cam_xpt.c:4561 [inline]
#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91 sys/cam/cam_xpt.c:3850
`
		wantBody := `panic: page fault
Stopped at kdb_enter+0x6a sys/kern/subr_kdb.c:556: movq $0,kdb_why
`
		assert.Equal(t, wantPrefix+wantBody, string(rep.Report))
		assert.Equal(t, len(wantPrefix), rep.reportPrefixLen)
	})
}

func testFreebsdSymbolizer(t *testing.T) (*freebsd, bsdSymbFunc) {
	t.Helper()
	symbols := map[string][]symbolizer.Symbol{
		"sctp_sosend": {
			{Addr: 0xffffffff80c00000, Size: 0x2000},
		},
		"sofree": {
			{Addr: 0xffffffff80d00000, Size: 0x2000},
		},
		"kdb_enter": {
			{Addr: 0xffffffff817b0000, Size: 0x200},
		},
		"filt_read": {
			{Addr: 0xffffffff80e00000, Size: 0x40},
			{Addr: 0xffffffff80f00000, Size: 0x200},
		},
	}
	symb := func(bin string, pcs ...uint64) ([]symbolizer.Frame, error) {
		if bin != "kernel.full" {
			return nil, fmt.Errorf("unexpected bin %q", bin)
		}
		var res []symbolizer.Frame
		for _, pc := range pcs {
			switch pc {
			case 0xffffffff8202f244:
				res = append(res,
					symbolizer.Frame{
						Func:   "cache_uz_flags",
						File:   "/usr/src/sys/vm/uma_int.h",
						Line:   303,
						Inline: true,
					},
					symbolizer.Frame{
						Func: "uma_zfree_arg",
						File: "/usr/src/sys/vm/uma_core.c",
						Line: 4536,
					},
				)
			case 0xffffffff8039e2f0: // 0xffffffff8039e2f1 - 1
				res = append(res,
					symbolizer.Frame{
						Func:   "xpt_free_ccb",
						File:   "/usr/src/sys/cam/cam_xpt.c",
						Line:   4561,
						Inline: true,
					},
					symbolizer.Frame{
						Func: "xpt_release_ccb",
						File: "/usr/src/sys/cam/cam_xpt.c",
						Line: 3850,
					},
				)
			case 0xffffffff80c00156: // 0xffffffff80c00000 + 0x157 - 1
				res = append(res, symbolizer.Frame{
					Func: "sctp_sosend",
					File: "/freebsd/src/sys/netinet/sctp_output.c",
					Line: 1234,
				})
			case 0xffffffff80d0042b: // 0xffffffff80d00000 + 0x42c - 1
				res = append(res,
					symbolizer.Frame{
						Func:   "sorele_locked",
						File:   "/build/src/sys/kern/uipc_socket.c",
						Line:   910,
						Inline: true,
					},
					symbolizer.Frame{
						Func: "sofree",
						File: "/build/src/sys/kern/uipc_socket.c",
						Line: 1280,
					},
				)
			case 0xffffffff817b006a: // 0xffffffff817b0000 + 0x6a (exact)
				res = append(res, symbolizer.Frame{
					Func: "kdb_enter",
					File: "/usr/src/sys/kern/subr_kdb.c",
					Line: 556,
				})
			case 0xffffffff80f0014f: // 0xffffffff80f00000 + 0x150 - 1
				res = append(res, symbolizer.Frame{
					Func: "filt_read",
					File: "/freebsd/src/sys/kern/sys_pipe.c",
					Line: 1750,
				})
			default:
				return nil, fmt.Errorf("unknown pc 0x%x", pc)
			}
		}
		return res, nil
	}

	reporter, _, err := ctorFreebsd(&config{
		kernelDirs: mgrconfig.KernelDirs{
			Src:      "/freebsd/src",
			BuildSrc: "/freebsd/src",
		},
	})
	require.NoError(t, err)
	fbsd := reporter.(*freebsd)
	fbsd.symbols = symbols
	fbsd.kernelObject = "kernel.full"
	return fbsd, symb
}
