// Copyright 2018 syzkaller project authors. All rights reserved.
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

type symbolizeLineTest struct {
	line   string
	result string
}

func testSymbolizeLine(t *testing.T, ctor fn, tests []symbolizeLineTest) {
	symbols := map[string][]symbolizer.Symbol{
		"closef": {
			{Addr: 0x815088a0, Size: 0x12f},
		},
		"sleep_finish_all": {
			{Addr: 0x81237520, Size: 0x173},
		},
	}
	symb := func(bin string, pcs ...uint64) ([]symbolizer.Frame, error) {
		var res []symbolizer.Frame
		for _, pc := range pcs {
			if bin != "bsd.gdb" {
				return nil, fmt.Errorf("unknown pc 0x%x", pc)
			}

			switch pc & 0xffffffff {
			case 0x8150894f:
				res = append(res, symbolizer.Frame{
					Func: "closef",
					File: "/bsd/src/kern_descrip.c",
					Line: 1241,
				})
			case 0x81237542:
				res = append(res,
					symbolizer.Frame{
						Func:   "sleep_finish_timeout",
						File:   "/bsd/src/kern_synch.c",
						Line:   336,
						Inline: true,
					},
					symbolizer.Frame{
						Func: "sleep_finish_all",
						File: "/bsd/src/kern_synch.c",
						Line: 157,
					},
				)
			default:
				return nil, fmt.Errorf("unknown pc 0x%x", pc)
			}
		}
		return res, nil
	}
	reporter, _, err := ctor(&config{
		kernelDirs: mgrconfig.KernelDirs{
			Src:      "/bsd/src2",
			BuildSrc: "/bsd/src",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bsd := reporter.(*bsd)
	bsd.symbols = symbols
	bsd.kernelObject = "bsd.gdb"
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := bsd.symbolizeLine(symb, []byte(test.line))
			if test.result != string(result) {
				t.Errorf("want %q\n\t     get %q", test.result, string(result))
			}
		})
	}
}

func TestBSDSymbolizeReport(t *testing.T) {
	reporter, _, err := ctorOpenbsd(&config{})
	require.NoError(t, err)

	orig := "panic: test\nclosef(ffffffff,ffffffff) at closef+0xaf\n"
	rep := &Report{Report: []byte(orig)}
	require.NoError(t, reporter.Symbolize(rep))
	assert.Equal(t, orig, string(rep.Report))

	bsd := reporter.(*bsd)
	bsd.kernelObject = "bsd.gdb"
	bsd.symbols = map[string][]symbolizer.Symbol{
		"closef": {{Addr: 0x815088a0, Size: 0x12f}},
	}
	symb := func(bin string, pcs ...uint64) ([]symbolizer.Frame, error) {
		return []symbolizer.Frame{{
			Func: "closef",
			File: "/bsd/src/kern_descrip.c",
			Line: 1241,
		}}, nil
	}
	prefix := "closef(ffffffff,ffffffff) at closef+0xaf\n"
	body := "panic: test\n"
	rep = &Report{
		Report:          []byte(prefix + body),
		reportPrefixLen: len(prefix),
	}
	symbolizeReportLines(rep, symb, bsd.symbolizeLine)
	wantPrefix := "closef(ffffffff,ffffffff) at closef+0xaf bsd/src/kern_descrip.c:1241\n"
	assert.Equal(t, wantPrefix+body, string(rep.Report))
	assert.Equal(t, len(wantPrefix), rep.reportPrefixLen)
}
