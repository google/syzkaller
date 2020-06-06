// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/symbolizer"
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
	symb := func(bin string, pc uint64) ([]symbolizer.Frame, error) {
		if bin != "bsd.gdb" {
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		}

		switch pc & 0xffffffff {
		case 0x8150894f:
			return []symbolizer.Frame{
				{
					Func: "closef",
					File: "/bsd/src/kern_descrip.c",
					Line: 1241,
				},
			}, nil
		case 0x81237542:
			return []symbolizer.Frame{
				{
					Func:   "sleep_finish_timeout",
					File:   "/bsd/src/kern_synch.c",
					Line:   336,
					Inline: true,
				},
				{
					Func: "sleep_finish_all",
					File: "/bsd/src/kern_synch.c",
					Line: 157,
				},
			}, nil
		default:
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		}
	}
	reporter, _, err := ctor(&config{
		kernelSrc:      "/bsd/src2",
		kernelBuildSrc: "/bsd/src",
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
