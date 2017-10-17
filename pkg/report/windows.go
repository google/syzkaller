// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type windows struct {
	kernelSrc string
	kernelObj string
	symbols   map[string][]symbolizer.Symbol
	ignores   []*regexp.Regexp
}

func ctorWindows(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &windows{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		symbols:   symbols,
		ignores:   ignores,
	}
	return ctx, nil
}

func (ctx *windows) ContainsCrash(output []byte) bool {
	panic("not implemented")
}

func (ctx *windows) Parse(output []byte) (desc string, text []byte, start int, end int) {
	panic("not implemented")
}

func (ctx *windows) Symbolize(text []byte) ([]byte, error) {
	panic("not implemented")
}

func (ctx *windows) ExtractConsoleOutput(output []byte) (result []byte) {
	panic("not implemented")
}

func (ctx *windows) ExtractGuiltyFile(report []byte) string {
	panic("not implemented")
}

func (ctx *windows) GetMaintainers(file string) ([]string, error) {
	panic("not implemented")
}
