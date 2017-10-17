// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type freebsd struct {
	kernelSrc string
	kernelObj string
	symbols   map[string][]symbolizer.Symbol
	ignores   []*regexp.Regexp
}

func ctorFreebsd(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &freebsd{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		symbols:   symbols,
		ignores:   ignores,
	}
	return ctx, nil
}

func (ctx *freebsd) ContainsCrash(output []byte) bool {
	panic("not implemented")
}

func (ctx *freebsd) Parse(output []byte) (desc string, text []byte, start int, end int) {
	panic("not implemented")
}

func (ctx *freebsd) Symbolize(text []byte) ([]byte, error) {
	panic("not implemented")
}

func (ctx *freebsd) ExtractConsoleOutput(output []byte) (result []byte) {
	panic("not implemented")
}

func (ctx *freebsd) ExtractGuiltyFile(report []byte) string {
	panic("not implemented")
}

func (ctx *freebsd) GetMaintainers(file string) ([]string, error) {
	panic("not implemented")
}
