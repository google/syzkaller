// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type fuchsia struct {
	kernelSrc string
	kernelObj string
	symbols   map[string][]symbolizer.Symbol
	ignores   []*regexp.Regexp
}

func ctorFuchsia(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &fuchsia{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		symbols:   symbols,
		ignores:   ignores,
	}
	return ctx, nil
}

func (ctx *fuchsia) ContainsCrash(output []byte) bool {
	panic("not implemented")
}

func (ctx *fuchsia) Parse(output []byte) (desc string, text []byte, start int, end int) {
	panic("not implemented")
}

func (ctx *fuchsia) Symbolize(text []byte) ([]byte, error) {
	panic("not implemented")
}

func (ctx *fuchsia) ExtractConsoleOutput(output []byte) (result []byte) {
	panic("not implemented")
}

func (ctx *fuchsia) ExtractGuiltyFile(report []byte) string {
	panic("not implemented")
}

func (ctx *fuchsia) GetMaintainers(file string) ([]string, error) {
	panic("not implemented")
}
