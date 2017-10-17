// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type akaros struct {
	kernelSrc string
	kernelObj string
	symbols   map[string][]symbolizer.Symbol
	ignores   []*regexp.Regexp
}

func ctorAkaros(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &akaros{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		symbols:   symbols,
		ignores:   ignores,
	}
	return ctx, nil
}

func (ctx *akaros) ContainsCrash(output []byte) bool {
	panic("not implemented")
}

func (ctx *akaros) Parse(output []byte) (desc string, text []byte, start int, end int) {
	panic("not implemented")
}

func (ctx *akaros) Symbolize(text []byte) ([]byte, error) {
	panic("not implemented")
}

func (ctx *akaros) ExtractConsoleOutput(output []byte) (result []byte) {
	panic("not implemented")
}

func (ctx *akaros) ExtractGuiltyFile(report []byte) string {
	panic("not implemented")
}

func (ctx *akaros) GetMaintainers(file string) ([]string, error) {
	panic("not implemented")
}
