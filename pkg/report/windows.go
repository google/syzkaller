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

func (ctx *windows) Parse(output []byte) *Report {
	panic("not implemented")
}

func (ctx *windows) Symbolize(rep *Report) error {
	panic("not implemented")
}
