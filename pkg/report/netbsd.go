// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type netbsd struct {
	kernelSrc string
	kernelObj string
	symbols   map[string][]symbolizer.Symbol
	ignores   []*regexp.Regexp
}

func ctorNetbsd(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &netbsd{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		symbols:   symbols,
		ignores:   ignores,
	}
	return ctx, nil
}

func (ctx *netbsd) ContainsCrash(output []byte) bool {
	return false
}

func (ctx *netbsd) Parse(output []byte) *Report {
	return nil
}

func (ctx *netbsd) Symbolize(rep *Report) error {
	return nil
}
