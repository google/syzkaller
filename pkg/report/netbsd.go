// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
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

func (ctx *netbsd) Parse(output []byte) (desc string, text []byte, start int, end int) {
	return "", nil, 0, 0
}

func (ctx *netbsd) Symbolize(text []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ctx *netbsd) ExtractConsoleOutput(output []byte) (result []byte) {
	return output
}

func (ctx *netbsd) ExtractGuiltyFile(report []byte) string {
	return ""
}

func (ctx *netbsd) GetMaintainers(file string) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}
