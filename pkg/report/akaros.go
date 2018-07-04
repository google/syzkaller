// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"regexp"
)

type akaros struct {
	ignores []*regexp.Regexp
}

func ctorAkaros(kernelSrc, kernelObj string, ignores []*regexp.Regexp) (Reporter, []string, error) {
	ctx := &akaros{
		ignores: ignores,
	}
	return ctx, nil, nil
}

func (ctx *akaros) ContainsCrash(output []byte) bool {
	return containsCrash(output, akarosOopses, ctx.ignores)
}

func (ctx *akaros) Parse(output []byte) *Report {
	rep := &Report{
		Output: output,
	}
	var oops *oops
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		line := output[pos:next]
		for _, oops1 := range akarosOopses {
			match := matchOops(line, oops1, ctx.ignores)
			if match != -1 {
				oops = oops1
				rep.StartPos = pos
				break
			}
		}
		if oops != nil {
			break
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, _ := extractDescription(output[rep.StartPos:], oops, nil)
	rep.Title = title
	rep.Report = output[rep.StartPos:]
	rep.Corrupted = corrupted != ""
	rep.corruptedReason = corrupted
	return rep
}

func (ctx *akaros) Symbolize(rep *Report) error {
	return nil
}

// kernel panic at kern/src/vfs.c:1359, from core 1: assertion failed: buf == buf_end
// kernel panic at kern/src/ns/sysfile.c:719, from core 1: assertion failed: n >= sizeof(struct kdirent)
/// $ kernel panic at kern/src/slab.c:518, from core 1: [German Accent]: OOM for a small slab growth!!!
var akarosOopses = []*oops{
	&oops{
		[]byte("kernel panic"),
		[]oopsFormat{
			{
				title:        compile("kernel panic .* assertion failed: (.*)"),
				fmt:          "assertion failed: %[1]v",
				noStackTrace: true,
			},
			{
				title:        compile("kernel panic .* from core [0-9]+: (.*)"),
				fmt:          "kernel panic: %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
