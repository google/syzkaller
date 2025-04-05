// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import "github.com/google/syzkaller/sys/targets"

type Frame struct {
	PC     uint64
	Func   string
	File   string
	Line   int
	Inline bool
}

type Symbolizer interface {
	Symbolize(bin string, pcs ...uint64) ([]Frame, error)
	Close()
}

func Make(target *targets.Target) Symbolizer {
	return &addr2Line{target: target}
}
