// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import "github.com/google/syzkaller/sys/targets"

type Frame struct {
	PC     uint64
	Func   string
	File   string
	Line   int
	Column int
	Inline bool
}

type Symbolizer interface {
	Symbolize(bin string, pcs ...uint64) ([]Frame, error)
	Close()
	Name() string
}

func Make(target *targets.Target, bin string) (Symbolizer, error) {
	if target != nil && target.Arch == targets.AMD64 && bin != "" {
		if s, err := newELFSymbolizer(bin); err == nil {
			return s, nil
		}
	}
	return &addr2Line{target: target}, nil
}
