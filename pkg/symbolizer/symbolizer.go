// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"github.com/google/syzkaller/sys/targets"
)

type Frame struct {
	PC     uint64
	Func   string
	File   string
	Line   int
	Inline bool
}

type Symbolizer interface {
	Symbolize(pcs ...uint64) ([]Frame, error)
	Close()
}

func Make(target *targets.Target, binPath string, extInterner ...*Interner) Symbolizer {
	i := &Interner{}
	if len(extInterner) > 0 {
		i = extInterner[0]
	}
	return &addr2Liner{target: target, binPath: binPath, interner: i}
}

type MultiBinSymbolizer struct {
	symbolizers map[string]Symbolizer
	target      *targets.Target
	interner    Interner
}

func MakeMultiBin(target *targets.Target) *MultiBinSymbolizer {
	return &MultiBinSymbolizer{target: target}
}

func (m *MultiBinSymbolizer) Get(binPath string) Symbolizer {
	if _, exists := m.symbolizers[binPath]; !exists {
		m.symbolizers[binPath] = Make(m.target, binPath, &m.interner)
	}
	return m.symbolizers[binPath]
}

func (m *MultiBinSymbolizer) Close() {
	for _, symb := range m.symbolizers {
		symb.Close()
	}
}
