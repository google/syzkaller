// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"debug/elf"
	"fmt"

	"github.com/google/syzkaller/sys/targets"
)

type Symbol struct {
	Addr uint64
	Size int
}

// ReadTextSymbols returns list of text symbols in the binary bin.
func (s *Symbolizer) ReadTextSymbols(bin string) (map[string][]Symbol, error) {
	return read(s.target, bin, true)
}

// ReadRodataSymbols returns list of rodata symbols in the binary bin.
func (s *Symbolizer) ReadRodataSymbols(bin string) (map[string][]Symbol, error) {
	return read(s.target, bin, false)
}

func read(target *targets.Target, bin string, text bool) (map[string][]Symbol, error) {
	file, err := elf.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file %v: %v", bin, err)
	}
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF symbols: %v", err)
	}
	symbols := make(map[string][]Symbol)
	for _, symb := range allSymbols {
		if symb.Size == 0 || symb.Section < 0 || int(symb.Section) >= len(file.Sections) {
			continue
		}
		sect := file.Sections[symb.Section]
		isText := sect.Type == elf.SHT_PROGBITS &&
			sect.Flags&(elf.SHF_WRITE|elf.SHF_ALLOC|elf.SHF_EXECINSTR) == (elf.SHF_ALLOC|elf.SHF_EXECINSTR)
		// Note: x86_64 vmlinux .rodata is marked as writable and according to flags it looks like .data,
		// so we look at the name.
		if text && !isText || !text && sect.Name != ".rodata" {
			continue
		}
		// Note: function sizes reported by kernel do not match symbol tables.
		// Kernel probably subtracts address of this symbol from address of the next symbol.
		// We could do the same, but for now we just round up size to 16.
		size := int(symb.Size)
		if text {
			size = (size + 15) / 16 * 16
		}
		symbols[symb.Name] = append(symbols[symb.Name], Symbol{symb.Value, size})
	}
	return symbols, nil
}
