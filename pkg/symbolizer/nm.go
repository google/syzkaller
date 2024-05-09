// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"debug/elf"
	"fmt"
	"sort"
)

type Symbol struct {
	Addr uint64
	Size int
}

// ReadTextSymbols returns list of text symbols in the binary bin.
func (s *Symbolizer) ReadTextSymbols(bin string) (map[string][]Symbol, error) {
	return read(bin, true)
}

// ReadRodataSymbols returns list of rodata symbols in the binary bin.
func (s *Symbolizer) ReadRodataSymbols(bin string) (map[string][]Symbol, error) {
	return read(bin, false)
}

func read(bin string, text bool) (map[string][]Symbol, error) {
	raw, err := load(bin, text)
	if err != nil {
		return nil, err
	}
	sort.Slice(raw, func(i, j int) bool {
		return raw[i].Value > raw[j].Value
	})
	symbols := make(map[string][]Symbol)
	// Function sizes reported by the Linux kernel do not match symbol tables.
	// The kernel computes size of a symbol based on the start of the next symbol.
	// We need to do the same to match kernel sizes to be able to find the right
	// symbol across multiple symbols with the same name.
	var prevAddr uint64
	var prevSize int
	for _, symb := range raw {
		size := int(symb.Size)
		if text {
			if symb.Value == prevAddr {
				size = prevSize
			} else if prevAddr != 0 {
				size = int(prevAddr - symb.Value)
			}
			prevAddr, prevSize = symb.Value, size
		}
		symbols[symb.Name] = append(symbols[symb.Name], Symbol{symb.Value, size})
	}
	return symbols, nil
}

func load(bin string, text bool) ([]elf.Symbol, error) {
	file, err := elf.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file %v: %w", bin, err)
	}
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF symbols: %w", err)
	}
	var symbols []elf.Symbol
	for _, symb := range allSymbols {
		if symb.Size == 0 || symb.Section < 0 || int(symb.Section) >= len(file.Sections) {
			continue
		}
		sect := file.Sections[symb.Section]
		isText := sect.Type == elf.SHT_PROGBITS &&
			sect.Flags&elf.SHF_ALLOC != 0 &&
			sect.Flags&elf.SHF_EXECINSTR != 0
		// Note: x86_64 vmlinux .rodata is marked as writable and according to flags it looks like .data,
		// so we look at the name.
		if text && !isText || !text && sect.Name != ".rodata" {
			continue
		}
		symbols = append(symbols, symb)
	}
	return symbols, nil
}
