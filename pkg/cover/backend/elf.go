// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/sys/targets"
)

func makeELF(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule) (*Impl, error) {
	return makeDWARF(target, objDir, srcDir, buildDir, moduleObj, hostModules,
		&containerFns{
			readSymbols:           elfReadSymbols,
			readTextData:          elfReadTextData,
			readModuleCoverPoints: elfReadModuleCoverPoints,
		},
	)
}

func elfReadSymbols(module *Module, info *symbolInfo) ([]*Symbol, error) {
	file, err := elf.Open(module.Path)
	if err != nil {
		return nil, err
	}
	debugInfo, err := file.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to parse DWARF: %v (set CONFIG_DEBUG_INFO=y on linux)", err)
	}
	text := file.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section in the object file")
	}
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF symbols: %v", err)
	}
	info.textAddr = text.Addr
	for i, symb := range allSymbols {
		text := symb.Value >= text.Addr && symb.Value+symb.Size <= text.Addr+text.Size
		if strings.HasPrefix(symb.Name, "__sanitizer_cov_trace_") {
			if symb.Name == "__sanitizer_cov_trace_pc" {
				info.tracePCIdx[i] = true
				if text {
					info.tracePC = symb.Value
				}
			} else {
				info.traceCmpIdx[i] = true
				if text {
					info.traceCmp[symb.Value] = true
				}
			}
		}
	}

	textSecIdx := 0
	for i, sec := range file.Sections {
		if sec.Name == ".text" {
			textSecIdx = i
		}
	}
	textSymbols := make(map[string]bool)
	for _, s := range allSymbols {
		if s.Info&0xf == uint8(elf.STT_FUNC) {
			if s.Section == elf.SectionIndex(textSecIdx) {
				textSymbols[s.Name] = true
			}
		}
	}
	allDwarfFunctions, err := readSymbolsFromDwarf(debugInfo, textSymbols)
	if err != nil {
		return nil, err
	}
	var symbols []*Symbol
	for _, ds := range allDwarfFunctions {
		if len(ds.Ranges) == 0 {
			continue
		}
		start := ds.Ranges[0][0]
		end := ds.Ranges[len(ds.Ranges)-1][1]
		var ranges [][2]uint64
		for _, r := range ds.Ranges {
			ranges = append(ranges, [2]uint64{
				r[0] + module.Addr,
				r[1] + module.Addr,
			})
		}
		text := start >= text.Addr && end <= text.Addr+text.Size
		if text {
			symbols = append(symbols, &Symbol{
				Module: module,
				ObjectUnit: ObjectUnit{
					Name: ds.Name,
				},
				Start:  start + module.Addr,
				End:    end + module.Addr,
				Ranges: ranges,
				Inline: ds.Inline,
				Unit: &CompileUnit{
					Module: module,
					ObjectUnit: ObjectUnit{
						Name: ds.DeclFile,
					},
				},
			})
		}
	}
	return symbols, nil
}

func elfReadTextData(module *Module) ([]byte, error) {
	file, err := elf.Open(module.Path)
	if err != nil {
		return nil, err
	}
	text := file.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section in the object file")
	}
	return text.Data()
}

func elfReadModuleCoverPoints(target *targets.Target, module *Module, info *symbolInfo) ([2][]uint64, error) {
	var pcs [2][]uint64
	file, err := elf.Open(module.Path)
	if err != nil {
		return pcs, err
	}
	callRelocType := arches[target.Arch].callRelocType
	relaOffset := arches[target.Arch].relaOffset
	for _, s := range file.Sections {
		if s.Type != elf.SHT_RELA { // nolint: misspell
			continue
		}
		rel := new(elf.Rela64)
		for r := s.Open(); ; {
			if err := binary.Read(r, binary.LittleEndian, rel); err != nil {
				if err == io.EOF {
					break
				}
				return pcs, err
			}
			if (rel.Info & 0xffffffff) != callRelocType {
				continue
			}
			pc := module.Addr + rel.Off - relaOffset
			index := int(elf.R_SYM64(rel.Info)) - 1
			if info.tracePCIdx[index] {
				pcs[0] = append(pcs[0], pc)
			} else if info.traceCmpIdx[index] {
				pcs[1] = append(pcs[1], pc)
			}
		}
	}
	return pcs, nil
}
