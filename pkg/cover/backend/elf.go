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
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
)

func makeELF(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule) (*Impl, error) {
	return makeDWARF(target, objDir, srcDir, buildDir, moduleObj, hostModules,
		&containerFns{
			readSymbols:           elfReadSymbols,
			readTextData:          elfReadTextData,
			readModuleCoverPoints: elfReadModuleCoverPoints,
			readTextRanges:        elfReadTextRanges,
		},
	)
}

func elfReadSymbols(module *Module, info *symbolInfo) ([]*Symbol, error) {
	file, err := elf.Open(module.Path)
	if err != nil {
		return nil, err
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
	var symbols []*Symbol
	for i, symb := range allSymbols {
		text := symb.Value >= text.Addr && symb.Value+symb.Size <= text.Addr+text.Size
		if text {
			start := symb.Value + module.Addr
			symbols = append(symbols, &Symbol{
				Module: module,
				ObjectUnit: ObjectUnit{
					Name: symb.Name,
				},
				Start: start,
				End:   start + symb.Size,
			})
		}
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
	return symbols, nil
}

func elfReadTextRanges(module *Module) ([]pcRange, []*CompileUnit, error) {
	file, err := elf.Open(module.Path)
	if err != nil {
		return nil, nil, err
	}
	text := file.Section(".text")
	if text == nil {
		return nil, nil, fmt.Errorf("no .text section in the object file")
	}
	kaslr := file.Section(".rela.text") != nil
	debugInfo, err := file.DWARF()
	if err != nil {
		if module.Name != "" {
			log.Logf(0, "ignoring module %v without DEBUG_INFO", module.Name)
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to parse DWARF: %v (set CONFIG_DEBUG_INFO=y on linux)", err)
	}

	var pcFix pcFixFn
	if kaslr {
		pcFix = func(r [2]uint64) ([2]uint64, bool) {
			if r[0] >= r[1] || r[0] < text.Addr || r[1] > text.Addr+text.Size {
				// Linux kernel binaries with CONFIG_RANDOMIZE_BASE=y are strange.
				// .text starts at 0xffffffff81000000 and symbols point there as
				// well, but PC ranges point to addresses around 0.
				// So try to add text offset and retry the check.
				// It's unclear if we also need some offset on top of text.Addr,
				// it gives approximately correct addresses, but not necessary
				// precisely correct addresses.
				r[0] += text.Addr
				r[1] += text.Addr
				if r[0] >= r[1] || r[0] < text.Addr || r[1] > text.Addr+text.Size {
					return r, true
				}
			}
			return r, false
		}
	}

	return readTextRanges(debugInfo, module, pcFix)
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
	offset := uint64(arches[target.Arch].opcodeOffset)
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
			// Note: this assumes that call instruction is 1 byte.
			pc := module.Addr + rel.Off - 1
			index := int(elf.R_SYM64(rel.Info)) - 1
			pc -= offset
			if info.tracePCIdx[index] {
				pcs[0] = append(pcs[0], pc)
			} else if info.traceCmpIdx[index] {
				pcs[1] = append(pcs[1], pc)
			}
		}
	}
	return pcs, nil
}
