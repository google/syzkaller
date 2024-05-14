// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
)

func makeELF(target *targets.Target, objDir, srcDir, buildDir string, splitBuildDelimiters, moduleObj []string,
	hostModules []KernelModule) (*Impl, error) {
	return makeDWARF(&dwarfParams{
		target:                target,
		objDir:                objDir,
		srcDir:                srcDir,
		buildDir:              buildDir,
		splitBuildDelimiters:  splitBuildDelimiters,
		moduleObj:             moduleObj,
		hostModules:           hostModules,
		readSymbols:           elfReadSymbols,
		readTextData:          elfReadTextData,
		readModuleCoverPoints: elfReadModuleCoverPoints,
		readTextRanges:        elfReadTextRanges,
		getCompilerVersion:    elfGetCompilerVersion,
	})
}

const (
	TraceCbNone int = iota
	TraceCbPc
	TraceCbCmp
)

// Normally, -fsanitize-coverage=trace-pc inserts calls to __sanitizer_cov_trace_pc() at the
// beginning of every basic block. -fsanitize-coverage=trace-cmp adds calls to other functions,
// like __sanitizer_cov_trace_cmp1() or __sanitizer_cov_trace_const_cmp4().
//
// On ARM64 there can be additional symbol names inserted by the linker. By default, BL instruction
// can only target addresses within the +/-128M range from PC. To target farther addresses, the
// ARM64 linker inserts so-called veneers that act as trampolines for functions. We count calls to
// such veneers as normal calls to __sanitizer_cov_trace_XXX.
func getTraceCallbackType(name string) int {
	if name == "__sanitizer_cov_trace_pc" || name == "____sanitizer_cov_trace_pc_veneer" {
		return TraceCbPc
	}
	if strings.HasPrefix(name, "__sanitizer_cov_trace_") ||
		(strings.HasPrefix(name, "____sanitizer_cov_trace_") && strings.HasSuffix(name, "_veneer")) {
		return TraceCbCmp
	}
	return TraceCbNone
}

func elfReadSymbols(module *Module, info *symbolInfo) ([]*Symbol, error) {
	file, err := elf.Open(module.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	text := file.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section in the object file")
	}
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF symbols: %w", err)
	}
	if module.Name == "" {
		info.textAddr = text.Addr
	}
	var symbols []*Symbol
	for i, symb := range allSymbols {
		if symb.Info&0xf != uint8(elf.STT_FUNC) && symb.Info&0xf != uint8(elf.STT_NOTYPE) {
			// Only save STT_FUNC, STT_NONE otherwise some symb range inside another symb range.
			continue
		}
		text := symb.Value >= text.Addr && symb.Value+symb.Size <= text.Addr+text.Size
		if text && symb.Size != 0 {
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
		switch getTraceCallbackType(symb.Name) {
		case TraceCbPc:
			info.tracePCIdx[i] = true
			if text {
				info.tracePC[symb.Value] = true
			}
		case TraceCbCmp:
			info.traceCmpIdx[i] = true
			if text {
				info.traceCmp[symb.Value] = true
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
	defer file.Close()
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
		return nil, nil, fmt.Errorf("failed to parse DWARF: %w (set CONFIG_DEBUG_INFO=y on linux)", err)
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
	defer file.Close()
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
	defer file.Close()
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

func elfGetCompilerVersion(path string) string {
	file, err := elf.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	sec := file.Section(".comment")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	return string(data[:])
}
