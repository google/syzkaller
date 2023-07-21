// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"debug/macho"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/sys/targets"
)

func makeMachO(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule) (*Impl, error) {
	return makeDWARF(&dwarfParams{
		target:                target,
		objDir:                objDir,
		srcDir:                srcDir,
		buildDir:              buildDir,
		moduleObj:             moduleObj,
		hostModules:           hostModules,
		readSymbols:           machoReadSymbols,
		readTextData:          machoReadTextData,
		readModuleCoverPoints: machoReadModuleCoverPoints,
		readTextRanges:        machoReadTextRanges,
	})
}

func machoReadSymbols(module *Module, info *symbolInfo) ([]*Symbol, error) {
	file, err := macho.Open(module.Path)
	if err != nil {
		return nil, err
	}
	text := file.Section("__text")
	if text == nil {
		return nil, fmt.Errorf("no __text section in the object file")
	}
	if file.Symtab == nil {
		return nil, fmt.Errorf("failed to read Mach-O symbols")
	}
	info.textAddr = text.Addr

	// We don't get symbol lengths or symbol ends in Mach-O symbols. So we
	// guesstimate them by taking the next symbols beginning -1. That only
	// works after we have sorted them.
	sort.Slice(file.Symtab.Syms, func(i, j int) bool {
		return file.Symtab.Syms[i].Value < file.Symtab.Syms[j].Value
	})

	var symbols []*Symbol
	for i, symb := range file.Symtab.Syms {
		// Mach-Os doesn't contain the Symbol size like in ELF
		symbEnd := text.Addr + text.Size
		if i < len(file.Symtab.Syms)-1 {
			symbEnd = file.Symtab.Syms[i+1].Value
		}

		text := symb.Value >= text.Addr && symbEnd <= text.Addr+text.Size
		if text {
			symbStart := symb.Value + module.Addr
			symbols = append(symbols, &Symbol{
				Module: module,
				ObjectUnit: ObjectUnit{
					Name: symb.Name,
				},
				Start: symbStart,
				End:   symbEnd,
			})
		}
		if strings.HasPrefix(symb.Name, "___sanitizer_cov_trace_") {
			if symb.Name == "___sanitizer_cov_trace_pc_guard" {
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

func machoReadTextRanges(module *Module) ([]pcRange, []*CompileUnit, error) {
	dir, kernel := filepath.Split(module.Path)
	dSYMPath := filepath.Join(dir, fmt.Sprintf(
		"%[1]s.dSYM/Contents/Resources/DWARF/%[1]s", kernel))
	dSYM, err := macho.Open(dSYMPath)
	if err != nil {
		return nil, nil, err
	}
	debugInfo, err := dSYM.DWARF()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DWARF: %w", err)
	}
	return readTextRanges(debugInfo, module, nil)
}

func machoReadTextData(module *Module) ([]byte, error) {
	file, err := macho.Open(module.Path)
	if err != nil {
		return nil, err
	}
	text := file.Section("__text")
	if text == nil {
		return nil, fmt.Errorf("no __text section in the object file")
	}
	return text.Data()
}

func machoReadModuleCoverPoints(target *targets.Target, module *Module, info *symbolInfo) ([2][]uint64, error) {
	// TODO: Linux/ELF supports module symbols. We should probably also do that
	// for XNU/Mach-O. To maximize code re-use we already have a lot of the
	// plumbing for module support. I think we mainly miss an equivalent to
	// discoverModules and this function at the moment.
	return [2][]uint64{}, fmt.Errorf("machoReadModuleCoverPoints not implemented")
}
