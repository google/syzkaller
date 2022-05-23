// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
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

type DwarfCompileUnit struct {
	Entry  *dwarf.Entry
	Name   string
	Ranges [][2]uint64
	Offset dwarf.Offset
}

type DwarfFunction struct {
	DwarfCompileUnit *DwarfCompileUnit
	Type             dwarf.Tag
	Name             string
	Ranges           [][2]uint64
	DeclFile         string
	AbstractOrigin   dwarf.Offset
	Inline           bool
	Offset           dwarf.Offset
}

func getFilenameByIndex(debugInfo *dwarf.Data, entry *dwarf.Entry, index int) (string, error) {
	r, err := debugInfo.LineReader(entry)
	if err != nil {
		return "", fmt.Errorf("not found line reader for Compile Unit")
	}
	files := r.Files()
	if files == nil {
		return "", fmt.Errorf("files == nil")
	}
	if index >= len(files) {
		return "", fmt.Errorf("index (%v) >= len(files) (%v)", index, len(files))
	}
	if index == 0 {
		return "", nil
	}
	return files[index].Name, nil
}

func readAllCompileUnits(debugInfo *dwarf.Data) ([]*DwarfCompileUnit, error) {
	var data []*DwarfCompileUnit

	for r := debugInfo.Reader(); ; {
		ent, err := r.Next()
		if err != nil {
			return nil, err
		}
		if ent == nil {
			break
		}
		if ent.Tag != dwarf.TagCompileUnit {
			return nil, fmt.Errorf("found unexpected tag %v on top level", ent.Tag)
		}
		attrName := ent.Val(dwarf.AttrName)
		if attrName == nil {
			continue
		}
		ranges, err := debugInfo.Ranges(ent)
		if err != nil {
			return nil, err
		}
		data = append(data, &DwarfCompileUnit{
			Entry:  ent,
			Name:   attrName.(string),
			Ranges: ranges,
			Offset: ent.Offset,
		})
		r.SkipChildren()
	}

	return data, nil
}

func getEntryByOffset(debugInfo *dwarf.Data, offset dwarf.Offset) (*dwarf.Entry, error) {
	r := debugInfo.Reader()
	r.Seek(offset)
	ent, err := r.Next()
	if err != nil {
		return nil, err
	}
	return ent, nil
}

func readAllSubprograms(debugInfo *dwarf.Data, compileUnit *DwarfCompileUnit) ([]*DwarfFunction, error) {
	var data []*DwarfFunction

	top := true
	first := true
	for r := debugInfo.Reader(); ; {
		if top {
			r.Seek(compileUnit.Offset)
			top = false
		}
		ent, err := r.Next()
		if err != nil {
			return nil, err
		}
		if ent == nil {
			break
		}
		if first && ent.Tag == dwarf.TagCompileUnit {
			first = false
			continue
		} else if ent.Tag == dwarf.TagCompileUnit {
			break
		}
		if ent.Tag != dwarf.TagSubprogram {
			continue
		}

		attrName := ent.Val(dwarf.AttrName)
		attrAbstractOrigin := ent.Val(dwarf.AttrAbstractOrigin)
		var decfile string
		if attrName == nil && attrAbstractOrigin != nil {
			ent1, err := getEntryByOffset(debugInfo, attrAbstractOrigin.(dwarf.Offset))
			if err != nil {
				return nil, err
			}
			attrName = ent1.Val(dwarf.AttrName)
			decfile, err = getFilenameByIndex(debugInfo, compileUnit.Entry, int(ent1.Val(dwarf.AttrDeclFile).(int64)))
			if err != nil {
				return nil, err
			}
		}
		if attrName == nil {
			continue
		}
		if decfile == "" && ent.Val(dwarf.AttrDeclFile) != nil {
			decfile, err = getFilenameByIndex(debugInfo, compileUnit.Entry, int(ent.Val(dwarf.AttrDeclFile).(int64)))
			if err != nil {
				return nil, err
			}
		}
		ranges, err := debugInfo.Ranges(ent)
		if err != nil {
			return nil, err
		}
		inline := false
		attrInline := ent.Val(dwarf.AttrInline)
		if attrInline != nil {
			inline = true
		}

		data = append(data, &DwarfFunction{
			DwarfCompileUnit: compileUnit,
			Type:             dwarf.TagSubprogram,
			Name:             attrName.(string),
			Ranges:           ranges,
			DeclFile:         decfile,
			Inline:           inline,
			Offset:           ent.Offset,
		})
		r.SkipChildren()
	}

	return data, nil
}

func readAllInlinedSubroutines(debugInfo *dwarf.Data, inlineSubprograms map[dwarf.Offset]*DwarfFunction,
	subprogram *DwarfFunction) ([]*DwarfFunction, error) {
	var data []*DwarfFunction

	top := true
	first := true
	for r := debugInfo.Reader(); ; {
		if top {
			r.Seek(subprogram.Offset)
			top = false
		}
		ent, err := r.Next()
		if err != nil {
			return nil, err
		}
		if ent == nil {
			break
		}
		if first && ent.Tag == dwarf.TagSubprogram {
			first = false
			continue
		} else if ent.Tag == dwarf.TagSubprogram {
			break
		}
		if ent.Tag != dwarf.TagInlinedSubroutine {
			continue
		}
		attrAbstractOrigin := ent.Val(dwarf.AttrAbstractOrigin)
		if attrAbstractOrigin == nil {
			continue
		}
		df := inlineSubprograms[attrAbstractOrigin.(dwarf.Offset)]
		ranges, err := debugInfo.Ranges(ent)
		if err != nil {
			return nil, err
		}
		if len(ranges) == 0 {
			continue
		}
		data = append(data, &DwarfFunction{
			DwarfCompileUnit: df.DwarfCompileUnit,
			Type:             dwarf.TagInlinedSubroutine,
			Name:             df.Name,
			Ranges:           ranges,
			Offset:           ent.Offset,
			DeclFile:         df.DeclFile,
			Inline:           df.Inline,
			AbstractOrigin:   attrAbstractOrigin.(dwarf.Offset),
		})
	}

	return data, nil
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
		flag := symb.Value >= text.Addr && symb.Value+symb.Size <= text.Addr+text.Size
		if strings.HasPrefix(symb.Name, "__sanitizer_cov_trace_") {
			if symb.Name == "__sanitizer_cov_trace_pc" {
				info.tracePCIdx[i] = true
				if flag {
					info.tracePC = symb.Value
				}
			} else {
				info.traceCmpIdx[i] = true
				if flag {
					info.traceCmp[symb.Value] = true
				}
			}
		}
	}

	compileUnits, err := readAllCompileUnits(debugInfo)
	if err != nil {
		return nil, err
	}
	allDwarfFunctions, err := elfReadSymbolsFromDwarf(debugInfo, compileUnits)
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
		flag := start >= text.Addr && end <= text.Addr+text.Size
		if flag {
			start1 := start + module.Addr
			end1 := end + module.Addr
			symbols = append(symbols, &Symbol{
				Module: module,
				ObjectUnit: ObjectUnit{
					Name: ds.Name,
				},
				Start:  start1,
				End:    end1,
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

func elfReadSymbolsFromDwarf(debugInfo *dwarf.Data, compileUnits []*DwarfCompileUnit) ([]*DwarfFunction, error) {
	var allSubprograms []*DwarfFunction
	var allInlineSubroutines []*DwarfFunction
	for _, cu := range compileUnits {
		errc := make(chan error, 1)
		go func(cu *DwarfCompileUnit) {
			subprograms, err := readAllSubprograms(debugInfo, cu)
			if err != nil {
				errc <- err
				return
			}
			allSubprograms = append(allSubprograms, subprograms...)
			inlineSubprograms := make(map[dwarf.Offset]*DwarfFunction)
			for _, sp := range subprograms {
				if sp.Inline {
					inlineSubprograms[sp.Offset] = sp
				}
			}
			for _, sp := range subprograms {
				if sp.Inline {
					continue
				}
				erric := make(chan error, 1)
				go func(sp *DwarfFunction) {
					inlineSubroutines, err := readAllInlinedSubroutines(debugInfo, inlineSubprograms, sp)
					if err != nil {
						erric <- err
						return
					}
					allInlineSubroutines = append(allInlineSubroutines, inlineSubroutines...)
					erric <- nil
				}(sp)
				if err := <-erric; err != nil {
					errc <- err
				}
			}
			errc <- nil
		}(cu)
		if err := <-errc; err != nil {
			return nil, err
		}
	}
	var allDwarfFunctions []*DwarfFunction
	for _, df := range allSubprograms {
		if len(df.Ranges) == 0 {
			continue
		}
		allDwarfFunctions = append(allDwarfFunctions, df)
	}
	for _, df := range allInlineSubroutines {
		if len(df.Ranges) == 0 {
			continue
		}
		allDwarfFunctions = append(allDwarfFunctions, df)
	}
	sort.Slice(allDwarfFunctions, func(i, j int) bool {
		return allDwarfFunctions[i].Ranges[0][0] < allDwarfFunctions[j].Ranges[0][0]
	})
	return allDwarfFunctions, nil
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
