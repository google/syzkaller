// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/sys/targets"
)

type ReportGenerator struct {
	target   *targets.Target
	srcDir   string
	objDir   string
	buildDir string
	*backend.Impl
}

type Prog struct {
	Data string
	PCs  []uint64
}

func MakeReportGenerator(target *targets.Target, vm, objDir, srcDir, buildDir string) (*ReportGenerator, error) {
	impl, err := backend.Make(target, vm, objDir)
	if err != nil {
		return nil, err
	}
	rg := &ReportGenerator{
		target:   target,
		srcDir:   srcDir,
		objDir:   objDir,
		buildDir: buildDir,
		Impl:     impl,
	}
	for _, unit := range rg.Units {
		unit.Name, unit.Path = rg.cleanPath(unit.Name)
	}
	return rg, nil
}

type file struct {
	filename  string
	lines     map[int]line
	functions []*function
	pcs       int
	covered   int
}

type function struct {
	name    string
	pcs     int
	covered int
}

type line struct {
	count     map[int]bool
	prog      int
	uncovered bool
}

func (rg *ReportGenerator) prepareFileMap(progs []Prog) (map[string]*file, error) {
	if err := rg.lazySymbolize(progs); err != nil {
		return nil, err
	}
	files := make(map[string]*file)
	for _, unit := range rg.Units {
		files[unit.Name] = &file{
			filename: unit.Path,
			lines:    make(map[int]line),
			pcs:      len(unit.PCs),
		}
	}
	progPCs := make(map[uint64]map[int]bool)
	for i, prog := range progs {
		for _, pc := range prog.PCs {
			if progPCs[pc] == nil {
				progPCs[pc] = make(map[int]bool)
			}
			progPCs[pc][i] = true
		}
	}
	matchedPC := false
	for _, frame := range rg.Frames {
		name, path := rg.cleanPath(frame.File)
		f := getFile(files, name, path)
		ln := f.lines[frame.Line]
		coveredBy := progPCs[frame.PC]
		if len(coveredBy) != 0 {
			// Covered frame.
			matchedPC = true
			if ln.count == nil {
				ln.count = make(map[int]bool)
				ln.prog = -1
			}
			for progIdx := range coveredBy {
				ln.count[progIdx] = true
				if ln.prog == -1 || len(progs[progIdx].Data) < len(progs[ln.prog].Data) {
					ln.prog = progIdx
				}
			}
		} else {
			// Uncovered frame.
			if !frame.Inline || len(ln.count) == 0 {
				ln.uncovered = true
			}
		}
		f.lines[frame.Line] = ln
	}
	if !matchedPC {
		return nil, fmt.Errorf("coverage doesn't match any coverage callbacks")
	}
	for _, unit := range rg.Units {
		f := files[unit.Name]
		for _, pc := range unit.PCs {
			if progPCs[pc] != nil {
				f.covered++
			}
		}
	}
	for _, s := range rg.Symbols {
		fun := &function{
			name: s.Name,
			pcs:  len(s.PCs),
		}
		for _, pc := range s.PCs {
			if progPCs[pc] != nil {
				fun.covered++
			}
		}
		f := files[s.Unit.Name]
		f.functions = append(f.functions, fun)
	}
	for _, f := range files {
		sort.Slice(f.functions, func(i, j int) bool {
			return f.functions[i].name < f.functions[j].name
		})
	}
	return files, nil
}

func (rg *ReportGenerator) lazySymbolize(progs []Prog) error {
	if len(rg.Symbols) == 0 {
		return nil
	}
	symbolize := make(map[*backend.Symbol]bool)
	uniquePCs := make(map[uint64]bool)
	var pcs []uint64
	for _, prog := range progs {
		for _, pc := range prog.PCs {
			if uniquePCs[pc] {
				continue
			}
			uniquePCs[pc] = true
			sym := rg.findSymbol(pc)
			if sym == nil {
				continue
			}
			if !sym.Symbolized && !symbolize[sym] {
				symbolize[sym] = true
				pcs = append(pcs, sym.PCs...)
			}
		}
	}
	if len(uniquePCs) == 0 {
		return fmt.Errorf("no coverage collected so far")
	}
	if len(pcs) == 0 {
		return nil
	}
	frames, err := rg.Symbolize(pcs)
	if err != nil {
		return err
	}
	rg.Frames = append(rg.Frames, frames...)
	for sym := range symbolize {
		sym.Symbolized = true
	}
	return nil
}

func getFile(files map[string]*file, name, path string) *file {
	f := files[name]
	if f == nil {
		f = &file{
			filename: path,
			lines:    make(map[int]line),
			// Special mark for header files, if a file does not have coverage at all it is not shown.
			pcs:     1,
			covered: 1,
		}
		files[name] = f
	}
	return f
}

func (rg *ReportGenerator) cleanPath(path string) (string, string) {
	filename := ""
	switch {
	case strings.HasPrefix(path, rg.objDir):
		// Assume the file was built there.
		path = strings.TrimPrefix(path, rg.objDir)
		filename = filepath.Join(rg.objDir, path)
	case strings.HasPrefix(path, rg.buildDir):
		// Assume the file was moved from buildDir to srcDir.
		path = strings.TrimPrefix(path, rg.buildDir)
		filename = filepath.Join(rg.srcDir, path)
	default:
		// Assume this is relative path.
		filename = filepath.Join(rg.srcDir, path)
	}
	return strings.TrimLeft(filepath.Clean(path), "/\\"), filename
}

func (rg *ReportGenerator) findSymbol(pc uint64) *backend.Symbol {
	idx := sort.Search(len(rg.Symbols), func(i int) bool {
		return pc < rg.Symbols[i].End
	})
	if idx == len(rg.Symbols) {
		return nil
	}
	s := rg.Symbols[idx]
	if pc < s.Start || pc > s.End {
		return nil
	}
	return s
}
