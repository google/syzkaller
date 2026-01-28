// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/ianlancetaylor/demangle"
)

type elfSymbolizer struct {
	path      string
	ef        *elf.File
	dw        *dwarf.Data
	cuRanges  []cuRange
	symbols   []elf.Symbol
	mu        sync.Mutex
	lineCache map[string]*parsedCU
	subCache  map[string][]subprogram
}

type parsedCU struct {
	entries []dwarf.LineEntry
	files   []*dwarf.LineFile
}

type cuRange struct {
	low   uint64
	high  uint64
	entry *dwarf.Entry
}

type subprogram struct {
	low   uint64
	high  uint64
	entry *dwarf.Entry
}

func newELFSymbolizer(bin string) (Symbolizer, error) {
	ef, err := elf.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary %v: %w", bin, err)
	}
	dw, err := ef.DWARF()
	if err != nil {
		ef.Close()
		return nil, fmt.Errorf("failed to parse DWARF %v: %w", bin, err)
	}

	symbols, _ := ef.Symbols()
	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].Value != symbols[j].Value {
			return symbols[i].Value < symbols[j].Value
		}
		ti := elf.ST_TYPE(symbols[i].Info)
		tj := elf.ST_TYPE(symbols[j].Info)
		if ti != tj {
			return ti != elf.STT_FUNC && tj == elf.STT_FUNC
		}
		if symbols[i].Size != symbols[j].Size {
			return symbols[i].Size < symbols[j].Size
		}
		return symbols[i].Name > symbols[j].Name
	})

	es := &elfSymbolizer{
		path:      bin,
		ef:        ef,
		dw:        dw,
		symbols:   symbols,
		lineCache: make(map[string]*parsedCU),
		subCache:  make(map[string][]subprogram),
	}

	if err := es.buildIndex(); err != nil {
		es.Close()
		return nil, fmt.Errorf("failed to index DWARF %v: %w", bin, err)
	}

	return es, nil
}

func (es *elfSymbolizer) buildIndex() error {
	r := es.dw.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return err
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagCompileUnit {
			r.SkipChildren()
			continue
		}

		ranges, err := es.dw.Ranges(entry)
		if err != nil {
			continue
		}
		for _, rng := range ranges {
			es.cuRanges = append(es.cuRanges, cuRange{
				low:   rng[0],
				high:  rng[1],
				entry: entry,
			})
		}
	}
	sort.Slice(es.cuRanges, func(i, j int) bool {
		return es.cuRanges[i].low < es.cuRanges[j].low
	})
	return nil
}

func (es *elfSymbolizer) findCU(pc uint64) *dwarf.Entry {
	idx := sort.Search(len(es.cuRanges), func(i int) bool {
		return es.cuRanges[i].high > pc
	})
	if idx < len(es.cuRanges) && es.cuRanges[idx].low <= pc {
		return es.cuRanges[idx].entry
	}
	return nil
}

func (es *elfSymbolizer) getParsedCU(cu *dwarf.Entry) (*parsedCU, error) {
	key := fmt.Sprintf("%x", cu.Offset)
	es.mu.Lock()
	if p, ok := es.lineCache[key]; ok {
		es.mu.Unlock()
		return p, nil
	}
	es.mu.Unlock()

	lr, err := es.dw.LineReader(cu)
	if err != nil {
		return nil, err
	}
	if lr == nil {
		return nil, fmt.Errorf("no line table")
	}

	var entries []dwarf.LineEntry
	var entry dwarf.LineEntry
	for {
		err := lr.Next(&entry)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		entries = append(entries, entry)
	}

	// Sort by address.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Address < entries[j].Address
	})

	p := &parsedCU{
		entries: entries,
		files:   lr.Files(),
	}

	es.mu.Lock()
	es.lineCache[key] = p
	es.mu.Unlock()
	return p, nil
}

func (es *elfSymbolizer) getFunction(cu *dwarf.Entry, pc uint64) (*dwarf.Entry, error) {
	key := fmt.Sprintf("%x", cu.Offset)
	es.mu.Lock()
	subs, ok := es.subCache[key]
	es.mu.Unlock()

	if !ok {
		var err error
		subs, err = es.parseSubprograms(cu)
		if err != nil {
			return nil, err
		}
		es.mu.Lock()
		es.subCache[key] = subs
		es.mu.Unlock()
	}

	idx := sort.Search(len(subs), func(i int) bool {
		return subs[i].high > pc
	})
	if idx < len(subs) && subs[idx].low <= pc {
		return subs[idx].entry, nil
	}
	return nil, nil
}

func (es *elfSymbolizer) parseSubprograms(cu *dwarf.Entry) ([]subprogram, error) {
	var subs []subprogram
	r := es.dw.Reader()
	r.Seek(cu.Offset)
	r.Next() // Skip CU

	for {
		entry, err := r.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		if entry.Tag == 0 {
			break
		}

		if entry.Tag == dwarf.TagSubprogram {
			if ranges, err := es.dw.Ranges(entry); err == nil {
				for _, rng := range ranges {
					subs = append(subs, subprogram{
						low:   rng[0],
						high:  rng[1],
						entry: entry,
					})
				}
			}
		}

		if entry.Children {
			r.SkipChildren()
		}
	}
	sort.Slice(subs, func(i, j int) bool {
		return subs[i].low < subs[j].low
	})
	return subs, nil
}

func (es *elfSymbolizer) Symbolize(bin string, pcs ...uint64) ([]Frame, error) {
	if bin != es.path {
		return nil, fmt.Errorf("symbolizer expects binary %v, got %v", es.path, bin)
	}
	var frames []Frame
	for _, pc := range pcs {
		frames = append(frames, es.symbolizePC(pc)...)
	}
	return frames, nil
}

func (es *elfSymbolizer) symbolizePC(pc uint64) []Frame {
	cu := es.findCU(pc)
	if cu == nil {
		return es.fallbackSymbol(pc)
	}

	p, err := es.getParsedCU(cu)
	if err != nil {
		return es.fallbackSymbol(pc)
	}

	var entry dwarf.LineEntry
	foundLine := false

	// Binary search for entry with Address <= pc < (next entry Address or EndSequence)
	// entries are sorted by Address.
	// We want idx such that entries[idx].Address <= pc.
	// Last such entry from the left.
	// sort.Search returns first index satisfying condition.
	// If we use func(i) entries[i].Address > pc.
	// Then idx is first entry > pc.
	// So idx-1 is the last entry <= pc.
	idx := sort.Search(len(p.entries), func(i int) bool {
		return p.entries[i].Address > pc
	})
	if idx > 0 {
		candidate := p.entries[idx-1]
		// Check validity: is it EndSequence?
		// If EndSequence, it marks the *end* of a sequence (exclusive of code).
		// So if candidate.EndSequence, it doesn't cover pc (pc is in a hole).
		if !candidate.EndSequence {
			entry = candidate
			foundLine = true
		}
	}

	funcEntry, _ := es.getFunction(cu, pc)
	var frames []Frame
	if funcEntry != nil {
		// Only pass entry pointer if foundLine is true, otherwise pass nil.
		var entryPtr *dwarf.LineEntry
		if foundLine {
			entryPtr = &entry
		}
		frames = es.unwindInlines(funcEntry, pc, entryPtr, p.files)
	}

	if len(frames) == 0 {
		if funcName := es.findSymbol(pc); funcName != "" {
			f := Frame{PC: pc, Func: funcName}
			if foundLine && entry.Line != 0 {
				f.File = entry.File.Name
				f.Line = entry.Line
				f.Column = entry.Column
			}
			return []Frame{f}
		}

		f := Frame{PC: pc}
		if foundLine && entry.Line != 0 {
			f.File = entry.File.Name
			f.Line = entry.Line
			f.Column = entry.Column
			f.Func = fmt.Sprintf("0x%x", pc)
		} else {
			f.Func = fmt.Sprintf("0x%x", pc)
		}
		frames = append(frames, f)
	}

	frames[0].PC = pc
	return frames
}

func (es *elfSymbolizer) fallbackSymbol(pc uint64) []Frame {
	if funcName := es.findSymbol(pc); funcName != "" {
		return []Frame{{PC: pc, Func: funcName}}
	}
	return []Frame{{PC: pc, Func: fmt.Sprintf("0x%x", pc)}}
}

func (es *elfSymbolizer) findSymbol(pc uint64) string {
	idx := sort.Search(len(es.symbols), func(i int) bool {
		return es.symbols[i].Value > pc
	})
	if idx > 0 {
		s := es.symbols[idx-1]
		if s.Size > 0 {
			if pc >= s.Value && pc < s.Value+s.Size {
				return s.Name
			}
		} else {
			var limit uint64
			if idx < len(es.symbols) {
				limit = es.symbols[idx].Value
			} else {
				limit = s.Value + 4096
			}
			if pc >= s.Value && pc < limit {
				return s.Name
			}
		}
	}
	return ""
}

func (es *elfSymbolizer) unwindInlines(funcEntry *dwarf.Entry, pc uint64, lineEntry *dwarf.LineEntry,
	files []*dwarf.LineFile) []Frame {
	var stack []*dwarf.Entry

	r := es.dw.Reader()
	if funcEntry.Children {
		r.Seek(funcEntry.Offset)
		r.Next()
		findCoveringInlined(es.dw, r, pc, &stack)
	}

	stack = append(stack, funcEntry)

	var frames []Frame
	for i, die := range stack {
		f := Frame{}
		f.Inline = (i > 0)

		origin, _ := es.resolveAbstractOrigin(die)

		name := es.getName(die, origin)
		f.Func = name

		es.fillLocation(&f, i, die, origin, stack, lineEntry, files)
		frames = append(frames, f)
	}

	return frames
}

func (es *elfSymbolizer) getName(die, origin *dwarf.Entry) string {
	// Try LinkageName first (for mangled names)
	if name, ok := die.Val(dwarf.AttrLinkageName).(string); ok {
		if d, err := demangle.ToString(name); err == nil {
			return d
		}
		return name
	}
	if origin != nil {
		if name, ok := origin.Val(dwarf.AttrLinkageName).(string); ok {
			if d, err := demangle.ToString(name); err == nil {
				return d
			}
			return name
		}
	}

	// Fallback to Name.
	if name, ok := die.Val(dwarf.AttrName).(string); ok {
		return name
	}
	if origin != nil {
		if name, ok := origin.Val(dwarf.AttrName).(string); ok {
			return name
		}
	}
	return fmt.Sprintf("func_%x", die.Offset)
}

func findCoveringInlined(dw *dwarf.Data, r *dwarf.Reader, pc uint64, stack *[]*dwarf.Entry) bool {
	for {
		entry, err := r.Next()
		if err != nil || entry == nil {
			return false
		}
		if entry.Tag == 0 {
			return false
		}

		covers := false
		if ranges, err := dw.Ranges(entry); err == nil {
			for _, rng := range ranges {
				if pc >= rng[0] && pc < rng[1] {
					covers = true
					break
				}
			}
		}

		if !covers {
			if entry.Children {
				r.SkipChildren()
			}
			continue
		}

		// Entry covers PC.
		if entry.Tag == dwarf.TagInlinedSubroutine {
			if entry.Children {
				if findCoveringInlined(dw, r, pc, stack) {
					*stack = append(*stack, entry)
					return true
				}
			}
			*stack = append(*stack, entry)
			return true
		}

		// Other tags (e.g. LexicalBlock).
		if entry.Children {
			if findCoveringInlined(dw, r, pc, stack) {
				return true
			}
		}
	}
}

func (es *elfSymbolizer) resolveAbstractOrigin(die *dwarf.Entry) (*dwarf.Entry, error) {
	ref, ok := die.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset)
	if !ok {
		return nil, nil
	}
	r := es.dw.Reader()
	r.Seek(ref)
	entry, err := r.Next()
	if err != nil || entry == nil {
		return nil, err
	}
	return entry, nil
}

func (es *elfSymbolizer) Close() {
	if es.ef != nil {
		es.ef.Close()
	}
}

func (es *elfSymbolizer) fillLocation(f *Frame, i int, die, origin *dwarf.Entry, stack []*dwarf.Entry,
	lineEntry *dwarf.LineEntry, files []*dwarf.LineFile) {
	if i == 0 {
		if lineEntry != nil && lineEntry.Line != 0 {
			f.File = lineEntry.File.Name
			f.Line = lineEntry.Line
			f.Column = lineEntry.Column
			return
		}
		// Fallback to function declaration file/line.
		target := die
		if origin != nil {
			target = origin
		}

		declFileIdx, _ := target.Val(dwarf.AttrDeclFile).(int64)
		if files != nil && declFileIdx > 0 && int(declFileIdx) < len(files) {
			if lf := files[declFileIdx]; lf != nil {
				f.File = lf.Name
			}
		}
		f.Line = 0
		f.Column = 0
		return
	}

	prev := stack[i-1]
	callFileIdx, _ := prev.Val(dwarf.AttrCallFile).(int64)
	callLine, _ := prev.Val(dwarf.AttrCallLine).(int64)
	callCol, _ := prev.Val(dwarf.AttrCallColumn).(int64)

	if files != nil && callFileIdx > 0 && int(callFileIdx) < len(files) {
		if lf := files[callFileIdx]; lf != nil {
			f.File = lf.Name
		}
	}
	f.Line = int(callLine)
	f.Column = int(callCol)
}
