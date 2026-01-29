// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"runtime"
	"sort"
	"sync"

	"github.com/ianlancetaylor/demangle"
)

type elfSymbolizer struct {
	path        string
	ef          *elf.File
	dw          *dwarf.Data
	symbols     []elf.Symbol
	lines       []LineInfo
	subprograms []SubprogramInfo
	files       []string
	maxSubLen   uint64
}

type LineInfo struct {
	PC      uint64
	FileIdx int
	Line    int
	Column  int
	EndSeq  bool
}

type SubprogramInfo struct {
	Low      uint64
	High     uint64
	Name     string
	CallFile string
	CallLine int
	CallCol  int
	Inlined  bool
	Depth    int
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
		path:    bin,
		ef:      ef,
		dw:      dw,
		symbols: symbols,
	}

	if err := es.buildIndex(); err != nil {
		es.Close()
		return nil, fmt.Errorf("failed to index DWARF %v: %w", bin, err)
	}

	return es, nil
}

func (es *elfSymbolizer) buildIndex() error {
	r := es.dw.Reader()
	var cus []*dwarf.Entry
	for {
		entry, err := r.Next()
		if err != nil {
			return err
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagCompileUnit {
			cus = append(cus, entry)
			r.SkipChildren()
		}
	}

	return es.finishBuildIndex(cus)
}

func (es *elfSymbolizer) finishBuildIndex(cus []*dwarf.Entry) error {
	type tempLine struct {
		PC     uint64
		File   string
		Line   int
		Column int
		EndSeq bool
	}
	type parseResult struct {
		lines []tempLine
		subs  []SubprogramInfo
		err   error
	}

	numWorkers := runtime.NumCPU()
	work := make(chan *dwarf.Entry, len(cus))
	for _, cu := range cus {
		work <- cu
	}
	close(work)

	results := make(chan parseResult, numWorkers)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var res parseResult

			// We define a helper to get file name from nil-able table
			getFile := func(files []*dwarf.LineFile, idx int64) string {
				if idx >= 0 && int(idx) < len(files) {
					if f := files[idx]; f != nil {
						return f.Name
					}
				}
				return ""
			}

			// We need a fresh reader for each worker to navigate DWARF safely
			dwReader := es.dw.Reader()

			for cu := range work {
				// We need line table both for lines AND for resolving CallFile in subprograms
				lr, err := es.dw.LineReader(cu)
				var files []*dwarf.LineFile
				if err == nil && lr != nil {
					files = lr.Files()

					var entry dwarf.LineEntry
					for {
						if err := lr.Next(&entry); err != nil {
							break
						}
						res.lines = append(res.lines, tempLine{
							PC:     entry.Address,
							File:   entry.File.Name,
							Line:   entry.Line,
							Column: entry.Column,
							EndSeq: entry.EndSequence,
						})
					}
				}

				// Parse Subprograms
				// Using the dwReader for this worker
				subs, err := es.parseSubprograms(dwReader, cu, files, getFile)
				if err == nil {
					res.subs = append(res.subs, subs...)
				} else if res.err == nil {
					res.err = err
				}
			}
			results <- res
		}()
	}

	wg.Wait()
	close(results)

	var allLines []tempLine
	var allSubs []SubprogramInfo

	for res := range results {
		if res.err != nil {
			return res.err
		}
		allLines = append(allLines, res.lines...)
		allSubs = append(allSubs, res.subs...)
	}

	// 1. Process Lines: Dedup files
	fileMap := make(map[string]int)
	es.lines = make([]LineInfo, len(allLines))

	for i, l := range allLines {
		idx, ok := fileMap[l.File]
		if !ok {
			idx = len(es.files)
			es.files = append(es.files, l.File)
			fileMap[l.File] = idx
		}
		es.lines[i] = LineInfo{
			PC:      l.PC,
			FileIdx: idx,
			Line:    l.Line,
			Column:  l.Column,
			EndSeq:  l.EndSeq,
		}
	}

	sort.Slice(es.lines, func(i, j int) bool {
		return es.lines[i].PC < es.lines[j].PC
	})

	// 2. Process Subprograms
	es.subprograms = allSubs

	// Calculate max Subprogram size for optimization
	// And sort
	var maxLen uint64
	for _, s := range es.subprograms {
		if l := s.High - s.Low; l > maxLen {
			maxLen = l
		}
	}
	// Cap maxLen to avoid crazy scans?
	// If maxLen is huge (e.g. broken DWARF), we might scan too much.
	// But let's trust DWARF for now.
	// We can implement a hard cap (e.g. 10MB) if needed.
	es.maxSubLen = maxLen
	// Align maxLen for safety
	if es.maxSubLen < 4096 {
		es.maxSubLen = 4096
	}

	sort.Slice(es.subprograms, func(i, j int) bool {
		if es.subprograms[i].Low != es.subprograms[j].Low {
			return es.subprograms[i].Low < es.subprograms[j].Low
		}
		// Deepest first (usually smallest range)
		return es.subprograms[i].Depth > es.subprograms[j].Depth
	})

	return nil
}

func (es *elfSymbolizer) parseSubprograms(r *dwarf.Reader, cu *dwarf.Entry, files []*dwarf.LineFile,
	getFile func([]*dwarf.LineFile, int64) string) ([]SubprogramInfo, error) {

	r.Seek(cu.Offset)
	r.Next() // Skip CU itself

	var subs []SubprogramInfo
	var depth int

	var walk func() error
	walk = func() error {
		for {
			entry, err := r.Next()
			if err != nil {
				return err
			}
			if entry == nil {
				return nil
			}
			if entry.Tag == 0 {
				return nil
			}

			isSub := entry.Tag == dwarf.TagSubprogram
			isInlined := entry.Tag == dwarf.TagInlinedSubroutine

			if isSub || isInlined {
				if ranges, err := es.dw.Ranges(entry); err == nil {
					name := es.getName(entry)

					var callFile string
					var callLine, callCol int

					if isInlined {
						if idx, ok := entry.Val(dwarf.AttrCallFile).(int64); ok {
							callFile = getFile(files, idx)
						}
						if val, ok := entry.Val(dwarf.AttrCallLine).(int64); ok {
							callLine = int(val)
						}
						if val, ok := entry.Val(dwarf.AttrCallColumn).(int64); ok {
							callCol = int(val)
						}
					}

					for _, rng := range ranges {
						if rng[1] <= rng[0] {
							continue
						}
						subs = append(subs, SubprogramInfo{
							Low:      rng[0],
							High:     rng[1],
							Name:     name,
							CallFile: callFile,
							CallLine: callLine,
							CallCol:  callCol,
							Inlined:  isInlined,
							Depth:    depth,
						})
					}
				}
			}

			if entry.Children {
				depth++
				if err := walk(); err != nil {
					return err
				}
				depth--
			}
		}
	}

	if err := walk(); err != nil {
		return nil, err
	}
	return subs, nil
}

func (s *elfSymbolizer) Name() string {
	return "native"
}

func (s *elfSymbolizer) Close() {
	if s.ef != nil {
		s.ef.Close()
	}
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
	// 1. Find Line Info
	var file string
	var line, col int

	// Binary search for lines
	idx := sort.Search(len(es.lines), func(i int) bool {
		return es.lines[i].PC > pc
	})
	if idx > 0 {
		cand := es.lines[idx-1]
		// Check invalid range logic?
		// DWARF line table logic: "row" applies until next row.
		// If EndSeq is true, it marks end of sequence.
		if !cand.EndSeq {
			file = es.files[cand.FileIdx]
			line = cand.Line
			col = cand.Column
		}
	}

	// 2. Find Inline Stack
	// Search for subprograms with Low <= PC.
	idx = sort.Search(len(es.subprograms), func(i int) bool {
		return es.subprograms[i].Low > pc
	})

	var stack []SubprogramInfo

	// Scan backwards
	minLow := pc - es.maxSubLen
	if minLow > pc { // Underflow check
		minLow = 0
	}

	for i := idx - 1; i >= 0; i-- {
		s := es.subprograms[i]
		if s.Low < minLow {
			break
		}
		if s.High > pc {
			// Matches PC
			stack = append(stack, s)
		}
	}

	// Stack is populated backwards (by LowPC).
	// We want to sort by Depth (Deepest first).
	// Current sort order of es.subprograms: Low, then Depth Descending.
	// Since we scan backwards, we might see various depths mixed?
	// The `stack` logic needs to reconstruct the hierarchy.
	// With flattened list, we just picked all covering ranges.
	// We need to re-sort `stack` by Depth Descending to get [Inner, Outer].
	sort.Slice(stack, func(i, j int) bool {
		return stack[i].Depth > stack[j].Depth
	})

	if len(stack) == 0 {
		return es.fallbackSymbol(pc, file, line, col)
	}

	var frames []Frame
	for i, sub := range stack {
		f := Frame{
			Func:   sub.Name,
			Inline: sub.Inlined,
		}

		if i == 0 {
			// Inner-most: use Line info found in step 1
			f.File = file
			f.Line = line
			f.Column = col
		} else {
			// Outer frames: use Call info from previous (inner) frame
			// Wait, the stack is [Inner, Outer].
			// If i=1 (Outer), we need location where Inner (i=0) was called.
			// Inner is `stack[i-1]`.
			prev := stack[i-1]
			f.File = prev.CallFile
			f.Line = prev.CallLine
			f.Column = prev.CallCol
		}
		frames = append(frames, f)
	}

	return frames
}

func (es *elfSymbolizer) fallbackSymbol(pc uint64, file string, line, col int) []Frame {
	if funcName := es.findSymbol(pc); funcName != "" {
		f := Frame{PC: pc, Func: funcName}
		if line != 0 {
			f.File = file
			f.Line = line
			f.Column = col
		}
		return []Frame{f}
	}
	f := Frame{PC: pc}
	if line != 0 {
		f.File = file
		f.Line = line
		f.Column = col
		f.Func = fmt.Sprintf("0x%x", pc)
	} else {
		f.Func = fmt.Sprintf("0x%x", pc)
	}
	return []Frame{f}
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
			// Fallback for symbols with size 0
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

func (es *elfSymbolizer) getName(entry *dwarf.Entry) string {
	// Try LinkageName first (for mangled names)
	if name, ok := entry.Val(dwarf.AttrLinkageName).(string); ok {
		if d, err := demangle.ToString(name); err == nil {
			return d
		}
		return name
	}

	// Try abstract origin
	if ref, ok := entry.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset); ok {
		// Read abstract origin
		// We need random access. es.dw.Reader().Seek(ref).
		// Since we are in parsing loop, using `es.dw` is safe? yes.
		// We need to create a new reader to not disturb current one.
		r := es.dw.Reader()
		r.Seek(ref)
		if origin, err := r.Next(); err == nil && origin != nil {
			// helper to avoid infinite recursion if bad dwarf?
			// Just check origin.
			if name, ok := origin.Val(dwarf.AttrLinkageName).(string); ok {
				if d, err := demangle.ToString(name); err == nil {
					return d
				}
				return name
			}
			if name, ok := origin.Val(dwarf.AttrName).(string); ok {
				return name
			}
		}
	}

	// Fallback to Name.
	if name, ok := entry.Val(dwarf.AttrName).(string); ok {
		return name
	}
	return fmt.Sprintf("func_%x", entry.Offset)
}
