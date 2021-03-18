// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bufio"
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

func makeELF(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule) (*Impl, error) {
	modules, err := discoverModules(target, objDir, moduleObj, hostModules)
	if err != nil {
		return nil, err
	}
	// Here and below index 0 refers to coverage callbacks (__sanitizer_cov_trace_pc)
	// and index 1 refers to comparison callbacks (__sanitizer_cov_trace_cmp*).
	var allCoverPoints [2][]uint64
	var allSymbols []*Symbol
	var allRanges []pcRange
	var allUnits []*CompileUnit
	var pcBase uint64
	for _, module := range modules {
		file, err := elf.Open(module.Path)
		if err != nil {
			return nil, err
		}
		errc := make(chan error, 1)
		go func() {
			symbols, info, err := readSymbols(file, module)
			if err != nil {
				errc <- err
				return
			}
			allSymbols = append(allSymbols, symbols...)
			if module.Name == "" {
				pcBase = info.textAddr
			}
			var coverPoints [2][]uint64
			if target.Arch != targets.AMD64 {
				coverPoints, err = objdump(target, module)
			} else if module.Name == "" {
				coverPoints, err = readCoverPoints(file, info)
			} else {
				coverPoints, err = readModuleCoverPoints(file, info, module)
			}
			allCoverPoints[0] = append(allCoverPoints[0], coverPoints[0]...)
			allCoverPoints[1] = append(allCoverPoints[1], coverPoints[1]...)
			if err == nil && module.Name == "" && len(coverPoints[0]) == 0 {
				err = fmt.Errorf("%v doesn't contain coverage callbacks (set CONFIG_KCOV=y)", module.Path)
			}
			errc <- err
		}()
		ranges, units, err := readTextRanges(file, module)
		if err != nil {
			return nil, err
		}
		if err := <-errc; err != nil {
			return nil, err
		}
		allRanges = append(allRanges, ranges...)
		allUnits = append(allUnits, units...)
	}

	sort.Slice(allSymbols, func(i, j int) bool {
		return allSymbols[i].Start < allSymbols[j].Start
	})
	sort.Slice(allRanges, func(i, j int) bool {
		return allRanges[i].start < allRanges[j].start
	})
	for k := range allCoverPoints {
		sort.Slice(allCoverPoints[k], func(i, j int) bool {
			return allCoverPoints[k][i] < allCoverPoints[k][j]
		})
	}

	allSymbols = buildSymbols(allSymbols, allRanges, allCoverPoints)
	nunit := 0
	for _, unit := range allUnits {
		if len(unit.PCs) == 0 {
			continue // drop the unit
		}
		// TODO: objDir won't work for out-of-tree modules.
		unit.Name, unit.Path = cleanPath(unit.Name, srcDir, buildDir)
		allUnits[nunit] = unit
		nunit++
	}
	allUnits = allUnits[:nunit]
	if len(allSymbols) == 0 || len(allUnits) == 0 {
		return nil, fmt.Errorf("failed to parse DWARF (set CONFIG_DEBUG_INFO=y?)")
	}
	if target.OS == targets.FreeBSD {
		// On FreeBSD .text address in ELF is 0, but .text is actually mapped at 0xffffffff.
		pcBase = ^uint64(0)
	}
	impl := &Impl{
		Units:   allUnits,
		Symbols: allSymbols,
		Symbolize: func(pcs map[*Module][]uint64) ([]Frame, error) {
			return symbolize(target, srcDir, buildDir, pcs)
		},
		RestorePC: func(pc uint32) uint64 {
			return PreviousInstructionPC(target, RestorePC(pc, uint32(pcBase>>32)))
		},
	}
	return impl, nil
}

type pcRange struct {
	start uint64
	end   uint64
	unit  *CompileUnit
}

func buildSymbols(symbols []*Symbol, ranges []pcRange, coverPoints [2][]uint64) []*Symbol {
	// Assign coverage point PCs to symbols.
	// Both symbols and coverage points are sorted, so we do it one pass over both.
	selectPCs := func(u *ObjectUnit, typ int) *[]uint64 {
		return [2]*[]uint64{&u.PCs, &u.CMPs}[typ]
	}
	for pcType := range coverPoints {
		pcs := coverPoints[pcType]
		var curSymbol *Symbol
		firstSymbolPC, symbolIdx := -1, 0
		for i := 0; i < len(pcs); i++ {
			pc := pcs[i]
			for ; symbolIdx < len(symbols) && pc >= symbols[symbolIdx].End; symbolIdx++ {
			}
			var symb *Symbol
			if symbolIdx < len(symbols) && pc >= symbols[symbolIdx].Start && pc < symbols[symbolIdx].End {
				symb = symbols[symbolIdx]
			}
			if curSymbol != nil && curSymbol != symb {
				*selectPCs(&curSymbol.ObjectUnit, pcType) = pcs[firstSymbolPC:i]
				firstSymbolPC = -1
			}
			curSymbol = symb
			if symb != nil && firstSymbolPC == -1 {
				firstSymbolPC = i
			}
		}
		if curSymbol != nil {
			*selectPCs(&curSymbol.ObjectUnit, pcType) = pcs[firstSymbolPC:]
		}
	}
	// Assign compile units to symbols based on unit pc ranges.
	// Do it one pass as both are sorted.
	nsymbol := 0
	rangeIndex := 0
	for _, s := range symbols {
		for ; rangeIndex < len(ranges) && ranges[rangeIndex].end <= s.Start; rangeIndex++ {
		}
		if rangeIndex == len(ranges) || s.Start < ranges[rangeIndex].start || len(s.PCs) == 0 {
			continue // drop the symbol
		}
		unit := ranges[rangeIndex].unit
		s.Unit = unit
		symbols[nsymbol] = s
		nsymbol++
	}
	symbols = symbols[:nsymbol]

	for pcType := range coverPoints {
		for _, s := range symbols {
			symbPCs := selectPCs(&s.ObjectUnit, pcType)
			unitPCs := selectPCs(&s.Unit.ObjectUnit, pcType)
			pos := len(*unitPCs)
			*unitPCs = append(*unitPCs, *symbPCs...)
			*symbPCs = (*unitPCs)[pos:]
		}
	}
	return symbols
}

type symbolInfo struct {
	textAddr    uint64
	tracePC     uint64
	traceCmp    map[uint64]bool
	tracePCIdx  map[int]bool
	traceCmpIdx map[int]bool
}

func readSymbols(file *elf.File, module *Module) ([]*Symbol, *symbolInfo, error) {
	text := file.Section(".text")
	if text == nil {
		return nil, nil, fmt.Errorf("no .text section in the object file")
	}
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read ELF symbols: %v", err)
	}
	var symbols []*Symbol
	info := &symbolInfo{
		textAddr:    text.Addr,
		traceCmp:    make(map[uint64]bool),
		tracePCIdx:  make(map[int]bool),
		traceCmpIdx: make(map[int]bool),
	}
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
	return symbols, info, nil
}

func readTextRanges(file *elf.File, module *Module) ([]pcRange, []*CompileUnit, error) {
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
		return nil, nil, fmt.Errorf("failed to parse DWARF: %v (set CONFIG_DEBUG_INFO=y?)", err)
	}
	var ranges []pcRange
	var units []*CompileUnit
	for r := debugInfo.Reader(); ; {
		ent, err := r.Next()
		if err != nil {
			return nil, nil, err
		}
		if ent == nil {
			break
		}
		if ent.Tag != dwarf.TagCompileUnit {
			return nil, nil, fmt.Errorf("found unexpected tag %v on top level", ent.Tag)
		}
		attrName := ent.Val(dwarf.AttrName)
		if attrName == nil {
			continue
		}
		unit := &CompileUnit{
			ObjectUnit: ObjectUnit{
				Name: attrName.(string),
			},
		}
		units = append(units, unit)
		ranges1, err := debugInfo.Ranges(ent)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range ranges1 {
			if r[0] >= r[1] || r[0] < text.Addr || r[1] > text.Addr+text.Size {
				if kaslr {
					// Linux kernel binaries with CONFIG_RANDOMIZE_BASE=y are strange.
					// .text starts at 0xffffffff81000000 and symbols point there as well,
					// but PC ranges point to addresses around 0.
					// So try to add text offset and retry the check.
					// It's unclear if we also need some offset on top of text.Addr,
					// it gives approximately correct addresses, but not necessary precisely
					// correct addresses.
					r[0] += text.Addr
					r[1] += text.Addr
					if r[0] >= r[1] || r[0] < text.Addr || r[1] > text.Addr+text.Size {
						continue
					}
				}
			}
			ranges = append(ranges, pcRange{r[0] + module.Addr, r[1] + module.Addr, unit})
		}
		r.SkipChildren()
	}
	return ranges, units, nil
}

func symbolize(target *targets.Target, srcDir, buildDir string, pcs map[*Module][]uint64) ([]Frame, error) {
	var frames []Frame
	for mod, pcs1 := range pcs {
		frames1, err := symbolizeModule(target, srcDir, buildDir, mod, pcs1)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frames1...)
	}
	return frames, nil
}

func symbolizeModule(target *targets.Target, srcDir, buildDir string, mod *Module, pcs []uint64) ([]Frame, error) {
	procs := runtime.GOMAXPROCS(0) / 2
	if need := len(pcs) / 1000; procs > need {
		procs = need
	}
	const (
		minProcs = 1
		maxProcs = 4
	)
	// addr2line on a beefy vmlinux takes up to 1.6GB of RAM, so don't create too many of them.
	if procs > maxProcs {
		procs = maxProcs
	}
	if procs < minProcs {
		procs = minProcs
	}
	type symbolizerResult struct {
		frames []symbolizer.Frame
		err    error
	}
	symbolizerC := make(chan symbolizerResult, procs)
	pcchan := make(chan []uint64, procs)
	for p := 0; p < procs; p++ {
		go func() {
			symb := symbolizer.NewSymbolizer(target)
			defer symb.Close()
			var res symbolizerResult
			for pcs := range pcchan {
				for i, pc := range pcs {
					pcs[i] = pc - mod.Addr
				}
				frames, err := symb.SymbolizeArray(mod.Path, pcs)
				if err != nil {
					res.err = fmt.Errorf("failed to symbolize: %v", err)
				}
				res.frames = append(res.frames, frames...)
			}
			symbolizerC <- res
		}()
	}
	for i := 0; i < len(pcs); {
		end := i + 100
		if end > len(pcs) {
			end = len(pcs)
		}
		pcchan <- pcs[i:end]
		i = end
	}
	close(pcchan)
	var err0 error
	var frames []Frame
	for p := 0; p < procs; p++ {
		res := <-symbolizerC
		if res.err != nil {
			err0 = res.err
		}
		for _, frame := range res.frames {
			name, path := cleanPath(frame.File, srcDir, buildDir)
			frames = append(frames, Frame{
				Module: mod,
				PC:     frame.PC + mod.Addr,
				Name:   name,
				Path:   path,
				Range: Range{
					StartLine: frame.Line,
					StartCol:  0,
					EndLine:   frame.Line,
					EndCol:    LineEnd,
				},
			})
		}
	}
	if err0 != nil {
		return nil, err0
	}
	return frames, nil
}

// readCoverPoints finds all coverage points (calls of __sanitizer_cov_trace_*) in the object file.
// Currently it is amd64-specific: looks for e8 opcode and correct offset.
// Running objdump on the whole object file is too slow.
func readCoverPoints(file *elf.File, info *symbolInfo) ([2][]uint64, error) {
	var pcs [2][]uint64
	if info.tracePC == 0 {
		return pcs, fmt.Errorf("no __sanitizer_cov_trace_pc symbol in the object file")
	}
	const callLen = 5
	text := file.Section(".text")
	if text == nil {
		return pcs, fmt.Errorf("no .text section in the object file")
	}
	data, err := text.Data()
	if err != nil {
		return pcs, fmt.Errorf("failed to read .text: %v", err)
	}
	end := len(data) - callLen + 1
	for i := 0; i < end; i++ {
		pos := bytes.IndexByte(data[i:end], 0xe8)
		if pos == -1 {
			break
		}
		pos += i
		i = pos
		off := uint64(int64(int32(binary.LittleEndian.Uint32(data[pos+1:]))))
		pc := text.Addr + uint64(pos)
		target := pc + off + callLen
		if target == info.tracePC {
			pcs[0] = append(pcs[0], pc)
		} else if info.traceCmp[target] {
			pcs[1] = append(pcs[1], pc)
		}
	}
	return pcs, nil
}

func readModuleCoverPoints(file *elf.File, info *symbolInfo, mod *Module) ([2][]uint64, error) {
	var pcs [2][]uint64
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
			pc := mod.Addr + rel.Off - 1
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

// objdump is an old, slow way of finding coverage points.
// amd64 uses faster option of parsing binary directly (readCoverPoints).
// TODO: use the faster approach for all other arches and drop this.
func objdump(target *targets.Target, mod *Module) ([2][]uint64, error) {
	var pcs [2][]uint64
	cmd := osutil.Command(target.Objdump, "-d", "--no-show-raw-insn", mod.Path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return pcs, err
	}
	defer stdout.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return pcs, err
	}
	defer stderr.Close()
	if err := cmd.Start(); err != nil {
		return pcs, fmt.Errorf("failed to run objdump on %v: %v", mod.Path, err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	s := bufio.NewScanner(stdout)
	callInsns, traceFuncs := archCallInsn(target)
	for s.Scan() {
		if pc := parseLine(callInsns, traceFuncs, s.Bytes()); pc != 0 {
			pcs[0] = append(pcs[0], pc+mod.Addr)
		}
	}
	stderrOut, _ := ioutil.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		return pcs, fmt.Errorf("failed to run objdump on %v: %v\n%s", mod.Path, err, stderrOut)
	}
	if err := s.Err(); err != nil {
		return pcs, fmt.Errorf("failed to run objdump on %v: %v\n%s", mod.Path, err, stderrOut)
	}
	return pcs, nil
}

func parseLine(callInsns, traceFuncs [][]byte, ln []byte) uint64 {
	pos := -1
	for _, callInsn := range callInsns {
		if pos = bytes.Index(ln, callInsn); pos != -1 {
			break
		}
	}
	if pos == -1 {
		return 0
	}
	hasCall := false
	for _, traceFunc := range traceFuncs {
		if hasCall = bytes.Contains(ln[pos:], traceFunc); hasCall {
			break
		}
	}
	if !hasCall {
		return 0
	}
	for len(ln) != 0 && ln[0] == ' ' {
		ln = ln[1:]
	}
	colon := bytes.IndexByte(ln, ':')
	if colon == -1 {
		return 0
	}
	pc, err := strconv.ParseUint(string(ln[:colon]), 16, 64)
	if err != nil {
		return 0
	}
	return pc
}

func cleanPath(path, srcDir, buildDir string) (string, string) {
	filename := ""
	switch {
	case strings.HasPrefix(path, buildDir):
		// Assume the file was moved from buildDir to srcDir.
		path = strings.TrimPrefix(path, buildDir)
		filename = filepath.Join(srcDir, path)
	default:
		// Assume this is relative path.
		filename = filepath.Join(srcDir, path)
	}
	return strings.TrimLeft(filepath.Clean(path), "/\\"), filename
}

func archCallInsn(target *targets.Target) ([][]byte, [][]byte) {
	callName := [][]byte{[]byte(" <__sanitizer_cov_trace_pc>")}
	switch target.Arch {
	case targets.I386:
		// c1000102:       call   c10001f0 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tcall ")}, callName
	case targets.ARM64:
		// ffff0000080d9cc0:       bl      ffff00000820f478 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbl\t")}, callName
	case targets.ARM:
		// 8010252c:       bl      801c3280 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbl\t")}, callName
	case targets.PPC64LE:
		// c00000000006d904:       bl      c000000000350780 <.__sanitizer_cov_trace_pc>
		// This is only known to occur in the test:
		// 838:   bl      824 <__sanitizer_cov_trace_pc+0x8>
		// This occurs on PPC64LE:
		// c0000000001c21a8:       bl      c0000000002df4a0 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbl ")}, [][]byte{
			[]byte("<__sanitizer_cov_trace_pc>"),
			[]byte("<__sanitizer_cov_trace_pc+0x8>"),
			[]byte(" <.__sanitizer_cov_trace_pc>"),
		}
	case targets.MIPS64LE:
		// ffffffff80100420:       jal     ffffffff80205880 <__sanitizer_cov_trace_pc>
		// This is only known to occur in the test:
		// b58:   bal     b30 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tjal\t"), []byte("\tbal\t")}, callName
	case targets.S390x:
		// 1001de:       brasl   %r14,2bc090 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbrasl\t")}, callName
	case targets.RiscV64:
		// ffffffe000200018:       jal     ra,ffffffe0002935b0 <__sanitizer_cov_trace_pc>
		// ffffffe0000010da:       jalr    1242(ra) # ffffffe0002935b0 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tjal\t"), []byte("\tjalr\t")}, callName
	default:
		panic(fmt.Sprintf("unknown arch %q", target.Arch))
	}
}
