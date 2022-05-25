// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bufio"
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

type containerFns struct {
	readSymbols           func(*Module, *symbolInfo) ([]*Symbol, error)
	readTextData          func(*Module) ([]byte, error)
	readModuleCoverPoints func(*targets.Target, *Module, *symbolInfo) ([2][]uint64, error)
	readTextRanges        func(*Module) ([]pcRange, []*CompileUnit, error)
}

type Arch struct {
	callLen       int
	relaOffset    uint64
	opcodeOffset  int
	opcodes       [2]byte
	callRelocType uint64
	target        func(arch *Arch, insn []byte, pc uint64, opcode byte) uint64
}

var arches = map[string]Arch{
	targets.AMD64: {
		callLen:       5,
		relaOffset:    1,
		opcodes:       [2]byte{0xe8, 0xe8},
		callRelocType: uint64(elf.R_X86_64_PLT32),
		target: func(arch *Arch, insn []byte, pc uint64, opcode byte) uint64 {
			off := uint64(int64(int32(binary.LittleEndian.Uint32(insn[1:]))))
			return pc + off + uint64(arch.callLen)
		},
	},
	targets.ARM64: {
		callLen:       4,
		opcodeOffset:  3,
		opcodes:       [2]byte{0x94, 0x97},
		callRelocType: uint64(elf.R_AARCH64_CALL26),
		target: func(arch *Arch, insn []byte, pc uint64, opcode byte) uint64 {
			off := uint64(binary.LittleEndian.Uint32(insn)) & ((1 << 24) - 1)
			if opcode == arch.opcodes[1] {
				off |= 0xffffffffff000000
			}
			return pc + 4*off
		},
	},
}

func makeDWARF(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule, fn *containerFns) (
	impl *Impl, err error) {
	defer func() {
		// It turns out that the DWARF-parsing library in Go crashes while parsing DWARF 5 data.
		// As GCC11 uses DWARF 5 by default, we can expect larger number of problems with
		// syzkallers compiled using old go versions.
		// So we just catch the panic and turn it into a meaningful error message.
		if recErr := recover(); recErr != nil {
			impl = nil
			err = fmt.Errorf("panic occurred while parsing DWARF "+
				"(possible remedy: use go1.16+ which support DWARF 5 debug data): %s", recErr)
		}
	}()
	impl, err = makeDWARFUnsafe(target, objDir, srcDir, buildDir, moduleObj, hostModules, fn)
	return
}

type DwarfRange struct {
	Symbol *Symbol
	Start  uint64
	End    uint64
}

func makeDWARFUnsafe(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule, fn *containerFns) (
	*Impl, error) {
	modules, err := discoverModules(target, objDir, moduleObj, hostModules)
	if err != nil {
		return nil, err
	}

	// Here and below index 0 refers to coverage callbacks (__sanitizer_cov_trace_pc(_guard))
	// and index 1 refers to comparison callbacks (__sanitizer_cov_trace_cmp*).
	var allCoverPoints [2][]uint64
	var allSymbols []*Symbol
	var allUnits []*CompileUnit
	var pcBase uint64
	errc := make(chan error, len(modules))
	for _, module := range modules {
		go func() {
			info := &symbolInfo{
				traceCmp:    make(map[uint64]bool),
				tracePCIdx:  make(map[int]bool),
				traceCmpIdx: make(map[int]bool),
			}
			symbols, err := fn.readSymbols(module, info)
			if err != nil {
				errc <- err
				return
			}
			allSymbols = append(allSymbols, symbols...)
			if module.Name == "" {
				pcBase = info.textAddr
			}
			var coverPoints [2][]uint64
			if target.Arch != targets.AMD64 && target.Arch != targets.ARM64 {
				coverPoints, err = objdump(target, module)
			} else if module.Name == "" {
				data, err := fn.readTextData(module)
				if err != nil {
					errc <- err
					return
				}
				coverPoints, err = readCoverPoints(target, info, data)
				if err != nil {
					errc <- err
					return
				}
			} else {
				coverPoints, err = fn.readModuleCoverPoints(target, module, info)
			}
			if err != nil {
				errc <- err
				return
			}
			allCoverPoints[0] = append(allCoverPoints[0], coverPoints[0]...)
			allCoverPoints[1] = append(allCoverPoints[1], coverPoints[1]...)
			if module.Name == "" && len(coverPoints[0]) == 0 {
				err = fmt.Errorf("%v doesn't contain coverage callbacks (set CONFIG_KCOV=y on linux)", module.Path)
			}
			errc <- err
		}()
		if err := <-errc; err != nil {
			return nil, err
		}
	}
	for k := range allCoverPoints {
		sort.Slice(allCoverPoints[k], func(i, j int) bool {
			return allCoverPoints[k][i] < allCoverPoints[k][j]
		})
	}
	var allRanges []*DwarfRange
	for _, symbol := range allSymbols {
		for _, r := range symbol.Ranges {
			allRanges = append(allRanges, &DwarfRange{
				Symbol: symbol,
				Start:  r[0],
				End:    r[1],
			})
		}
	}
	sort.Slice(allRanges, func(i, j int) bool {
		if allRanges[i].End != allRanges[j].End {
			return allRanges[i].End < allRanges[j].End
		}
		return allRanges[i].Start > allRanges[j].Start
	})

	allUnits = buildSymbols(allSymbols, allRanges, allCoverPoints)
	for _, s := range allSymbols {
		// TODO: objDir won't work for out-of-tree modules.
		s.Unit.Name, s.Unit.Path = cleanPath(s.Unit.Name, objDir, srcDir, buildDir)
	}
	for _, unit := range allUnits {
		unit.Name, unit.Path = cleanPath(unit.Name, objDir, srcDir, buildDir)
	}
	if len(allSymbols) == 0 || len(allUnits) == 0 {
		return nil, fmt.Errorf("failed to parse DWARF (set CONFIG_DEBUG_INFO=y on linux)")
	}
	if target.OS == targets.FreeBSD {
		// On FreeBSD .text address in ELF is 0, but .text is actually mapped at 0xffffffff.
		pcBase = ^uint64(0)
	}
	impl := &Impl{
		Units:   allUnits,
		Symbols: allSymbols,
		Ranges:  allRanges,
		Symbolize: func(pcs map[*Module][]uint64) ([]Frame, error) {
			return symbolize(target, objDir, srcDir, buildDir, pcs)
		},
		RestorePC: func(pc uint32) uint64 {
			return PreviousInstructionPC(target, RestorePC(pc, uint32(pcBase>>32)))
		},
	}
	return impl, nil
}

func buildSymbols(symbols []*Symbol, ranges []*DwarfRange, coverPoints [2][]uint64) []*CompileUnit {
	// Assign coverage point PCs to symbols.
	// Both ranges and coverage points are sorted, so we do it one pass over both.
	selectPCs := func(u *ObjectUnit, typ int) *[]uint64 {
		return [2]*[]uint64{&u.PCs, &u.CMPs}[typ]
	}
	allUnits := make(map[string]map[string]*CompileUnit)
	var units []*CompileUnit
	for pcType := range coverPoints {
		pcs := coverPoints[pcType]
		if len(pcs) == 0 {
			continue
		}
		for i := 0; i < len(pcs); i++ {
			pc := pcs[i]
			idx := sort.Search(len(ranges), func(i int) bool {
				return pc < ranges[i].Start
			})
			if idx == 0 {
				continue
			}
			idx--
			var symb *Symbol
			for j := idx; j < len(ranges); j++ {
				if pc >= ranges[j].Symbol.Start && pc < ranges[j].Symbol.End {
					symb = ranges[j].Symbol
					break
				}
			}
			if symb == nil {
				continue
			}
			sPCs := selectPCs(&symb.ObjectUnit, pcType)
			*sPCs = append(*sPCs, pc)
		}

		for _, s := range symbols {
			symbPCs := selectPCs(&s.ObjectUnit, pcType)
			if allUnits[s.Module.Name] == nil {
				allUnits[s.Module.Name] = make(map[string]*CompileUnit)
			}
			if allUnits[s.Module.Name][s.Unit.Name] == nil {
				allUnits[s.Module.Name][s.Unit.Name] = &CompileUnit{
					Module: s.Module,
					ObjectUnit: ObjectUnit{
						OrigName: s.Unit.ObjectUnit.Name,
						Name:     s.Unit.ObjectUnit.Name,
					},
				}
			}
			unitPCs := selectPCs(&allUnits[s.Module.Name][s.Unit.Name].ObjectUnit, pcType)
			*unitPCs = append(*unitPCs, *symbPCs...)
		}
	}
	for _, f := range allUnits {
		for _, unit := range f {
			units = append(units, unit)
		}
	}

	return units
}

type symbolInfo struct {
	textAddr    uint64
	tracePC     uint64
	traceCmp    map[uint64]bool
	tracePCIdx  map[int]bool
	traceCmpIdx map[int]bool
}

type pcRange struct {
	start uint64
	end   uint64
	unit  *CompileUnit
}

type pcFixFn = (func([2]uint64) ([2]uint64, bool))

func readTextRanges(debugInfo *dwarf.Data, module *Module, pcFix pcFixFn) (
	[]pcRange, []*CompileUnit, error) {
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
			Module: module,
		}
		units = append(units, unit)
		ranges1, err := debugInfo.Ranges(ent)
		if err != nil {
			return nil, nil, err
		}

		var filtered bool
		for _, r := range ranges1 {
			if pcFix != nil {
				r, filtered = pcFix(r)
				if filtered {
					continue
				}
			}
			ranges = append(ranges, pcRange{r[0] + module.Addr, r[1] + module.Addr, unit})
		}
		r.SkipChildren()
	}
	return ranges, units, nil
}

func symbolizeModule(target *targets.Target, objDir, srcDir, buildDir string,
	mod *Module, pcs []uint64) ([]Frame, error) {
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
			name, path := cleanPath(frame.File, objDir, srcDir, buildDir)
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
				Inline: frame.Inline,
				Func:   frame.Func,
			})
		}
	}
	if err0 != nil {
		return nil, err0
	}
	return frames, nil
}

func symbolize(target *targets.Target, objDir, srcDir, buildDir string,
	pcs map[*Module][]uint64) ([]Frame, error) {
	var frames []Frame
	for mod, pcs1 := range pcs {
		frames1, err := symbolizeModule(target, objDir, srcDir, buildDir, mod, pcs1)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frames1...)
	}
	return frames, nil
}

// readCoverPoints finds all coverage points (calls of __sanitizer_cov_trace_*) in the object file.
// Currently it is [amd64|arm64]-specific: looks for opcode and correct offset.
// Running objdump on the whole object file is too slow.
func readCoverPoints(target *targets.Target, info *symbolInfo, data []byte) ([2][]uint64, error) {
	var pcs [2][]uint64
	if info.tracePC == 0 {
		return pcs, fmt.Errorf("no __sanitizer_cov_trace_pc symbol in the object file")
	}

	// Loop that's checking each instruction for the current architectures call
	// opcode. When found, it compares the call target address with those of the
	// __sanitizer_cov_trace_* functions we previously collected. When found,
	// we collect the pc as a coverage point.
	arch := arches[target.Arch]
	for i, opcode := range data {
		if opcode != arch.opcodes[0] && opcode != arch.opcodes[1] {
			continue
		}
		i -= arch.opcodeOffset
		if i < 0 || i+arch.callLen > len(data) {
			continue
		}
		pc := info.textAddr + uint64(i)
		target := arch.target(&arch, data[i:], pc, opcode)
		if target == info.tracePC {
			pcs[0] = append(pcs[0], pc)
		} else if info.traceCmp[target] {
			pcs[1] = append(pcs[1], pc)
		}
	}
	return pcs, nil
}

func cleanPath(path, objDir, srcDir, buildDir string) (string, string) {
	filename := ""
	switch {
	case strings.HasPrefix(path, objDir):
		// Assume the file was built there.
		path = strings.TrimPrefix(path, objDir)
		filename = filepath.Join(objDir, path)
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
	return r.Next()
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

func readSymbolsFromDwarf(debugInfo *dwarf.Data, textSymbols map[string]bool) ([]*DwarfFunction, error) {
	var allSubprograms []*DwarfFunction
	var allInlineSubroutines []*DwarfFunction
	compileUnits, err := readAllCompileUnits(debugInfo)
	if err != nil {
		return nil, err
	}
	for _, cu := range compileUnits {
		errc := make(chan error, 1)
		go func(cu *DwarfCompileUnit) {
			subprograms, err := readAllSubprograms(debugInfo, cu)
			if err != nil {
				errc <- err
				return
			}
			var textSubPrograms []*DwarfFunction
			for _, subprogram := range subprograms {
				if ok := textSymbols[subprogram.Name]; ok {
					textSubPrograms = append(textSubPrograms, subprogram)
					continue
				}
			}
			allSubprograms = append(allSubprograms, textSubPrograms...)
			inlineSubprograms := make(map[dwarf.Offset]*DwarfFunction)
			for _, sp := range subprograms {
				if sp.Inline {
					inlineSubprograms[sp.Offset] = sp
				}
			}
			for _, sp := range textSubPrograms {
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

	return allDwarfFunctions, nil
}
