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
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

type dwarfParams struct {
	target                *targets.Target
	objDir                string
	srcDir                string
	buildDir              string
	splitBuildDelimiters  []string
	moduleObj             []string
	hostModules           []KernelModule
	readSymbols           func(*Module, *symbolInfo) ([]*Symbol, error)
	readTextData          func(*Module) ([]byte, error)
	readModuleCoverPoints func(*targets.Target, *Module, *symbolInfo) ([2][]uint64, error)
	readTextRanges        func(*Module) ([]pcRange, []*CompileUnit, error)
	getCompilerVersion    func(string) string
}

type Arch struct {
	scanSize      int
	callLen       int
	relaOffset    uint64
	callRelocType uint64
	isCallInsn    func(arch *Arch, insn []byte) bool
	callTarget    func(arch *Arch, insn []byte, pc uint64) uint64
}

var arches = map[string]Arch{
	targets.AMD64: {
		scanSize:      1,
		callLen:       5,
		relaOffset:    1,
		callRelocType: uint64(elf.R_X86_64_PLT32),
		isCallInsn: func(arch *Arch, insn []byte) bool {
			return insn[0] == 0xe8
		},
		callTarget: func(arch *Arch, insn []byte, pc uint64) uint64 {
			off := uint64(int64(int32(binary.LittleEndian.Uint32(insn[1:]))))
			return pc + off + uint64(arch.callLen)
		},
	},
	targets.ARM64: {
		scanSize:      4,
		callLen:       4,
		callRelocType: uint64(elf.R_AARCH64_CALL26),
		isCallInsn: func(arch *Arch, insn []byte) bool {
			const mask = uint32(0xfc000000)
			const opc = uint32(0x94000000)
			return binary.LittleEndian.Uint32(insn)&mask == opc
		},
		callTarget: func(arch *Arch, insn []byte, pc uint64) uint64 {
			off26 := binary.LittleEndian.Uint32(insn) & 0x3ffffff
			sign := off26 >> 25
			off := uint64(off26)
			// Sign-extend the 26-bit offset stored in the instruction.
			if sign == 1 {
				off |= 0xfffffffffc000000
			}
			return pc + 4*off
		},
	},
}

func makeDWARF(params *dwarfParams) (impl *Impl, err error) {
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
	impl, err = makeDWARFUnsafe(params)
	return
}

type Result struct {
	CoverPoints [2][]uint64
	Symbols     []*Symbol
}

func processModule(params *dwarfParams, module *Module, info *symbolInfo,
	target *targets.Target) (*Result, error) {
	symbols, err := params.readSymbols(module, info)
	if err != nil {
		return nil, err
	}

	var data []byte
	var coverPoints [2][]uint64
	if target.Arch != targets.AMD64 && target.Arch != targets.ARM64 {
		coverPoints, err = objdump(target, module)
	} else if module.Name == "" {
		data, err = params.readTextData(module)
		if err != nil {
			return nil, err
		}
		coverPoints, err = readCoverPoints(target, info, data)
	} else {
		coverPoints, err = params.readModuleCoverPoints(target, module, info)
	}
	if err != nil {
		return nil, err
	}

	result := &Result{
		Symbols:     symbols,
		CoverPoints: coverPoints,
	}
	return result, nil
}

func makeDWARFUnsafe(params *dwarfParams) (*Impl, error) {
	target := params.target
	objDir := params.objDir
	srcDir := params.srcDir
	buildDir := params.buildDir
	splitBuildDelimiters := params.splitBuildDelimiters
	modules, err := discoverModules(target, objDir, params.moduleObj, params.hostModules)
	if err != nil {
		return nil, err
	}

	// Here and below index 0 refers to coverage callbacks (__sanitizer_cov_trace_pc(_guard))
	// and index 1 refers to comparison callbacks (__sanitizer_cov_trace_cmp*).
	var allCoverPoints [2][]uint64
	var allSymbols []*Symbol
	var allRanges []pcRange
	var allUnits []*CompileUnit
	preciseCoverage := true
	type binResult struct {
		symbols     []*Symbol
		coverPoints [2][]uint64
		ranges      []pcRange
		units       []*CompileUnit
		err         error
	}
	binC := make(chan binResult, len(modules))
	for _, module := range modules {
		go func(m *Module) {
			info := &symbolInfo{
				tracePC:     make(map[uint64]bool),
				traceCmp:    make(map[uint64]bool),
				tracePCIdx:  make(map[int]bool),
				traceCmpIdx: make(map[int]bool),
			}
			result, err := processModule(params, module, info, target)
			if err != nil {
				binC <- binResult{err: err}
				return
			}
			if module.Name == "" && len(result.CoverPoints[0]) == 0 {
				err = fmt.Errorf("%v doesn't contain coverage callbacks (set CONFIG_KCOV=y on linux)", module.Path)
				if err != nil {
					binC <- binResult{err: err}
					return
				}
			}
			ranges, units, err := params.readTextRanges(module)
			if err != nil {
				binC <- binResult{err: err}
				return
			}
			binC <- binResult{symbols: result.Symbols, coverPoints: result.CoverPoints, ranges: ranges, units: units}
		}(module)
		if isKcovBrokenInCompiler(params.getCompilerVersion(module.Path)) {
			preciseCoverage = false
		}
	}
	for range modules {
		result := <-binC
		if err := result.err; err != nil {
			return nil, err
		}
		allSymbols = append(allSymbols, result.symbols...)
		allCoverPoints[0] = append(allCoverPoints[0], result.coverPoints[0]...)
		allCoverPoints[1] = append(allCoverPoints[1], result.coverPoints[1]...)
		allRanges = append(allRanges, result.ranges...)
		allUnits = append(allUnits, result.units...)
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
		unit.Name, unit.Path = cleanPath(unit.Name, objDir, srcDir, buildDir, splitBuildDelimiters)
		allUnits[nunit] = unit
		nunit++
	}
	allUnits = allUnits[:nunit]
	if len(allSymbols) == 0 || len(allUnits) == 0 {
		return nil, fmt.Errorf("failed to parse DWARF (set CONFIG_DEBUG_INFO=y on linux)")
	}
	var interner symbolizer.Interner
	impl := &Impl{
		Units:   allUnits,
		Symbols: allSymbols,
		Symbolize: func(pcs map[*Module][]uint64) ([]Frame, error) {
			return symbolize(target, &interner, objDir, srcDir, buildDir, splitBuildDelimiters, pcs)
		},
		CallbackPoints:  allCoverPoints[0],
		PreciseCoverage: preciseCoverage,
	}
	return impl, nil
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

// Regexps to parse compiler version string in isKcovBrokenInCompiler.
// Some targets (e.g. NetBSD) use g++ instead of gcc.
var gccRE = regexp.MustCompile(`gcc|GCC|g\+\+`)
var gccVersionRE = regexp.MustCompile(`(gcc|GCC|g\+\+).* ([0-9]{1,2})\.[0-9]+\.[0-9]+`)

// GCC < 14 incorrectly tail-calls kcov callbacks, which does not let syzkaller
// verify that collected coverage points have matching callbacks.
// See https://github.com/google/syzkaller/issues/4447 for more information.
func isKcovBrokenInCompiler(versionStr string) bool {
	if !gccRE.MatchString(versionStr) {
		return false
	}
	groups := gccVersionRE.FindStringSubmatch(versionStr)
	if len(groups) > 0 {
		version, err := strconv.Atoi(groups[2])
		if err == nil {
			return version < 14
		}
	}
	return true
}

type symbolInfo struct {
	textAddr uint64
	// Set of addresses that correspond to __sanitizer_cov_trace_pc or its trampolines.
	tracePC     map[uint64]bool
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

func symbolizeModule(target *targets.Target, interner *symbolizer.Interner, objDir, srcDir, buildDir string,
	splitBuildDelimiters []string, mod *Module, pcs []uint64) ([]Frame, error) {
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
					res.err = fmt.Errorf("failed to symbolize: %w", err)
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
			name, path := cleanPath(frame.File, objDir, srcDir, buildDir, splitBuildDelimiters)
			frames = append(frames, Frame{
				Module:   mod,
				PC:       frame.PC + mod.Addr,
				Name:     interner.Do(name),
				FuncName: frame.Func,
				Path:     interner.Do(path),
				Inline:   frame.Inline,
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

func symbolize(target *targets.Target, interner *symbolizer.Interner, objDir, srcDir, buildDir string,
	splitBuildDelimiters []string, pcs map[*Module][]uint64) ([]Frame, error) {
	var frames []Frame
	type frameResult struct {
		frames []Frame
		err    error
	}
	frameC := make(chan frameResult, len(pcs))
	for mod, pcs1 := range pcs {
		go func(mod *Module, pcs []uint64) {
			frames, err := symbolizeModule(target, interner, objDir, srcDir, buildDir, splitBuildDelimiters, mod, pcs)
			frameC <- frameResult{frames: frames, err: err}
		}(mod, pcs1)
	}
	for range pcs {
		res := <-frameC
		if res.err != nil {
			return nil, res.err
		}
		frames = append(frames, res.frames...)
	}
	return frames, nil
}

// nextCallTarget finds the next call instruction in data[] starting at *pos and returns that
// instruction's target and pc.
func nextCallTarget(arch *Arch, textAddr uint64, data []byte, pos *int) (uint64, uint64) {
	for *pos < len(data) {
		i := *pos
		if i+arch.callLen > len(data) {
			break
		}
		*pos += arch.scanSize
		insn := data[i : i+arch.callLen]
		if !arch.isCallInsn(arch, insn) {
			continue
		}
		pc := textAddr + uint64(i)
		callTarget := arch.callTarget(arch, insn, pc)
		*pos = i + arch.scanSize
		return callTarget, pc
	}
	return 0, 0
}

// readCoverPoints finds all coverage points (calls of __sanitizer_cov_trace_*) in the object file.
// Currently it is [amd64|arm64]-specific: looks for opcode and correct offset.
// Running objdump on the whole object file is too slow.
func readCoverPoints(target *targets.Target, info *symbolInfo, data []byte) ([2][]uint64, error) {
	var pcs [2][]uint64
	if len(info.tracePC) == 0 {
		return pcs, fmt.Errorf("no __sanitizer_cov_trace_pc symbol in the object file")
	}

	i := 0
	for {
		arch := arches[target.Arch]
		callTarget, pc := nextCallTarget(&arch, info.textAddr, data, &i)
		if callTarget == 0 {
			break
		}
		if info.tracePC[callTarget] {
			pcs[0] = append(pcs[0], pc)
		} else if info.traceCmp[callTarget] {
			pcs[1] = append(pcs[1], pc)
		}
	}
	return pcs, nil
}

// Source files for Android may be split between two subdirectories: the common AOSP kernel
// and the device-specific drivers: https://source.android.com/docs/setup/build/building-pixel-kernels.
// Android build system references these subdirectories in various ways, which often results in
// paths to non-existent files being recorded in the debug info.
//
// cleanPathAndroid() assumes that the subdirectories reside in `srcDir`, with their names being listed in
// `delimiters`.
// If one of the `delimiters` occurs in the `path`, it is stripped together with the path prefix, and the
// remaining file path is appended to `srcDir + delimiter`.
// If none of the `delimiters` occur in the `path`, `path` is treated as a relative path that needs to be
// looked up in `srcDir + delimiters[i]`.
func cleanPathAndroid(path, srcDir string, delimiters []string, existFn func(string) bool) (string, string) {
	if len(delimiters) == 0 {
		return "", ""
	}
	reStr := "(" + strings.Join(delimiters, "|") + ")(.*)"
	re := regexp.MustCompile(reStr)
	match := re.FindStringSubmatch(path)
	if match != nil {
		delimiter := match[1]
		filename := match[2]
		path := filepath.Clean(srcDir + delimiter + filename)
		return filename, path
	}
	// None of the delimiters found in `path`: it is probably a relative path to the source file.
	// Try to look it up in every subdirectory of srcDir.
	for _, delimiter := range delimiters {
		absPath := filepath.Clean(srcDir + delimiter + path)
		if existFn(absPath) {
			return path, absPath
		}
	}
	return "", ""
}

func cleanPath(path, objDir, srcDir, buildDir string, splitBuildDelimiters []string) (string, string) {
	filename := ""

	path = filepath.Clean(path)
	aname, apath := cleanPathAndroid(path, srcDir, splitBuildDelimiters, osutil.IsExist)
	if aname != "" {
		return aname, apath
	}
	absPath := osutil.Abs(path)
	switch {
	case strings.HasPrefix(absPath, objDir):
		// Assume the file was built there.
		path = strings.TrimPrefix(absPath, objDir)
		filename = filepath.Join(objDir, path)
	case strings.HasPrefix(absPath, buildDir):
		// Assume the file was moved from buildDir to srcDir.
		path = strings.TrimPrefix(absPath, buildDir)
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
		return pcs, fmt.Errorf("failed to run objdump on %v: %w", mod.Path, err)
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
	stderrOut, _ := io.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		return pcs, fmt.Errorf("failed to run objdump on %v: %w\n%s", mod.Path, err, stderrOut)
	}
	if err := s.Err(); err != nil {
		return pcs, fmt.Errorf("failed to run objdump on %v: %w\n%s", mod.Path, err, stderrOut)
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
		return [][]byte{[]byte("\tbl ")}, [][]byte{
			[]byte("<__sanitizer_cov_trace_pc>"),
			[]byte("<____sanitizer_cov_trace_pc_veneer>"),
		}

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
