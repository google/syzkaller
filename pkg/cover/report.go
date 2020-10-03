// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bufio"
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"math"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

type ReportGenerator struct {
	target       *targets.Target
	kernelObject string
	srcDir       string
	objDir       string
	buildDir     string
	units        []*compileUnit
	symbols      []*symbol
	pcs          map[uint64][]pcFrame
}

type Prog struct {
	Data string
	PCs  []uint64
}

type symbol struct {
	name       string
	unit       *compileUnit
	start      uint64
	end        uint64
	pcs        []uint64
	symbolized bool
}

type compileUnit struct {
	name     string
	filename string
	pcs      int
}

type pcFrame struct {
	symbolizer.Frame
	filename string
}

type pcRange struct {
	start uint64
	end   uint64
	cu    *compileUnit
}

func MakeReportGenerator(target *targets.Target, kernelObject, srcDir, buildDir string) (*ReportGenerator, error) {
	file, err := elf.Open(kernelObject)
	if err != nil {
		return nil, err
	}
	var coverPoints []uint64
	var symbols []*symbol
	errc := make(chan error, 1)
	go func() {
		var err error
		var tracePC uint64
		symbols, tracePC, err = readSymbols(file)
		if err != nil {
			errc <- err
			return
		}
		if target.Arch == "amd64" {
			coverPoints, err = readCoverPoints(file, tracePC)
		} else {
			coverPoints, err = objdump(target, kernelObject)
		}
		errc <- err
	}()
	ranges, units, err := readTextRanges(file)
	if err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	if len(coverPoints) == 0 {
		return nil, fmt.Errorf("%v doesn't contain coverage callbacks (set CONFIG_KCOV=y)", kernelObject)
	}
	symbols = buildSymbols(symbols, ranges, coverPoints)
	objDir := filepath.Dir(kernelObject)
	nunit := 0
	for _, unit := range units {
		if unit.pcs == 0 {
			continue // drop the unit
		}
		unit.name, unit.filename = cleanPath(unit.name, srcDir, objDir, buildDir)
		units[nunit] = unit
		nunit++
	}
	units = units[:nunit]
	if len(symbols) == 0 || len(units) == 0 {
		return nil, fmt.Errorf("failed to parse DWARF (set CONFIG_DEBUG_INFO=y?)")
	}
	rg := &ReportGenerator{
		target:       target,
		kernelObject: kernelObject,
		srcDir:       srcDir,
		objDir:       objDir,
		buildDir:     buildDir,
		units:        units,
		symbols:      symbols,
		pcs:          make(map[uint64][]pcFrame),
	}
	return rg, nil
}

func buildSymbols(symbols []*symbol, ranges []pcRange, coverPoints []uint64) []*symbol {
	// Assign coverage point PCs to symbols.
	// Both symbols and coverage points are sorted, so we do it one pass over both.
	var curSymbol *symbol
	firstSymbolPC, symbolIdx := -1, 0
	for i := 0; i < len(coverPoints); i++ {
		pc := coverPoints[i]
		for ; symbolIdx < len(symbols) && pc >= symbols[symbolIdx].end; symbolIdx++ {
		}
		var symb *symbol
		if symbolIdx < len(symbols) && pc >= symbols[symbolIdx].start && pc < symbols[symbolIdx].end {
			symb = symbols[symbolIdx]
		}
		if curSymbol != nil && curSymbol != symb {
			curSymbol.pcs = coverPoints[firstSymbolPC:i]
			firstSymbolPC = -1
		}
		curSymbol = symb
		if symb != nil && firstSymbolPC == -1 {
			firstSymbolPC = i
		}
	}
	if curSymbol != nil {
		curSymbol.pcs = coverPoints[firstSymbolPC:]
	}
	// Assign compile units to symbols based on unit pc ranges.
	// Do it one pass as both are sorted.
	nsymbol := 0
	rangeIndex := 0
	for _, s := range symbols {
		for ; rangeIndex < len(ranges) && ranges[rangeIndex].end <= s.start; rangeIndex++ {
		}
		if rangeIndex == len(ranges) || s.start < ranges[rangeIndex].start || len(s.pcs) == 0 {
			continue // drop the symbol
		}
		unit := ranges[rangeIndex].cu
		s.unit = unit
		unit.pcs += len(s.pcs)
		symbols[nsymbol] = s
		nsymbol++
	}
	return symbols[:nsymbol]
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

func (rg *ReportGenerator) DoHTML(buf io.Writer, progs []Prog) error {
	files, err := rg.prepareFileMap(progs)
	if err != nil {
		return err
	}
	return rg.generateHTML(buf, progs, files)
}

func (rg *ReportGenerator) DoCSV(buf io.Writer, progs []Prog) error {
	files, err := rg.prepareFileMap(progs)
	if err != nil {
		return err
	}
	return rg.generateCSV(buf, progs, files)
}

func (rg *ReportGenerator) prepareFileMap(progs []Prog) (map[string]*file, error) {
	files := make(map[string]*file)
	for _, unit := range rg.units {
		f := &file{
			filename: unit.filename,
			lines:    make(map[int]line),
			pcs:      unit.pcs,
		}
		files[unit.name] = f
	}
	if err := rg.lazySymbolize(files, progs); err != nil {
		return nil, err
	}
	coveredPCs := make(map[uint64]bool)
	for progIdx, prog := range progs {
		for _, pc := range prog.PCs {
			frames, ok := rg.pcs[pc]
			if !ok {
				continue
			}
			coveredPCs[pc] = true
			for _, frame := range frames {
				f := getFile(files, frame.File, frame.filename)
				ln := f.lines[frame.Line]
				if ln.count == nil {
					ln.count = make(map[int]bool)
					ln.prog = -1
				}
				ln.count[progIdx] = true
				if ln.prog == -1 || len(prog.Data) < len(progs[ln.prog].Data) {
					ln.prog = progIdx
				}
				f.lines[frame.Line] = ln
			}
		}
	}
	if len(coveredPCs) == 0 {
		return nil, fmt.Errorf("coverage doesn't match any coverage callbacks")
	}
	for pc, frames := range rg.pcs {
		if coveredPCs[pc] {
			continue
		}
		for _, frame := range frames {
			f := getFile(files, frame.File, frame.filename)
			ln := f.lines[frame.Line]
			if !frame.Inline || len(ln.count) == 0 {
				ln.uncovered = true
				f.lines[frame.Line] = ln
			}
		}
	}
	for _, s := range rg.symbols {
		covered := 0
		for _, pc := range s.pcs {
			if coveredPCs[pc] {
				covered++
			}
		}
		f := files[s.unit.name]
		f.functions = append(f.functions, &function{
			name:    s.name,
			pcs:     len(s.pcs),
			covered: covered,
		})
		sort.Slice(f.functions, func(i, j int) bool {
			return f.functions[i].name < f.functions[j].name
		})
	}
	return files, nil
}

func (rg *ReportGenerator) lazySymbolize(files map[string]*file, progs []Prog) error {
	uniquePCs := make(map[uint64]bool)
	symbolizeSymbols := make(map[*symbol]bool)
	var symbolizePCs []uint64
	anyPCs := false
	for _, prog := range progs {
		for _, pc := range prog.PCs {
			anyPCs = true
			if uniquePCs[pc] {
				continue
			}
			uniquePCs[pc] = true
			s := findSymbol(rg.symbols, pc)
			if s == nil {
				continue
			}
			files[s.unit.name].covered++
			if !s.symbolized && !symbolizeSymbols[s] {
				symbolizeSymbols[s] = true
				symbolizePCs = append(symbolizePCs, s.pcs...)
			}
		}
	}
	if !anyPCs {
		return fmt.Errorf("no coverage collected so far")
	}
	if len(symbolizeSymbols) == 0 {
		return nil
	}
	frames, err := symbolize(rg.target, rg.kernelObject, symbolizePCs)
	if err != nil {
		return err
	}
	for _, frame := range frames {
		f := pcFrame{frame, ""}
		f.File, f.filename = cleanPath(frame.File, rg.srcDir, rg.objDir, rg.buildDir)
		rg.pcs[frame.PC] = append(rg.pcs[frame.PC], f)
	}
	for s := range symbolizeSymbols {
		s.symbolized = true
	}
	return nil
}

func getFile(files map[string]*file, name, filename string) *file {
	f := files[name]
	if f == nil {
		f = &file{
			filename: filename,
			lines:    make(map[int]line),
			// Special mark for header files, if a file does not have coverage at all it is not shown.
			pcs:     1,
			covered: 1,
		}
		files[name] = f
	}
	return f
}

var csvHeader = []string{
	"Filename",
	"Function",
	"Covered PCs",
	"Total PCs",
}

func (rg *ReportGenerator) generateCSV(w io.Writer, progs []Prog, files map[string]*file) error {
	var data [][]string
	for fname, file := range files {
		for _, function := range file.functions {
			data = append(data, []string{
				fname,
				function.name,
				strconv.Itoa(function.covered),
				strconv.Itoa(function.pcs),
			})
		}
	}
	sort.Slice(data, func(i, j int) bool {
		if data[i][0] != data[j][0] {
			return data[i][0] < data[j][0]
		}
		return data[i][1] < data[j][1]
	})
	writer := csv.NewWriter(w)
	defer writer.Flush()
	if err := writer.Write(csvHeader); err != nil {
		return err
	}
	return writer.WriteAll(data)
}

func (rg *ReportGenerator) generateHTML(w io.Writer, progs []Prog, files map[string]*file) error {
	d := &templateData{
		Root: new(templateDir),
	}
	for fname, file := range files {
		pos := d.Root
		path := ""
		for {
			if path != "" {
				path += "/"
			}
			sep := strings.IndexByte(fname, filepath.Separator)
			if sep == -1 {
				path += fname
				break
			}
			dir := fname[:sep]
			path += dir
			if pos.Dirs == nil {
				pos.Dirs = make(map[string]*templateDir)
			}
			if pos.Dirs[dir] == nil {
				pos.Dirs[dir] = &templateDir{
					templateBase: templateBase{
						Path: path,
						Name: dir,
					},
				}
			}
			pos = pos.Dirs[dir]
			fname = fname[sep+1:]
		}
		f := &templateFile{
			templateBase: templateBase{
				Path:    path,
				Name:    fname,
				Total:   file.pcs,
				Covered: file.covered,
			},
		}
		pos.Files = append(pos.Files, f)
		if file.covered == 0 {
			continue
		}
		lines, err := parseFile(file.filename)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		for i, ln := range lines {
			cov, ok := file.lines[i+1]
			prog, class, count := "", "", "     "
			if ok {
				if len(cov.count) != 0 {
					if cov.prog != -1 {
						prog = fmt.Sprintf("onclick='onProgClick(%v)'", cov.prog)
					}
					count = fmt.Sprintf("% 5v", len(cov.count))
					class = "covered"
					if cov.uncovered {
						class = "both"
					}
				} else {
					class = "uncovered"
				}
			}
			buf.WriteString(fmt.Sprintf("<span class='count' %v>%v</span>", prog, count))
			if class == "" {
				buf.WriteByte(' ')
				buf.Write(ln)
				buf.WriteByte('\n')
			} else {
				buf.WriteString(fmt.Sprintf("<span class='%v'> ", class))
				buf.Write(ln)
				buf.WriteString("</span>\n")
			}
		}
		d.Contents = append(d.Contents, template.HTML(buf.String()))
		f.Index = len(d.Contents) - 1

		addFunctionCoverage(file, d)
	}
	for _, prog := range progs {
		d.Progs = append(d.Progs, template.HTML(html.EscapeString(prog.Data)))
	}

	processDir(d.Root)
	return coverTemplate.Execute(w, d)
}

func addFunctionCoverage(file *file, data *templateData) {
	var buf bytes.Buffer
	for _, function := range file.functions {
		percentage := ""
		if function.covered > 0 {
			percentage = fmt.Sprintf("%v%%", percent(function.covered, function.pcs))
		} else {
			percentage = "---"
		}
		buf.WriteString(fmt.Sprintf("<span class='hover'>%v", function.name))
		buf.WriteString(fmt.Sprintf("<span class='cover hover'>%v", percentage))
		buf.WriteString(fmt.Sprintf("<span class='cover-right'>of %v", strconv.Itoa(function.pcs)))
		buf.WriteString("</span></span></span><br>\n")
	}
	data.Functions = append(data.Functions, template.HTML(buf.String()))
}

func processDir(dir *templateDir) {
	for len(dir.Dirs) == 1 && len(dir.Files) == 0 {
		for _, child := range dir.Dirs {
			dir.Name += "/" + child.Name
			dir.Files = child.Files
			dir.Dirs = child.Dirs
		}
	}
	sort.Slice(dir.Files, func(i, j int) bool {
		return dir.Files[i].Name < dir.Files[j].Name
	})
	for _, f := range dir.Files {
		dir.Total += f.Total
		dir.Covered += f.Covered
		f.Percent = percent(f.Covered, f.Total)
	}
	for _, child := range dir.Dirs {
		processDir(child)
		dir.Total += child.Total
		dir.Covered += child.Covered
	}
	dir.Percent = percent(dir.Covered, dir.Total)
	if dir.Covered == 0 {
		dir.Dirs = nil
		dir.Files = nil
	}
}

func cleanPath(path, srcDir, objDir, buildDir string) (string, string) {
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

func percent(covered, total int) int {
	f := math.Ceil(float64(covered) / float64(total) * 100)
	if f == 100 && covered < total {
		f = 99
	}
	return int(f)
}

func findSymbol(symbols []*symbol, pc uint64) *symbol {
	idx := sort.Search(len(symbols), func(i int) bool {
		return pc < symbols[i].end
	})
	if idx == len(symbols) {
		return nil
	}
	s := symbols[idx]
	if pc < s.start || pc > s.end {
		return nil
	}
	return s
}

func readSymbols(file *elf.File) ([]*symbol, uint64, error) {
	text := file.Section(".text")
	if text == nil {
		return nil, 0, fmt.Errorf("no .text section in the object file")
	}
	allSymbols, err := file.Symbols()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read ELF symbols: %v", err)
	}
	var tracePC uint64
	var symbols []*symbol
	for _, symb := range allSymbols {
		if symb.Value < text.Addr || symb.Value+symb.Size > text.Addr+text.Size {
			continue
		}
		symbols = append(symbols, &symbol{
			name:  symb.Name,
			start: symb.Value,
			end:   symb.Value + symb.Size,
		})
		if tracePC == 0 && symb.Name == "__sanitizer_cov_trace_pc" {
			tracePC = symb.Value
		}
	}
	if tracePC == 0 {
		return nil, 0, fmt.Errorf("no __sanitizer_cov_trace_pc symbol in the object file")
	}
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].start < symbols[j].start
	})
	return symbols, tracePC, nil
}

func readTextRanges(file *elf.File) ([]pcRange, []*compileUnit, error) {
	text := file.Section(".text")
	if text == nil {
		return nil, nil, fmt.Errorf("no .text section in the object file")
	}
	debugInfo, err := file.DWARF()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DWARF: %v (set CONFIG_DEBUG_INFO=y?)", err)
	}
	var ranges []pcRange
	var units []*compileUnit
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
		unit := &compileUnit{
			name: attrName.(string),
		}
		units = append(units, unit)
		ranges1, err := debugInfo.Ranges(ent)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range ranges1 {
			if r[0] >= r[1] || r[0] < text.Addr || r[1] > text.Addr+text.Size {
				continue
			}
			ranges = append(ranges, pcRange{r[0], r[1], unit})
		}
		r.SkipChildren()
	}
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})
	return ranges, units, nil
}

func symbolize(target *targets.Target, obj string, pcs []uint64) ([]symbolizer.Frame, error) {
	procs := runtime.GOMAXPROCS(0) / 2
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
				frames, err := symb.SymbolizeArray(obj, pcs)
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
	var frames []symbolizer.Frame
	for p := 0; p < procs; p++ {
		res := <-symbolizerC
		if res.err != nil {
			err0 = res.err
		}
		frames = append(frames, res.frames...)
	}
	if err0 != nil {
		return nil, err0
	}
	return frames, nil
}

// readCoverPoints finds all coverage points (calls of __sanitizer_cov_trace_pc) in the object file.
// Currently it is amd64-specific: looks for e8 opcode and correct offset.
// Running objdump on the whole object file is too slow.
func readCoverPoints(file *elf.File, tracePC uint64) ([]uint64, error) {
	text := file.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section in the object file")
	}
	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .text: %v", err)
	}
	var pcs []uint64
	const callLen = 5
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
		if target == tracePC {
			pcs = append(pcs, pc)
		}
	}
	return pcs, nil
}

// objdump is an old, slow way of finding coverage points.
// amd64 uses faster option of parsing binary directly (readCoverPoints).
// TODO: use the faster approach for all other arches and drop this.
func objdump(target *targets.Target, obj string) ([]uint64, error) {
	cmd := osutil.Command(target.Objdump, "-d", "--no-show-raw-insn", obj)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	defer stderr.Close()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to run objdump on %v: %v", obj, err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	s := bufio.NewScanner(stdout)
	callInsns, traceFuncs := archCallInsn(target)
	var pcs []uint64
	for s.Scan() {
		if pc := parseLine(callInsns, traceFuncs, s.Bytes()); pc != 0 {
			pcs = append(pcs, pc)
		}
	}
	stderrOut, _ := ioutil.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("failed to run objdump on %v: %v\n%s", obj, err, stderrOut)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("failed to run objdump on %v: %v\n%s", obj, err, stderrOut)
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

func parseFile(fn string) ([][]byte, error) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	htmlReplacer := strings.NewReplacer(">", "&gt;", "<", "&lt;", "&", "&amp;", "\t", "        ")
	var lines [][]byte
	for {
		idx := bytes.IndexByte(data, '\n')
		if idx == -1 {
			break
		}
		lines = append(lines, []byte(htmlReplacer.Replace(string(data[:idx]))))
		data = data[idx+1:]
	}
	if len(data) != 0 {
		lines = append(lines, data)
	}
	return lines, nil
}

func PreviousInstructionPC(target *targets.Target, pc uint64) uint64 {
	switch target.Arch {
	case "amd64":
		return pc - 5
	case "386":
		return pc - 5
	case "arm64":
		return pc - 4
	case "arm":
		// THUMB instructions are 2 or 4 bytes with low bit set.
		// ARM instructions are always 4 bytes.
		return (pc - 3) & ^uint64(1)
	case "ppc64le":
		return pc - 4
	case "mips64le":
		return pc - 8
	case "s390x":
		return pc - 6
	case "riscv64":
		return pc - 4
	default:
		panic(fmt.Sprintf("unknown arch %q", target.Arch))
	}
}

func archCallInsn(target *targets.Target) ([][]byte, [][]byte) {
	callName := [][]byte{[]byte(" <__sanitizer_cov_trace_pc>")}
	switch target.Arch {
	case "386":
		// c1000102:       call   c10001f0 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tcall ")}, callName
	case "arm64":
		// ffff0000080d9cc0:       bl      ffff00000820f478 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbl\t")}, callName
	case "arm":
		// 8010252c:       bl      801c3280 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbl\t")}, callName
	case "ppc64le":
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
	case "mips64le":
		// ffffffff80100420:       jal     ffffffff80205880 <__sanitizer_cov_trace_pc>
		// This is only known to occur in the test:
		// b58:   bal     b30 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tjal\t"), []byte("\tbal\t")}, callName
	case "s390x":
		// 1001de:       brasl   %r14,2bc090 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tbrasl\t")}, callName
	case "riscv64":
		// ffffffe000200018:       jal     ra,ffffffe0002935b0 <__sanitizer_cov_trace_pc>
		// ffffffe0000010da:       jalr    1242(ra) # ffffffe0002935b0 <__sanitizer_cov_trace_pc>
		return [][]byte{[]byte("\tjal\t"), []byte("\tjalr\t")}, callName
	default:
		panic(fmt.Sprintf("unknown arch %q", target.Arch))
	}
}

type templateData struct {
	Root      *templateDir
	Contents  []template.HTML
	Progs     []template.HTML
	Functions []template.HTML
}

type templateBase struct {
	Name    string
	Path    string
	Total   int
	Covered int
	Percent int
}

type templateDir struct {
	templateBase
	Dirs  map[string]*templateDir
	Files []*templateFile
}

type templateFile struct {
	templateBase
	Index int
}

var coverTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>
			.file {
				display: none;
				margin: 0;
				padding: 0;
			}
			.count {
				font-weight: bold;
				border-right: 1px solid #ddd;
				padding-right: 4px;
				cursor: zoom-in;
			}
			.split {
				height: 100%;
				position: fixed;
				z-index: 1;
				top: 0;
				overflow-x: hidden;
			}
			.tree {
				left: 0;
				width: 24%;
			}
			.function {
				height: 100%;
				position: fixed;
				z-index: 1;
				top: 0;
				overflow-x: hidden;
				display: none;
			}
			.list {
				left: 24%;
				width: 30%;
			}
			.right {
				border-left: 2px solid #444;
				right: 0;
				width: 76%;
				font-family: 'Courier New', Courier, monospace;
				color: rgb(80, 80, 80);
			}
			.cover {
				float: right;
				width: 120px;
				padding-right: 4px;
			}
			.cover-right {
				float: right;
			}
			.covered {
				color: rgb(0, 0, 0);
				font-weight: bold;
			}
			.uncovered {
				color: rgb(255, 0, 0);
				font-weight: bold;
			}
			.both {
				color: rgb(200, 100, 0);
				font-weight: bold;
			}
			ul, #dir_list {
				list-style-type: none;
				padding-left: 16px;
			}
			#dir_list {
				margin: 0;
				padding: 0;
			}
			.hover:hover {
				background: #ffff99;
			}
			.caret {
				cursor: pointer;
				user-select: none;
			}
			.caret::before {
				color: black;
				content: "\25B6";
				display: inline-block;
				margin-right: 3px;
			}
			.caret-down::before {
				transform: rotate(90deg);
			}
			.nested {
				display: none;
			}
			.active {
				display: block;
			}
		</style>
	</head>
	<body>
		<div class="split tree">
			<ul id="dir_list">
				{{template "dir" .Root}}
			</ul>
		</div>
		<div id="right_pane" class="split right">
			{{range $i, $f := .Contents}}
				<pre class="file" id="contents_{{$i}}">{{$f}}</pre>
			{{end}}
			{{range $i, $p := .Progs}}
				<pre class="file" id="prog_{{$i}}">{{$p}}</pre>
			{{end}}
			{{range $i, $p := .Functions}}
				<div class="function list" id="function_{{$i}}">{{$p}}</div>
			{{end}}
		</div>
	</body>
	<script>
	(function() {
		var toggler = document.getElementsByClassName("caret");
		for (var i = 0; i < toggler.length; i++) {
			toggler[i].addEventListener("click", function() {
				this.parentElement.querySelector(".nested").classList.toggle("active");
				this.classList.toggle("caret-down");
			});
		}
		if (window.location.hash) {
			var hash = decodeURIComponent(window.location.hash.substring(1)).split("/");
			var path = "path";
			for (var i = 0; i < hash.length; i++) {
				path += "/" + hash[i];
				var elem = document.getElementById(path);
				if (elem)
					elem.click();
			}
		}
	})();
	var visible;
        function onPercentClick(index) {
		if (visible)
			visible.style.display = 'none';
		visible = document.getElementById("function_" + index);
		visible.style.display = 'block';
		document.getElementById("right_pane").scrollTo(0, 0);
	}
	function onFileClick(index) {
		if (visible)
			visible.style.display = 'none';
		visible = document.getElementById("contents_" + index);
		visible.style.display = 'block';
		document.getElementById("right_pane").scrollTo(0, 0);
	}
	function onProgClick(index) {
		if (visible)
			visible.style.display = 'none';
		visible = document.getElementById("prog_" + index);
		visible.style.display = 'block';
		document.getElementById("right_pane").scrollTo(0, 0);
	}
	</script>
</html>

{{define "dir"}}
	{{range $dir := .Dirs}}
		<li>
			<span id="path/{{$dir.Path}}" class="caret hover">
				{{$dir.Name}}
				<span class="cover hover">
					{{if $dir.Covered}}{{$dir.Percent}}%{{else}}---{{end}}
					<span class="cover-right">of {{$dir.Total}}</span>
				</span>
			</span>
			<ul class="nested">
				{{template "dir" $dir}}
			</ul>
		</li>
	{{end}}
	{{range $file := .Files}}
		<li><span class="hover">
			{{if $file.Covered}}
				<a href="#{{$file.Path}}" id="path/{{$file.Path}}" onclick="onFileClick({{$file.Index}})">
					{{$file.Name}}
				</a>
				<span class="cover hover">
					<a href="#{{$file.Path}}/func_cov" id="path/{{$file.Path}}/func_cov" onclick="onPercentClick({{$file.Index}})">
                                                {{$file.Percent}}%
					</a>
					<span class="cover-right">of {{$file.Total}}</span>
				</span>
			{{else}}
					{{$file.Name}}<span class="cover hover">---<span class="cover-right">
						of {{$file.Total}}</span></span>
			{{end}}
		</span></li>
	{{end}}
{{end}}
`))
