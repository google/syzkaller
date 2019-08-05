// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type ReportGenerator struct {
	srcDir   string
	buildDir string
	symbols  map[string][]symbol
	pcs      map[string]map[uint64][]symbolizer.Frame
}

type Prog struct {
	Data string
	PCs  []uint64
}

type symbol struct {
	start uint64
	end   uint64
}

func MakeReportGenerator(modules map[string]string, srcDir, buildDir, arch string) (*ReportGenerator, error) {
	rg := &ReportGenerator{
		srcDir:   srcDir,
		buildDir: buildDir,
		pcs:      make(map[string]map[uint64][]symbolizer.Frame),
	}
	errc := make(chan error)
	go func() {
		var err error
		rg.symbols, err = readSymbols(modules)
		errc <- err
	}()
	frames, err := objdumpAndSymbolize(modules, arch)
	if err != nil {
		return nil, err
	}
	for module, frms := range frames {
		if len(frms) == 0 && module == "vmlinux" {
			return nil, fmt.Errorf("%v does not have debug info (set CONFIG_DEBUG_INFO=y)", modules["vmlinux"])
		}
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	for module, frms := range frames {
		for _, frame := range frms {
			if _, ok := rg.pcs[module]; !ok {
				rg.pcs[module] = make(map[uint64][]symbolizer.Frame)
			}
			rg.pcs[module][frame.PC] = append(rg.pcs[module][frame.PC], frame)
		}
	}
	return rg, nil
}

type file struct {
	lines       map[int]line
	totalPCs    map[uint64]bool
	coverPCs    map[uint64]bool
	totalInline map[int]bool
	coverInline map[int]bool
}

type line struct {
	count         map[int]bool
	prog          int
	uncovered     bool
	symbolCovered bool
}

func (rg *ReportGenerator) Do(w io.Writer, moduleProgs map[string][]Prog, dlkmAddr map[string]uint64) error {
	coveredPCs := make(map[string]map[uint64]bool)
	symbols := make(map[string]map[uint64]bool)
	files := make(map[string]*file)
	for module, progs := range moduleProgs {
		offset := dlkmAddr[module]
		if module == "vmlinux" {
			offset = 0
		}
		for progIdx, prog := range progs {
			for _, pc := range prog.PCs {
				if _, ok := symbols[module]; !ok {
					symbols[module] = make(map[uint64]bool)
				}
				symbols[module][rg.findSymbol(module, pc-offset)] = true
				frames, ok := rg.pcs[module][pc-offset]
				if !ok {
					continue
				}
				if _, ok := coveredPCs[module]; !ok {
					coveredPCs[module] = make(map[uint64]bool)
				}
				coveredPCs[module][pc-offset] = true
				for _, frame := range frames {
					f := getFile(files, frame.File)
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
		if len(coveredPCs[module]) == 0 && module == "vmlinux" {
			return fmt.Errorf("no coverage data available")
		}
		for pc, frames := range rg.pcs[module] {
			covered := coveredPCs[module][pc-offset]
			for _, frame := range frames {
				f := getFile(files, frame.File)
				if frame.Inline {
					f.totalInline[frame.Line] = true
					if covered {
						f.coverInline[frame.Line] = true
					}
				} else {
					f.totalPCs[pc-offset] = true
					if covered {
						f.coverPCs[pc-offset] = true
					}
				}
				if !covered {
					ln := f.lines[frame.Line]
					if !frame.Inline || len(ln.count) == 0 {
						ln.uncovered = true
						ln.symbolCovered = symbols[module][rg.findSymbol(module, pc-offset)]
						f.lines[frame.Line] = ln
					}
				}
			}
		}
	}
	return rg.generate(w, moduleProgs, files)
}

func getFile(files map[string]*file, name string) *file {
	f := files[name]
	if f == nil {
		f = &file{
			lines:       make(map[int]line),
			totalPCs:    make(map[uint64]bool),
			coverPCs:    make(map[uint64]bool),
			totalInline: make(map[int]bool),
			coverInline: make(map[int]bool),
		}
		files[name] = f
	}
	return f
}

func (rg *ReportGenerator) generate(w io.Writer, moduleProgs map[string][]Prog, files map[string]*file) error {
	d := &templateData{
		Root: new(templateDir),
	}
	for fname, file := range files {
		if !strings.HasPrefix(fname, rg.buildDir) {
			return fmt.Errorf("path '%s' doesn't match build dir '%s'", fname, rg.buildDir)
		}
		// Trim the existing build dir
		remain := filepath.Clean(strings.TrimPrefix(fname, rg.buildDir))
		// Add the current kernel source dir
		fname = filepath.Join(rg.srcDir, remain)
		pos := d.Root
		path := ""
		for {
			if path != "" {
				path += "/"
			}
			sep := strings.IndexByte(remain, filepath.Separator)
			if sep == -1 {
				path += remain
				break
			}
			dir := remain[:sep]
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
			remain = remain[sep+1:]
		}
		f := &templateFile{
			templateBase: templateBase{
				Path:    path,
				Name:    remain,
				Total:   len(file.totalPCs) + len(file.totalInline),
				Covered: len(file.coverPCs) + len(file.coverInline),
			},
		}
		if f.Total == 0 {
			return fmt.Errorf("%v: file does not have any coverage", fname)
		}
		pos.Files = append(pos.Files, f)
		if len(file.lines) == 0 || f.Covered == 0 {
			continue
		}
		lines, err := parseFile(fname)
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
					class = "weak-uncovered"
					if cov.symbolCovered {
						class = "uncovered"
					}
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
	}
	for _, progs := range moduleProgs {
		for _, prog := range progs {
			d.Progs = append(d.Progs, template.HTML(html.EscapeString(prog.Data)))
		}
	}
	processDir(d.Root)
	return coverTemplate.Execute(w, d)
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

func percent(covered, total int) int {
	f := math.Ceil(float64(covered) / float64(total) * 100)
	if f == 100 && covered < total {
		f = 99
	}
	return int(f)
}

func (rg *ReportGenerator) findSymbol(module string, pc uint64) uint64 {
	idx := sort.Search(len(rg.symbols[module]), func(i int) bool {
		return pc < rg.symbols[module][i].end
	})
	if idx == len(rg.symbols[module]) {
		return 0
	}
	s := rg.symbols[module][idx]
	if pc < s.start || pc > s.end {
		return 0
	}
	return s.start
}

func readSymbols(modules map[string]string) (map[string][]symbol, error) {
	symbols := make(map[string][]symbol)
	for module := range modules {
		raw, err := symbolizer.ReadSymbols(modules[module])
		if err != nil {
			return nil, fmt.Errorf("failed to run nm on %v: %v", modules[module], err)
		}
		for _, ss := range raw {
			for _, s := range ss {
				symbols[module] = append(symbols[module], symbol{
					start: s.Addr,
					end:   s.Addr + uint64(s.Size),
				})
			}
		}
		sort.Slice(symbols[module], func(i, j int) bool {
			return symbols[module][i].start < symbols[module][j].start
		})
	}
	return symbols, nil
}

func getCrossCompilerPrefix(arch string) string {
	var prefix string
	switch arch {
	case "amd64":
		prefix = "x86_64_linux-gnu-"
	case "386":
		prefix = "x86_64_linux-gnu-"
	case "arm64":
		prefix = "aarch64-linux-gnu-"
	case "arm":
		prefix = "arm-linux-gnueabi-"
	case "ppc64le":
		prefix = "powerpc64le-linux-gnu-"
	default:
		prefix = ""
	}
	return prefix
}

// objdumpAndSymbolize collects list of PCs of __sanitizer_cov_trace_pc calls
// in the kernel and symbolizes them.
func objdumpAndSymbolize(modules map[string]string, arch string) (map[string][]symbolizer.Frame, error) {
	prefix := getCrossCompilerPrefix(arch)
	frames := make(map[string][]symbolizer.Frame)
	for module := range modules {
		errc := make(chan error)
		pcchan := make(chan []uint64, 10)
		go func() {
			symb := symbolizer.NewSymbolizer()
			defer symb.Close()
			var err error
			for PCs := range pcchan {
				if err != nil {
					continue
				}
				frames1, err1 := symb.SymbolizeArray(modules[module], PCs)
				if err1 != nil {
					err = fmt.Errorf("failed to symbolize: %v", err1)
				}
				frames[module] = append(frames[module], frames1...)
			}
			errc <- err
		}()
		cmd := osutil.Command(prefix+"objdump", "-d", "--no-show-raw-insn", modules[module])
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		defer stdout.Close()
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to run objdump on %v: %v", modules[module], err)
		}
		defer func() {
			cmd.Process.Kill()
			cmd.Wait()
		}()
		s := bufio.NewScanner(stdout)
		callInsnS, traceFuncS := archCallInsn(arch)
		callInsn, traceFunc := []byte(callInsnS), []byte(traceFuncS)
		var pcs []uint64
		for s.Scan() {
			ln := s.Bytes()
			if pos := bytes.Index(ln, callInsn); pos == -1 {
				continue
			} else if !bytes.Contains(ln[pos:], traceFunc) {
				continue
			}
			for len(ln) != 0 && ln[0] == ' ' {
				ln = ln[1:]
			}
			colon := bytes.IndexByte(ln, ':')
			if colon == -1 {
				continue
			}
			pc, err := strconv.ParseUint(string(ln[:colon]), 16, 64)
			if err != nil {
				continue
			}
			pcs = append(pcs, pc)
			if len(pcs) == 100 {
				pcchan <- pcs
				pcs = nil
			}
		}
		if len(pcs) != 0 {
			pcchan <- pcs
		}
		close(pcchan)
		if err := s.Err(); err != nil {
			return nil, fmt.Errorf("failed to run objdump output: %v", err)
		}
		if err := <-errc; err != nil {
			return nil, err
		}
	}
	for module := range modules {
		sort.Slice(frames[module], func(i, j int) bool {
			return frames[module][i].PC < frames[module][j].PC
		})
	}
	return frames, nil
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

func PreviousInstructionPC(arch string, pc uint64) uint64 {
	switch arch {
	case "amd64":
		return pc - 5
	case "386":
		return pc - 1
	case "arm64":
		return pc - 4
	case "arm":
		// THUMB instructions are 2 or 4 bytes with low bit set.
		// ARM instructions are always 4 bytes.
		return (pc - 3) & ^uint64(1)
	case "ppc64le":
		return pc - 4
	default:
		panic(fmt.Sprintf("unknown arch %q", arch))
	}
}

func archCallInsn(arch string) (string, string) {
	const callName = " <__sanitizer_cov_trace_pc>"
	switch arch {
	case "amd64":
		// ffffffff8100206a:       callq  ffffffff815cc1d0 <__sanitizer_cov_trace_pc>
		return "\tcallq ", callName
	case "386":
		// c1000102:       call   c10001f0 <__sanitizer_cov_trace_pc>
		return "\tcall ", callName
	case "arm64":
		// ffff0000080d9cc0:       bl      ffff00000820f478 <__sanitizer_cov_trace_pc>
		return "\tbl\t", callName
	case "arm":
		// 8010252c:       bl      801c3280 <__sanitizer_cov_trace_pc>
		return "\tbl\t", callName
	case "ppc64le":
		// c00000000006d904:       bl      c000000000350780 <.__sanitizer_cov_trace_pc>
		return "\tbl ", " <.__sanitizer_cov_trace_pc>"
	default:
		panic(fmt.Sprintf("unknown arch %q", arch))
	}
}

type templateData struct {
	Root     *templateDir
	Contents []template.HTML
	Progs    []template.HTML
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
			.weak-uncovered {
				color: rgb(200, 0, 0);
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
					{{$file.Name}}<span class="cover hover">
						{{$file.Percent}}%
						<span class="cover-right">of {{$file.Total}}</span>
					</span>
				</a>
			{{else}}
					{{$file.Name}}<span class="cover hover">---<span class="cover-right">
						of {{$file.Total}}</span></span>
			{{end}}
		</span></li>
	{{end}}
{{end}}
`))
