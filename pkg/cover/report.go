// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type ReportGenerator struct {
	vmlinux  string
	srcDir   string
	arch     string
	symbols  []symbol
	coverPCs []uint64
}

type symbol struct {
	start uint64
	end   uint64
	name  string
}

type coverage struct {
	line    int
	covered bool
}

func MakeReportGenerator(vmlinux, srcDir, arch string) (*ReportGenerator, error) {
	rg := &ReportGenerator{
		vmlinux: vmlinux,
		srcDir:  srcDir,
		arch:    arch,
	}
	if err := rg.readSymbols(); err != nil {
		return nil, err
	}
	if err := rg.readPCs(); err != nil {
		return nil, err
	}
	return rg, nil
}

func (rg *ReportGenerator) Do(w io.Writer, pcs []uint64) error {
	if len(pcs) == 0 {
		return fmt.Errorf("no coverage data available")
	}
	for i, pc := range pcs {
		pcs[i] = PreviousInstructionPC(rg.arch, pc)
	}
	covered, _, err := rg.symbolize(pcs)
	if err != nil {
		return err
	}
	if len(covered) == 0 {
		return fmt.Errorf("'%s' does not have debug info (set CONFIG_DEBUG_INFO=y)", rg.vmlinux)
	}
	uncoveredPCs := rg.uncoveredPcsInFuncs(pcs)
	uncovered, prefix, err := rg.symbolize(uncoveredPCs)
	if err != nil {
		return err
	}
	return rg.generate(w, prefix, covered, uncovered)
}

func (rg *ReportGenerator) generate(w io.Writer, prefix string, covered, uncovered []symbolizer.Frame) error {
	var d templateData
	for f, covered := range fileSet(covered, uncovered) {
		remain := filepath.Clean(strings.TrimPrefix(f, prefix))
		if rg.srcDir != "" && !strings.HasPrefix(remain, rg.srcDir) {
			f = filepath.Join(rg.srcDir, remain)
		}
		lines, err := parseFile(f)
		if err != nil {
			return err
		}
		coverage := 0
		var buf bytes.Buffer
		for i, ln := range lines {
			if len(covered) > 0 && covered[0].line == i+1 {
				if covered[0].covered {
					buf.Write([]byte("<span id='covered'>"))
					buf.Write(ln)
					buf.Write([]byte("</span> /*covered*/\n"))
					coverage++
				} else {
					buf.Write([]byte("<span id='uncovered'>"))
					buf.Write(ln)
					buf.Write([]byte("</span>\n"))
				}
				covered = covered[1:]
			} else {
				buf.Write(ln)
				buf.Write([]byte{'\n'})
			}
		}
		f = filepath.Clean(remain)
		d.Files = append(d.Files, &templateFile{
			ID:       hash.String([]byte(f)),
			Name:     f,
			Body:     template.HTML(buf.String()),
			Coverage: coverage,
		})
	}
	sort.Sort(templateFileArray(d.Files))
	return coverTemplate.Execute(w, d)
}

func (rg *ReportGenerator) readSymbols() error {
	symbols, err := symbolizer.ReadSymbols(rg.vmlinux)
	if err != nil {
		return fmt.Errorf("failed to run nm on %v: %v", rg.vmlinux, err)
	}
	for name, ss := range symbols {
		for _, s := range ss {
			rg.symbols = append(rg.symbols, symbol{
				start: s.Addr,
				end:   s.Addr + uint64(s.Size),
				name:  name,
			})
		}
	}
	sort.Slice(rg.symbols, func(i, j int) bool {
		return rg.symbols[i].start < rg.symbols[j].start
	})
	return nil
}

// readPCs collects list of PCs of __sanitizer_cov_trace_pc calls in the kernel.
func (rg *ReportGenerator) readPCs() error {
	cmd := osutil.Command("objdump", "-d", "--no-show-raw-insn", rg.vmlinux)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to run objdump on %v: %v", rg.vmlinux, err)
	}
	defer cmd.Wait()
	s := bufio.NewScanner(stdout)
	callInsnS, traceFuncS := archCallInsn(rg.arch)
	callInsn, traceFunc := []byte(callInsnS), []byte(traceFuncS)
	for s.Scan() {
		ln := s.Bytes()
		if pos := bytes.Index(ln, callInsn); pos == -1 {
			continue
		} else if !bytes.Contains(ln[pos:], traceFunc) {
			continue
		}
		colon := bytes.IndexByte(ln, ':')
		if colon == -1 {
			continue
		}
		pc, err := strconv.ParseUint(string(ln[:colon]), 16, 64)
		if err != nil {
			continue
		}
		rg.coverPCs = append(rg.coverPCs, pc)
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("failed to run objdump output: %v", err)
	}
	sort.Slice(rg.coverPCs, func(i, j int) bool {
		return rg.coverPCs[i] < rg.coverPCs[j]
	})
	return nil
}

// uncoveredPcsInFuncs returns uncovered PCs with __sanitizer_cov_trace_pc calls in functions containing pcs.
func (rg *ReportGenerator) uncoveredPcsInFuncs(pcs []uint64) []uint64 {
	handledFuncs := make(map[uint64]bool)
	uncovered := make(map[uint64]bool)
	for _, pc := range pcs {
		idx := sort.Search(len(rg.symbols), func(i int) bool {
			return pc < rg.symbols[i].end
		})
		if idx == len(rg.symbols) {
			continue
		}
		s := rg.symbols[idx]
		if pc < s.start || pc > s.end {
			continue
		}
		if !handledFuncs[s.start] {
			handledFuncs[s.start] = true
			startPC := sort.Search(len(rg.coverPCs), func(i int) bool {
				return s.start <= rg.coverPCs[i]
			})
			endPC := sort.Search(len(rg.coverPCs), func(i int) bool {
				return s.end < rg.coverPCs[i]
			})
			for _, pc1 := range rg.coverPCs[startPC:endPC] {
				uncovered[pc1] = true
			}
		}
		delete(uncovered, pc)
	}
	uncoveredPCs := make([]uint64, 0, len(uncovered))
	for pc := range uncovered {
		uncoveredPCs = append(uncoveredPCs, pc)
	}
	return uncoveredPCs
}

func (rg *ReportGenerator) symbolize(pcs []uint64) ([]symbolizer.Frame, string, error) {
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()

	frames, err := symb.SymbolizeArray(rg.vmlinux, pcs)
	if err != nil {
		return nil, "", err
	}

	prefix := ""
	for i := range frames {
		frame := &frames[i]
		frame.PC--
		if prefix == "" {
			prefix = frame.File
		} else {
			i := 0
			for ; i < len(prefix) && i < len(frame.File); i++ {
				if prefix[i] != frame.File[i] {
					break
				}
			}
			prefix = prefix[:i]
		}

	}
	return frames, prefix, nil
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

func fileSet(covered, uncovered []symbolizer.Frame) map[string][]coverage {
	files := make(map[string]map[int]bool)
	funcs := make(map[string]bool)
	for _, frame := range covered {
		if files[frame.File] == nil {
			files[frame.File] = make(map[int]bool)
		}
		files[frame.File][frame.Line] = true
		funcs[frame.Func] = true
	}
	for _, frame := range uncovered {
		if !funcs[frame.Func] {
			continue
		}
		if files[frame.File] == nil {
			files[frame.File] = make(map[int]bool)
		}
		if !files[frame.File][frame.Line] {
			files[frame.File][frame.Line] = false
		}
	}
	res := make(map[string][]coverage)
	for f, lines := range files {
		sorted := make([]coverage, 0, len(lines))
		for ln, covered := range lines {
			sorted = append(sorted, coverage{ln, covered})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].line < sorted[j].line
		})
		res[f] = sorted
	}
	return res
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
		panic("unknown arch")
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
		panic("unknown arch")
	}
}

type templateData struct {
	Files []*templateFile
}

type templateFile struct {
	ID       string
	Name     string
	Body     template.HTML
	Coverage int
}

type templateFileArray []*templateFile

func (a templateFileArray) Len() int { return len(a) }
func (a templateFileArray) Less(i, j int) bool {
	n1 := a[i].Name
	n2 := a[j].Name
	// Move include files to the bottom.
	if len(n1) != 0 && len(n2) != 0 {
		if n1[0] != '.' && n2[0] == '.' {
			return true
		}
		if n1[0] == '.' && n2[0] != '.' {
			return false
		}
	}
	return n1 < n2
}
func (a templateFileArray) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

var coverTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>
			body {
				background: white;
			}
			#topbar {
				background: black;
				position: fixed;
				top: 0; left: 0; right: 0;
				height: 42px;
				border-bottom: 1px solid rgb(70, 70, 70);
			}
			#nav {
				float: left;
				margin-left: 10px;
				margin-top: 10px;
			}
			#content {
				font-family: 'Courier New', Courier, monospace;
				color: rgb(70, 70, 70);
				margin-top: 50px;
			}
			#covered {
				color: rgb(0, 0, 0);
				font-weight: bold;
			}
			#uncovered {
				color: rgb(255, 0, 0);
				font-weight: bold;
			}
		</style>
	</head>
	<body>
		<div id="topbar">
			<div id="nav">
				<select id="files">
				{{range $f := .Files}}
				<option value="{{$f.ID}}">{{$f.Name}} ({{$f.Coverage}})</option>
				{{end}}
				</select>
			</div>
		</div>
		<div id="content">
		{{range $i, $f := .Files}}
		<pre class="file" id="{{$f.ID}}" {{if $i}}style="display: none;"{{end}}>{{$f.Body}}</pre>{{end}}
		</div>
	</body>
	<script>
	(function() {
		var files = document.getElementById('files');
		var visible = document.getElementById(files.value);
		if (window.location.hash) {
			var hash = window.location.hash.substring(1);
			for (var i = 0; i < files.options.length; i++) {
				if (files.options[i].value === hash) {
					files.selectedIndex = i;
					visible.style.display = 'none';
					visible = document.getElementById(files.value);
					visible.style.display = 'block';
					break;
				}
			}
		}
		files.addEventListener('change', onChange, false);
		function onChange() {
			visible.style.display = 'none';
			visible = document.getElementById(files.value);
			visible.style.display = 'block';
			window.scrollTo(0, 0);
			window.location.hash = files.value;
		}
	})();
	</script>
</html>
`))
