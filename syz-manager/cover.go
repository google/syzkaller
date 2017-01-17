// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/cover"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/symbolizer"
)

type symbol struct {
	start uint64
	end   uint64
	name  string
}

type symbolArray []symbol

func (a symbolArray) Len() int           { return len(a) }
func (a symbolArray) Less(i, j int) bool { return a[i].start < a[j].start }
func (a symbolArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type coverage struct {
	line    int
	covered bool
}

type coverageArray []coverage

func (a coverageArray) Len() int           { return len(a) }
func (a coverageArray) Less(i, j int) bool { return a[i].line < a[j].line }
func (a coverageArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type uint64Array []uint64

func (a uint64Array) Len() int           { return len(a) }
func (a uint64Array) Less(i, j int) bool { return a[i] < a[j] }
func (a uint64Array) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var (
	allCoverPCs   []uint64
	allCoverReady = make(chan bool)
)

const (
	callLen = 5 // length of a call instruction, x86-ism
)

func initAllCover(vmlinux string) {
	// Running objdump on vmlinux takes 20-30 seconds, so we do it asynchronously on start.
	go func() {
		pcs, err := coveredPCs(vmlinux)
		if err == nil {
			sort.Sort(uint64Array(pcs))
			allCoverPCs = pcs
		} else {
			Logf(0, "failed to run objdump on %v: %v", vmlinux, err)
		}
		close(allCoverReady)
	}()
}

func generateCoverHtml(w io.Writer, vmlinux string, cov []uint32) error {
	if len(cov) == 0 {
		return fmt.Errorf("No coverage data available")
	}

	base, err := getVmOffset(vmlinux)
	if err != nil {
		return err
	}
	pcs := make([]uint64, len(cov))
	for i, pc := range cov {
		pcs[i] = cover.RestorePC(pc, base) - callLen
	}
	uncovered, err := uncoveredPcsInFuncs(vmlinux, pcs)
	if err != nil {
		return err
	}

	coveredFrames, prefix, err := symbolize(vmlinux, pcs)
	if err != nil {
		return err
	}
	if len(coveredFrames) == 0 {
		return fmt.Errorf("'%s' does not have debug info (set CONFIG_DEBUG_INFO=y)", vmlinux)
	}

	uncoveredFrames, prefix, err := symbolize(vmlinux, uncovered)
	if err != nil {
		return err
	}

	var d templateData
	for f, covered := range fileSet(coveredFrames, uncoveredFrames) {
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
		if len(f) > len(prefix) {
			f = f[len(prefix):]
		}
		d.Files = append(d.Files, &templateFile{
			Name:     f,
			Body:     template.HTML(buf.String()),
			Coverage: coverage,
		})
	}

	sort.Sort(templateFileArray(d.Files))
	if err := coverTemplate.Execute(w, d); err != nil {
		return err
	}
	return nil
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
		sort.Sort(coverageArray(sorted))
		res[f] = sorted
	}
	return res
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

func getVmOffset(vmlinux string) (uint32, error) {
	out, err := exec.Command("readelf", "-SW", vmlinux).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("readelf failed: %v\n%s", err, out)
	}
	s := bufio.NewScanner(bytes.NewReader(out))
	var addr uint32
	for s.Scan() {
		ln := s.Text()
		pieces := strings.Fields(ln)
		for i := 0; i < len(pieces); i++ {
			if pieces[i] != "PROGBITS" {
				continue
			}
			v, err := strconv.ParseUint("0x"+pieces[i+1], 0, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse addr in readelf output: %v", err)
			}
			if v == 0 {
				continue
			}
			v32 := (uint32)(v >> 32)
			if addr == 0 {
				addr = v32
			}
			if addr != v32 {
				return 0, fmt.Errorf("different section offsets in a single binary")
			}
		}
	}
	return addr, nil
}

// uncoveredPcsInFuncs returns uncovered PCs with __sanitizer_cov_trace_pc calls in functions containing pcs.
func uncoveredPcsInFuncs(vmlinux string, pcs []uint64) ([]uint64, error) {
	allSymbols, err := symbolizer.ReadSymbols(vmlinux)
	if err != nil {
		return nil, fmt.Errorf("failed to run nm on vmlinux: %v", err)
	}
	var symbols symbolArray
	for name, ss := range allSymbols {
		for _, s := range ss {
			symbols = append(symbols, symbol{s.Addr, s.Addr + uint64(s.Size), name})
		}
	}
	sort.Sort(symbols)

	<-allCoverReady
	if len(allCoverPCs) == 0 {
		return nil, nil
	}

	handledFuncs := make(map[uint64]bool)
	uncovered := make(map[uint64]bool)
	for _, pc := range pcs {
		idx := sort.Search(len(symbols), func(i int) bool {
			return pc < symbols[i].end
		})
		if idx == len(symbols) {
			continue
		}
		s := symbols[idx]
		if pc < s.start || pc > s.end {
			continue
		}
		if !handledFuncs[s.start] {
			handledFuncs[s.start] = true
			startPC := sort.Search(len(allCoverPCs), func(i int) bool {
				return s.start <= allCoverPCs[i]
			})
			endPC := sort.Search(len(allCoverPCs), func(i int) bool {
				return s.end < allCoverPCs[i]
			})
			for _, pc1 := range allCoverPCs[startPC:endPC] {
				uncovered[pc1] = true
			}
		}
		delete(uncovered, pc)
	}
	uncoveredPCs := make([]uint64, 0, len(uncovered))
	for pc := range uncovered {
		uncoveredPCs = append(uncoveredPCs, pc)
	}
	return uncoveredPCs, nil
}

// coveredPCs returns list of PCs of __sanitizer_cov_trace_pc calls in binary bin.
func coveredPCs(bin string) ([]uint64, error) {
	cmd := exec.Command("objdump", "-d", "--no-show-raw-insn", bin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	var pcs []uint64
	s := bufio.NewScanner(stdout)
	// A line looks as: "ffffffff8100206a:       callq  ffffffff815cc1d0 <__sanitizer_cov_trace_pc>"
	callInsn := []byte("callq ")
	traceFunc := []byte(" <__sanitizer_cov_trace_pc>")
	for s.Scan() {
		ln := s.Bytes()
		if pos := bytes.Index(ln, callInsn); pos == -1 {
			continue
		} else if bytes.Index(ln[pos:], traceFunc) == -1 {
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
		pcs = append(pcs, pc)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return pcs, nil
}

func symbolize(vmlinux string, pcs []uint64) ([]symbolizer.Frame, string, error) {
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()

	frames, err := symb.SymbolizeArray(vmlinux, pcs)
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

type templateData struct {
	Files []*templateFile
}

type templateFile struct {
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

var coverTemplate = template.Must(template.New("").Parse(
	`
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
				{{range $i, $f := .Files}}
				<option value="file{{$i}}">{{$f.Name}} ({{$f.Coverage}})</option>
				{{end}}
				</select>
			</div>
		</div>
		<div id="content">
		{{range $i, $f := .Files}}
		<pre class="file" id="file{{$i}}" {{if $i}}style="display: none"{{end}}>{{$f.Body}}</pre>
		{{end}}
		</div>
	</body>
	<script>
	(function() {
		var files = document.getElementById('files');
		var visible = document.getElementById('file0');
		files.addEventListener('change', onChange, false);
		function onChange() {
			visible.style.display = 'none';
			visible = document.getElementById(files.value);
			visible.style.display = 'block';
			window.scrollTo(0, 0);
		}
	})();
	</script>
</html>
`))
