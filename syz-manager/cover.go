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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type symbol struct {
	start uint64
	end   uint64
	name  string
}

type coverage struct {
	line    int
	covered bool
}

var (
	initCoverOnce     sync.Once
	initCoverError    error
	initCoverSymbols  []symbol
	initCoverPCs      []uint64
	initCoverVMOffset uint32
)

func initCover(kernelObj, arch string) error {
	if kernelObj == "" {
		return fmt.Errorf("kernel_obj is not specified")
	}
	vmlinux := filepath.Join(kernelObj, "vmlinux")
	symbols, err := symbolizer.ReadSymbols(vmlinux)
	if err != nil {
		return fmt.Errorf("failed to run nm on %v: %v", vmlinux, err)
	}
	for name, ss := range symbols {
		for _, s := range ss {
			initCoverSymbols = append(initCoverSymbols, symbol{s.Addr, s.Addr + uint64(s.Size), name})
		}
	}
	sort.Slice(initCoverSymbols, func(i, j int) bool {
		return initCoverSymbols[i].start < initCoverSymbols[j].start
	})
	initCoverPCs, err = coveredPCs(arch, vmlinux)
	if err != nil {
		return fmt.Errorf("failed to run objdump on %v: %v", vmlinux, err)
	}
	sort.Slice(initCoverPCs, func(i, j int) bool {
		return initCoverPCs[i] < initCoverPCs[j]
	})
	initCoverVMOffset, err = getVMOffset(vmlinux)
	return err
}

func generateCoverHTML(w io.Writer, kernelObj, kernelSrc, arch string, cov cover.Cover) error {
	if len(cov) == 0 {
		return fmt.Errorf("no coverage data available")
	}
	initCoverOnce.Do(func() { initCoverError = initCover(kernelObj, arch) })
	if initCoverError != nil {
		return initCoverError
	}

	pcs := make([]uint64, 0, len(cov))
	for pc := range cov {
		fullPC := cover.RestorePC(pc, initCoverVMOffset)
		prevPC := previousInstructionPC(arch, fullPC)
		pcs = append(pcs, prevPC)
	}
	vmlinux := filepath.Join(kernelObj, "vmlinux")
	uncovered, err := uncoveredPcsInFuncs(vmlinux, pcs)
	if err != nil {
		return err
	}

	coveredFrames, _, err := symbolize(vmlinux, pcs)
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
		remain := strings.TrimPrefix(f, prefix)
		if kernelSrc != "" {
			f = filepath.Join(kernelSrc, remain)
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

func getVMOffset(vmlinux string) (uint32, error) {
	out, err := osutil.RunCmd(time.Hour, "", "readelf", "-SW", vmlinux)
	if err != nil {
		return 0, err
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
	handledFuncs := make(map[uint64]bool)
	uncovered := make(map[uint64]bool)
	for _, pc := range pcs {
		idx := sort.Search(len(initCoverSymbols), func(i int) bool {
			return pc < initCoverSymbols[i].end
		})
		if idx == len(initCoverSymbols) {
			continue
		}
		s := initCoverSymbols[idx]
		if pc < s.start || pc > s.end {
			continue
		}
		if !handledFuncs[s.start] {
			handledFuncs[s.start] = true
			startPC := sort.Search(len(initCoverPCs), func(i int) bool {
				return s.start <= initCoverPCs[i]
			})
			endPC := sort.Search(len(initCoverPCs), func(i int) bool {
				return s.end < initCoverPCs[i]
			})
			for _, pc1 := range initCoverPCs[startPC:endPC] {
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
func coveredPCs(arch, bin string) ([]uint64, error) {
	cmd := osutil.Command("objdump", "-d", "--no-show-raw-insn", bin)
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
	traceFunc := []byte(" <__sanitizer_cov_trace_pc>")
	var callInsn []byte
	switch arch {
	case "amd64":
		// ffffffff8100206a:       callq  ffffffff815cc1d0 <__sanitizer_cov_trace_pc>
		callInsn = []byte("\tcallq ")
	case "386":
		// c1000102:       call   c10001f0 <__sanitizer_cov_trace_pc>
		callInsn = []byte("\tcall ")
	case "arm64":
		// ffff0000080d9cc0:       bl      ffff00000820f478 <__sanitizer_cov_trace_pc>
		callInsn = []byte("\tbl\t")
	case "arm":
		// 8010252c:       bl      801c3280 <__sanitizer_cov_trace_pc>
		callInsn = []byte("\tbl\t")
	case "ppc64le":
		// c00000000006d904:       bl      c000000000350780 <.__sanitizer_cov_trace_pc>
		callInsn = []byte("\tbl ")
		traceFunc = []byte(" <.__sanitizer_cov_trace_pc>")
	default:
		panic("unknown arch")
	}
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

func previousInstructionPC(arch string, pc uint64) uint64 {
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
