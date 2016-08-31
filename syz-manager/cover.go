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
	"github.com/google/syzkaller/symbolizer"
)

func generateCoverHtml(w io.Writer, vmlinux string, cov []uint32) error {
	if len(cov) == 0 {
		return fmt.Errorf("No coverage data available")
	}
	frames, prefix, err := symbolize(vmlinux, cov)
	if err != nil {
		return err
	}
	if len(frames) == 0 {
		return fmt.Errorf("'%s' does not have debug info (set CONFIG_DEBUG_INFO=y)", vmlinux)
	}

	var d templateData
	for f, covered := range fileSet(frames) {
		lines, err := parseFile(f)
		if err != nil {
			return err
		}
		coverage := len(covered)
		var buf bytes.Buffer
		for i, ln := range lines {
			if len(covered) > 0 && covered[0] == i+1 {
				buf.Write([]byte("<span id='covered'>"))
				buf.Write(ln)
				buf.Write([]byte("</span>\n"))
				covered = covered[1:]
			} else {
				buf.Write(ln)
				buf.Write([]byte("\n"))
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

func fileSet(frames []symbolizer.Frame) map[string][]int {
	files := make(map[string]map[int]struct{})
	for _, frame := range frames {
		if files[frame.File] == nil {
			files[frame.File] = make(map[int]struct{})
		}
		files[frame.File][frame.Line] = struct{}{}
	}
	res := make(map[string][]int)
	for f, lines := range files {
		sorted := make([]int, 0, len(lines))
		for ln := range lines {
			sorted = append(sorted, ln)
		}
		sort.Ints(sorted)
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

func symbolize(vmlinux string, cov []uint32) ([]symbolizer.Frame, string, error) {
	base, err := getVmOffset(vmlinux)
	if err != nil {
		return nil, "", err
	}
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()

	pcs := make([]uint64, len(cov))
	for i, pc := range cov {
		pcs[i] = cover.RestorePC(pc, base) - 1
	}
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

func (a templateFileArray) Len() int           { return len(a) }
func (a templateFileArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a templateFileArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

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
