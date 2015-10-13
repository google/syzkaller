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
	"sync"

	"github.com/google/syzkaller/cover"
)

type LineInfo struct {
	file string
	line int
}

var (
	mu           sync.Mutex
	pcLines      = make(map[uint32][]LineInfo)
	parsedFiles  = make(map[string][][]byte)
	htmlReplacer = strings.NewReplacer(">", "&gt;", "<", "&lt;", "&", "&amp;", "\t", "        ")
	sourcePrefix string
)

func generateCoverHtml(w io.Writer, vmlinux string, cov []uint32) error {
	mu.Lock()
	defer mu.Unlock()

	info, err := covToLineInfo(vmlinux, cov)
	if err != nil {
		return err
	}
	files := fileSet(info)
	for f := range files {
		if _, ok := parsedFiles[f]; ok {
			continue
		}
		if err := parseFile(f); err != nil {
			return err
		}
	}

	var d templateData
	for f, covered := range files {
		lines := parsedFiles[f]
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
		stripped := f
		if len(stripped) > len(sourcePrefix) {
			stripped = stripped[len(sourcePrefix):]
		}
		d.Files = append(d.Files, &templateFile{
			Name:     stripped,
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

func covToLineInfo(vmlinux string, cov []uint32) ([]LineInfo, error) {
	var missing []uint32
	for _, pc := range cov {
		if _, ok := pcLines[pc]; !ok {
			missing = append(missing, pc)
		}
	}
	if len(missing) > 0 {
		if err := symbolize(vmlinux, missing); err != nil {
			return nil, err
		}
	}
	var info []LineInfo
	for _, pc := range cov {
		info = append(info, pcLines[pc]...)
	}
	return info, nil
}

func fileSet(info []LineInfo) map[string][]int {
	files := make(map[string]map[int]struct{})
	for _, li := range info {
		if files[li.file] == nil {
			files[li.file] = make(map[int]struct{})
		}
		files[li.file][li.line] = struct{}{}
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

func parseFile(fn string) error {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}
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
	parsedFiles[fn] = lines
	if sourcePrefix == "" {
		sourcePrefix = fn
	} else {
		i := 0
		for ; i < len(sourcePrefix) && i < len(fn); i++ {
			if sourcePrefix[i] != fn[i] {
				break
			}
		}
		sourcePrefix = sourcePrefix[:i]
	}
	return nil
}

func symbolize(vmlinux string, cov []uint32) error {
	cmd := exec.Command("addr2line", "-a", "-i", "-e", vmlinux)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Wait()
	go func() {
		for _, pc := range cov {
			fmt.Fprintf(stdin, "0x%x\n", cover.RestorePC(pc)-1)
		}
		stdin.Close()
	}()
	s := bufio.NewScanner(stdout)
	var pc uint32
	for s.Scan() {
		ln := s.Text()
		if len(ln) > 3 && ln[0] == '0' && ln[1] == 'x' {
			v, err := strconv.ParseUint(ln, 0, 64)
			if err != nil {
				return fmt.Errorf("failed to parse pc in addr2line output: %v", err)
			}
			pc = uint32(v) + 1
			continue
		}
		colon := strings.IndexByte(ln, ':')
		if colon == -1 {
			continue
		}
		file := ln[:colon]
		line, err := strconv.Atoi(ln[colon+1:])
		if err != nil || pc == 0 || file == "" || file == "??" || line <= 0 {
			continue
		}
		pcLines[pc] = append(pcLines[pc], LineInfo{file, line})
	}
	if err := s.Err(); err != nil {
		return err
	}
	return nil
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
