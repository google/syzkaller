// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bytes"
	"encoding/csv"
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
)

func (rg *ReportGenerator) DoHTML(w io.Writer, progs []Prog) error {
	files, err := rg.prepareFileMap(progs)
	if err != nil {
		return err
	}
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

var csvHeader = []string{
	"Filename",
	"Function",
	"Covered PCs",
	"Total PCs",
}

func (rg *ReportGenerator) DoCSV(w io.Writer, progs []Prog) error {
	files, err := rg.prepareFileMap(progs)
	if err != nil {
		return err
	}
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

func percent(covered, total int) int {
	f := math.Ceil(float64(covered) / float64(total) * 100)
	if f == 100 && covered < total {
		f = 99
	}
	return int(f)
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
