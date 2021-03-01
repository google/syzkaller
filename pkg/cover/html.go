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

	"github.com/google/syzkaller/pkg/cover/backend"
)

func (rg *ReportGenerator) DoHTML(w io.Writer, progs []Prog) error {
	files, err := rg.prepareFileMap(progs)
	if err != nil {
		return err
	}
	d := &templateData{
		Root: new(templateDir),
	}
	haveProgs := len(progs) > 1 || progs[0].Data != ""
	fileOpenErr := fmt.Errorf("failed to open/locate any source file")
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
				Total:   file.totalPCs,
				Covered: file.coveredPCs,
			},
			HasFunctions: len(file.functions) != 0,
		}
		pos.Files = append(pos.Files, f)
		if file.coveredPCs == 0 {
			continue
		}
		addFunctionCoverage(file, d)
		contents := ""
		lines, err := parseFile(file.filename)
		if err == nil {
			contents = fileContents(file, lines, haveProgs)
			fileOpenErr = nil
		} else {
			// We ignore individual errors of opening/locating source files
			// because there is a number of reasons when/why it can happen.
			// We fail only if we can't open/locate any single source file.
			// syz-ci can mess state of source files (https://github.com/google/syzkaller/issues/1770),
			// or bazel lies about location of auto-generated files,
			// or a used can update source files with git pull/checkout.
			contents = html.EscapeString(err.Error())
			if fileOpenErr != nil {
				fileOpenErr = err
			}
		}
		d.Contents = append(d.Contents, template.HTML(contents))
		f.Index = len(d.Contents) - 1
	}
	if fileOpenErr != nil {
		return fileOpenErr
	}
	for _, prog := range progs {
		d.Progs = append(d.Progs, template.HTML(html.EscapeString(prog.Data)))
	}

	processDir(d.Root)
	return coverTemplate.Execute(w, d)
}

type fileStats struct {
	Name                  string
	CoveredLines          int
	TotalLines            int
	CoveredPCs            int
	TotalPCs              int
	TotalFunctions        int
	CoveredPCsInFunctions int
	TotalPCsInFunctions   int
}

var csvFilesHeader = []string{
	"Filename",
	"CoveredLines",
	"TotalLines",
	"CoveredPCs",
	"TotalPCs",
	"TotalFunctions",
	"CoveredPCsInFunctions",
	"TotalPCsInFunctions",
}

func (rg *ReportGenerator) convertToStats(progs []Prog) ([]fileStats, error) {
	files, err := rg.prepareFileMap(progs)
	if err != nil {
		return nil, err
	}

	var data []fileStats
	for fname, file := range files {
		lines, err := parseFile(file.filename)
		if err != nil {
			fmt.Printf("failed to open/locate %s\n", file.filename)
			continue
		}
		totalFuncs := len(file.functions)
		var coveredInFunc int
		var pcsInFunc int
		for _, function := range file.functions {
			coveredInFunc += function.covered
			pcsInFunc += function.pcs
		}
		totalLines := len(lines)
		var coveredLines int
		for _, line := range file.lines {
			if len(line.progCount) != 0 {
				coveredLines++
			}
		}
		data = append(data, fileStats{
			Name:                  fname,
			CoveredLines:          coveredLines,
			TotalLines:            totalLines,
			CoveredPCs:            file.coveredPCs,
			TotalPCs:              file.totalPCs,
			TotalFunctions:        totalFuncs,
			CoveredPCsInFunctions: coveredInFunc,
			TotalPCsInFunctions:   pcsInFunc,
		})
	}

	return data, nil
}

func (rg *ReportGenerator) DoCSVFiles(w io.Writer, progs []Prog) error {
	data, err := rg.convertToStats(progs)
	if err != nil {
		return err
	}

	sort.SliceStable(data, func(i, j int) bool {
		return data[i].Name < data[j].Name
	})

	writer := csv.NewWriter(w)
	defer writer.Flush()
	if err := writer.Write(csvFilesHeader); err != nil {
		return err
	}

	var d [][]string
	for _, dt := range data {
		d = append(d, []string{
			dt.Name,
			strconv.Itoa(dt.CoveredLines),
			strconv.Itoa(dt.TotalLines),
			strconv.Itoa(dt.CoveredPCs),
			strconv.Itoa(dt.TotalPCs),
			strconv.Itoa(dt.TotalFunctions),
			strconv.Itoa(dt.CoveredPCsInFunctions),
			strconv.Itoa(dt.TotalPCsInFunctions),
		})
	}
	return writer.WriteAll(d)
}

func groupCoverByFilePrefixes(datas []fileStats, subsystems []Subsystem) map[string]map[string]string {
	d := make(map[string]map[string]string)

	for _, subsystem := range subsystems {
		var coveredLines int
		var totalLines int
		var coveredPCsInFile int
		var totalPCsInFile int
		var totalFuncs int
		var coveredPCsInFuncs int
		var pcsInFuncs int
		var percentLines float64
		var percentPCsInFile float64
		var percentPCsInFunc float64

		for _, path := range subsystem.Paths {
			for _, data := range datas {
				if !strings.HasPrefix(data.Name, path) {
					continue
				}
				coveredLines += data.CoveredLines
				totalLines += data.TotalLines
				coveredPCsInFile += data.CoveredPCs
				totalPCsInFile += data.TotalPCs
				totalFuncs += data.TotalFunctions
				coveredPCsInFuncs += data.CoveredPCsInFunctions
				pcsInFuncs += data.TotalPCsInFunctions
			}
		}

		if totalLines != 0 {
			percentLines = 100.0 * float64(coveredLines) / float64(totalLines)
		}
		if totalPCsInFile != 0 {
			percentPCsInFile = 100.0 * float64(coveredPCsInFile) / float64(totalPCsInFile)
		}
		if pcsInFuncs != 0 {
			percentPCsInFunc = 100.0 * float64(coveredPCsInFuncs) / float64(pcsInFuncs)
		}

		d[subsystem.Name] = map[string]string{
			"subsystem":  subsystem.Name,
			"lines":      fmt.Sprintf("%v / %v / %.2f%%", coveredLines, totalLines, percentLines),
			"PCsInFiles": fmt.Sprintf("%v / %v / %.2f%%", coveredPCsInFile, totalPCsInFile, percentPCsInFile),
			"totalFuncs": strconv.Itoa(totalFuncs),
			"PCsInFuncs": fmt.Sprintf("%v / %v / %.2f%%", coveredPCsInFuncs, pcsInFuncs, percentPCsInFunc),
		}
	}

	return d
}

func (rg *ReportGenerator) DoHTMLTable(w io.Writer, progs []Prog) error {
	data, err := rg.convertToStats(progs)
	if err != nil {
		return err
	}

	d := groupCoverByFilePrefixes(data, rg.subsystem)

	return coverTableTemplate.Execute(w, d)
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

func fileContents(file *file, lines [][]byte, haveProgs bool) string {
	var buf bytes.Buffer
	lineCover := perLineCoverage(file.covered, file.uncovered)
	htmlReplacer := strings.NewReplacer(">", "&gt;", "<", "&lt;", "&", "&amp;", "\t", "        ")
	for i, ln := range lines {
		if haveProgs {
			prog, count := "", "     "
			if line := file.lines[i+1]; len(line.progCount) != 0 {
				prog = fmt.Sprintf("onclick='onProgClick(%v)'", line.progIndex)
				count = fmt.Sprintf("% 5v", len(line.progCount))
			}
			buf.WriteString(fmt.Sprintf("<span class='count' %v>%v</span> ", prog, count))
		}

		start := 0
		cover := append(lineCover[i+1], lineCoverChunk{End: backend.LineEnd})
		for _, cov := range cover {
			end := cov.End - 1
			if end > len(ln) {
				end = len(ln)
			}
			if end == start {
				continue
			}
			chunk := htmlReplacer.Replace(string(ln[start:end]))
			start = end
			class := ""
			if cov.Covered && cov.Uncovered {
				class = "both"
			} else if cov.Covered {
				class = "covered"
			} else if cov.Uncovered {
				class = "uncovered"
			} else {
				buf.WriteString(chunk)
				continue
			}
			buf.WriteString(fmt.Sprintf("<span class='%v'>%v</span>", class, chunk))
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

type lineCoverChunk struct {
	End       int
	Covered   bool
	Uncovered bool
}

func perLineCoverage(covered, uncovered []backend.Range) map[int][]lineCoverChunk {
	lines := make(map[int][]lineCoverChunk)
	for _, r := range covered {
		mergeRange(lines, r, true)
	}
	for _, r := range uncovered {
		mergeRange(lines, r, false)
	}
	return lines
}

func mergeRange(lines map[int][]lineCoverChunk, r backend.Range, covered bool) {
	// Don't panic on broken debug info, it is frequently broken.
	if r.EndLine < r.StartLine {
		r.EndLine = r.StartLine
	}
	if r.EndLine == r.StartLine && r.EndCol <= r.StartCol {
		r.EndCol = backend.LineEnd
	}
	for line := r.StartLine; line <= r.EndLine; line++ {
		start := 0
		if line == r.StartLine {
			start = r.StartCol
		}
		end := backend.LineEnd
		if line == r.EndLine {
			end = r.EndCol
		}
		ln := lines[line]
		if ln == nil {
			ln = append(ln, lineCoverChunk{End: backend.LineEnd})
		}
		lines[line] = mergeLine(ln, start, end, covered)
	}
}

func mergeLine(chunks []lineCoverChunk, start, end int, covered bool) []lineCoverChunk {
	var res []lineCoverChunk
	chunkStart := 0
	for _, chunk := range chunks {
		if chunkStart >= end || chunk.End <= start {
			res = append(res, chunk)
		} else if covered && chunk.Covered || !covered && chunk.Uncovered {
			res = append(res, chunk)
		} else if chunkStart >= start && chunk.End <= end {
			if covered {
				chunk.Covered = true
			} else {
				chunk.Uncovered = true
			}
			res = append(res, chunk)
		} else {
			if chunkStart < start {
				res = append(res, lineCoverChunk{start, chunk.Covered, chunk.Uncovered})
			}
			mid := end
			if mid > chunk.End {
				mid = chunk.End
			}
			res = append(res, lineCoverChunk{mid, chunk.Covered || covered, chunk.Uncovered || !covered})
			if chunk.End > end {
				res = append(res, lineCoverChunk{chunk.End, chunk.Covered, chunk.Uncovered})
			}
		}
		chunkStart = chunk.End
	}
	return res
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
	var lines [][]byte
	for {
		idx := bytes.IndexByte(data, '\n')
		if idx == -1 {
			break
		}
		lines = append(lines, data[:idx])
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
	Index        int
	HasFunctions bool
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
					<a href="#{{$file.Path}}" id="path/{{$file.Path}}"
						onclick="{{if .HasFunctions}}onPercentClick{{else}}onFileClick{{end}}({{$file.Index}})">
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

var coverTableTemplate = template.Must(template.New("coverTable").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>
			body {
				background: white;
			}
			#content {
				color: rgb(70, 70, 70);
				margin-top: 50px;
			}
			th, td {
				text-align: left;
				border: 1px solid black;
			}
			th {
				background: gray;
			}
			tr:nth-child(2n+1) {
				background: #CCC
			}
			table {
				border-collapse: collapse;
				border: 1px solid black;
				margin-bottom: 20px;
			}
		</style>
	</head>
	<body>
		<div>
			<table>
				<thead>
					<tr>
						<th>Subsystem</th>
						<th>Covered / Total Lines / %</th>
						<th>Covered / Total PCs in File / %</th>
						<th>Covered / Total PCs in Function / %</th>
						<th>Covered Functions</th>
					</tr>
				</thead>
				<tbody id="content">
					{{range $i, $p := .}}
					<tr>
						<td>{{$p.subsystem}}</td>
						<td>{{$p.lines}}</td>
						<td>{{$p.PCsInFiles}}</td>
						<td>{{$p.PCsInFuncs}}</td>
						<td>{{$p.totalFuncs}}</td>
					</tr>
					{{end}}
				</tbody>
			</table>
		</div>
	</body>
</html>

`))
