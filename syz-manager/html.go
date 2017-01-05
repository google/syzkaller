// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/cover"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

const dateFormat = "Jan 02 2006 15:04:05 MST"

func (mgr *Manager) initHttp() {
	http.HandleFunc("/", mgr.httpSummary)
	http.HandleFunc("/corpus", mgr.httpCorpus)
	http.HandleFunc("/crash", mgr.httpCrash)
	http.HandleFunc("/cover", mgr.httpCover)
	http.HandleFunc("/prio", mgr.httpPrio)
	http.HandleFunc("/file", mgr.httpFile)
	http.HandleFunc("/report", mgr.httpReport)

	ln, err := net.Listen("tcp4", mgr.cfg.Http)
	if err != nil {
		Fatalf("failed to listen on %v: %v", mgr.cfg.Http, err)
	}
	Logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		Fatalf("failed to serve http: %v", err)
	}()
}

func (mgr *Manager) httpSummary(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := &UISummaryData{
		Name: mgr.cfg.Name,
	}
	data.Stats = append(data.Stats, UIStat{Name: "uptime", Value: fmt.Sprint(time.Since(mgr.startTime) / 1e9 * 1e9)})
	data.Stats = append(data.Stats, UIStat{Name: "corpus", Value: fmt.Sprint(len(mgr.corpus))})
	data.Stats = append(data.Stats, UIStat{Name: "triage queue", Value: fmt.Sprint(len(mgr.candidates))})

	var err error
	if data.Crashes, err = mgr.collectCrashes(); err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}

	type CallCov struct {
		count int
		cov   cover.Cover
	}
	calls := make(map[string]*CallCov)
	for _, inp := range mgr.corpus {
		if calls[inp.Call] == nil {
			calls[inp.Call] = new(CallCov)
		}
		cc := calls[inp.Call]
		cc.count++
		cc.cov = cover.Union(cc.cov, cover.Cover(inp.Cover))
	}

	secs := uint64(1)
	if !mgr.firstConnect.IsZero() {
		secs = uint64(time.Since(mgr.firstConnect))/1e9 + 1
	}

	var cov cover.Cover
	totalUnique := mgr.uniqueCover(true)
	for c, cc := range calls {
		cov = cover.Union(cov, cc.cov)
		unique := cover.Intersection(cc.cov, totalUnique)
		data.Calls = append(data.Calls, UICallType{
			Name:        c,
			Inputs:      cc.count,
			Cover:       len(cc.cov),
			UniqueCover: len(unique),
		})
	}
	sort.Sort(UICallTypeArray(data.Calls))
	data.Stats = append(data.Stats, UIStat{Name: "cover", Value: fmt.Sprint(len(cov)), Link: "/cover"})

	var intStats []UIStat
	for k, v := range mgr.stats {
		val := fmt.Sprintf("%v", v)
		if x := v / secs; x >= 10 {
			val += fmt.Sprintf(" (%v/sec)", x)
		} else if x := v * 60 / secs; x >= 10 {
			val += fmt.Sprintf(" (%v/min)", x)
		} else {
			x := v * 60 * 60 / secs
			val += fmt.Sprintf(" (%v/hour)", x)
		}
		intStats = append(intStats, UIStat{Name: k, Value: val})
	}
	sort.Sort(UIStatArray(intStats))
	data.Stats = append(data.Stats, intStats...)
	data.Log = CachedLogOutput()

	if err := summaryTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCrash(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	crashID := r.FormValue("id")
	crashes, err := mgr.collectCrashes()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}
	var crash *UICrashType
	for _, c := range crashes {
		if c.ID == crashID {
			crash = &c
			break
		}
	}
	if crash == nil {
		http.Error(w, fmt.Sprintf("can't find crash %v", crashID), http.StatusInternalServerError)
		return
	}
	if err := crashTemplate.Execute(w, crash); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCorpus(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var data []UIInput
	call := r.FormValue("call")
	totalUnique := mgr.uniqueCover(false)
	for i, inp := range mgr.corpus {
		if call != inp.Call {
			continue
		}
		p, err := prog.Deserialize(inp.Prog)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		unique := cover.Intersection(inp.Cover, totalUnique)
		data = append(data, UIInput{
			Short:       p.String(),
			Full:        string(inp.Prog),
			Cover:       len(inp.Cover),
			UniqueCover: len(unique),
			N:           i,
		})
	}
	sort.Sort(UIInputArray(data))

	if err := corpusTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var cov cover.Cover
	call := r.FormValue("call")
	unique := r.FormValue("unique") != "" && call != ""
	perCall := false
	if n, err := strconv.Atoi(call); err == nil && n < len(mgr.corpus) {
		cov = mgr.corpus[n].Cover
	} else {
		perCall = true
		for _, inp := range mgr.corpus {
			if call == "" || call == inp.Call {
				cov = cover.Union(cov, cover.Cover(inp.Cover))
			}
		}
	}
	if unique {
		cov = cover.Intersection(cov, mgr.uniqueCover(perCall))
	}

	if err := generateCoverHtml(w, mgr.cfg.Vmlinux, cov); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
	runtime.GC()
}

func (mgr *Manager) uniqueCover(perCall bool) cover.Cover {
	totalCover := make(map[uint32]int)
	callCover := make(map[string]map[uint32]bool)
	for _, inp := range mgr.corpus {
		if perCall && callCover[inp.Call] == nil {
			callCover[inp.Call] = make(map[uint32]bool)
		}
		for _, pc := range inp.Cover {
			if perCall {
				if callCover[inp.Call][pc] {
					continue
				}
				callCover[inp.Call][pc] = true
			}
			totalCover[pc]++
		}
	}
	var cov cover.Cover
	for pc, count := range totalCover {
		if count == 1 {
			cov = append(cov, pc)
		}
	}
	cover.Canonicalize(cov)
	return cov
}

func (mgr *Manager) httpPrio(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.minimizeCorpus()
	call := r.FormValue("call")
	idx := -1
	for i, c := range sys.Calls {
		if c.CallName == call {
			idx = i
			break
		}
	}
	if idx == -1 {
		http.Error(w, fmt.Sprintf("unknown call: %v", call), http.StatusInternalServerError)
		return
	}

	data := &UIPrioData{Call: call}
	for i, p := range mgr.prios[idx] {
		data.Prios = append(data.Prios, UIPrio{sys.Calls[i].Name, p})
	}
	sort.Sort(UIPrioArray(data.Prios))

	if err := prioTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpFile(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	file := filepath.Clean(r.FormValue("name"))
	if !strings.HasPrefix(file, "crashes/") && !strings.HasPrefix(file, "corpus/") {
		http.Error(w, "oh, oh, oh!", http.StatusInternalServerError)
		return
	}
	file = filepath.Join(mgr.cfg.Workdir, file)
	f, err := os.Open(file)
	if err != nil {
		http.Error(w, "failed to open the file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, f)
}

func (mgr *Manager) httpReport(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	crashID := r.FormValue("id")
	desc, err := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "description"))
	if err != nil {
		http.Error(w, "failed to read description file", http.StatusInternalServerError)
		return
	}
	tag, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.tag"))
	prog, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.prog"))
	cprog, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.cprog"))
	report, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.report"))

	fmt.Fprintf(w, "Syzkaller hit '%s' bug on commit %s.\n\n", trimNewLines(desc), trimNewLines(tag))
	if len(report) != 0 {
		fmt.Fprintf(w, "%s\n\n", report)
	}
	if len(prog) == 0 && len(cprog) == 0 {
		fmt.Fprintf(w, "The bug is not reproducible.\n")
	} else {
		fmt.Fprintf(w, "Syzkaller reproducer:\n%s\n\n", prog)
		if len(cprog) != 0 {
			fmt.Fprintf(w, "C reproducer:\n%s\n\n", cprog)
		}
	}
}

func (mgr *Manager) collectCrashes() ([]UICrashType, error) {
	dirs, err := ioutil.ReadDir(mgr.crashdir)
	if err != nil {
		return nil, err
	}
	var crashTypes []UICrashType
	for _, dir := range dirs {
		if !dir.IsDir() || len(dir.Name()) != 40 {
			continue
		}
		desc, err := ioutil.ReadFile(filepath.Join(mgr.crashdir, dir.Name(), "description"))
		if err != nil || len(desc) == 0 {
			continue
		}
		desc = trimNewLines(desc)
		files, err := ioutil.ReadDir(filepath.Join(mgr.crashdir, dir.Name()))
		if err != nil {
			return nil, err
		}
		var maxTime time.Time
		var crashes []UICrash
		for _, f := range files {
			if !strings.HasPrefix(f.Name(), "log") {
				continue
			}
			index, err := strconv.ParseUint(f.Name()[3:], 10, 64)
			if err != nil {
				continue
			}
			tag, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, dir.Name(), "tag"+strconv.Itoa(int(index))))
			crash := UICrash{
				Index: int(index),
				Time:  f.ModTime().Format(dateFormat),
				Log:   filepath.Join("crashes", dir.Name(), f.Name()),
				Tag:   string(tag),
			}
			reportFile := filepath.Join("crashes", dir.Name(), "report"+strconv.Itoa(int(index)))
			if _, err := os.Stat(filepath.Join(mgr.cfg.Workdir, reportFile)); err == nil {
				crash.Report = reportFile
			}
			crashes = append(crashes, crash)
			if maxTime.Before(f.ModTime()) {
				maxTime = f.ModTime()
			}
		}
		sort.Sort(UICrashArray(crashes))

		triaged := ""
		if _, err := os.Stat(filepath.Join(mgr.crashdir, dir.Name(), "repro.prog")); err == nil {
			if _, err := os.Stat(filepath.Join(mgr.crashdir, dir.Name(), "repro.cprog")); err == nil {
				triaged = "has C repro"
			} else {
				triaged = "has repro"
			}
		} else if _, err := os.Stat(filepath.Join(mgr.crashdir, dir.Name(), "repro.report")); err == nil && !mgr.needRepro(string(desc)) {
			triaged = "non-reproducible"
		}
		crashTypes = append(crashTypes, UICrashType{
			Description: string(desc),
			LastTime:    maxTime.Format(dateFormat),
			ID:          dir.Name(),
			Count:       len(crashes),
			Triaged:     triaged,
			Crashes:     crashes,
		})
	}
	sort.Sort(UICrashTypeArray(crashTypes))
	return crashTypes, nil
}

func trimNewLines(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data
}

type UISummaryData struct {
	Name    string
	Stats   []UIStat
	Calls   []UICallType
	Crashes []UICrashType
	Log     string
}

type UICrashType struct {
	Description string
	LastTime    string
	ID          string
	Count       int
	Triaged     string
	Crashes     []UICrash
}

type UICrash struct {
	Index  int
	Time   string
	Log    string
	Report string
	Tag    string
}

type UIStat struct {
	Name  string
	Value string
	Link  string
}

type UICallType struct {
	Name        string
	Inputs      int
	Cover       int
	UniqueCover int
}

type UIInput struct {
	Short       string
	Full        string
	Calls       int
	Cover       int
	UniqueCover int
	N           int
}

type UICallTypeArray []UICallType

func (a UICallTypeArray) Len() int           { return len(a) }
func (a UICallTypeArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a UICallTypeArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type UIInputArray []UIInput

func (a UIInputArray) Len() int           { return len(a) }
func (a UIInputArray) Less(i, j int) bool { return a[i].Cover > a[j].Cover }
func (a UIInputArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type UIStatArray []UIStat

func (a UIStatArray) Len() int           { return len(a) }
func (a UIStatArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a UIStatArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type UICrashTypeArray []UICrashType

func (a UICrashTypeArray) Len() int           { return len(a) }
func (a UICrashTypeArray) Less(i, j int) bool { return a[i].Description < a[j].Description }
func (a UICrashTypeArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type UICrashArray []UICrash

func (a UICrashArray) Len() int           { return len(a) }
func (a UICrashArray) Less(i, j int) bool { return a[i].Index < a[j].Index }
func (a UICrashArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var summaryTemplate = template.Must(template.New("").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{STYLE}}
</head>
<body>
<b>{{.Name }} syzkaller</b>
<br>
<br>

<table>
	<caption>Stats:</caption>
	{{range $s := $.Stats}}
	<tr>
		<td>{{$s.Name}}</td>
		{{if $s.Link}}
			<td><a href="{{$s.Link}}">{{$s.Value}}</a></td>
		{{else}}
			<td>{{$s.Value}}</td>
		{{end}}
	</tr>
	{{end}}
</table>
<br>

<table>
	<caption>Crashes:</caption>
	<tr>
		<th>Description</th>
		<th>Count</th>
		<th>Last Time</th>
		<th>Report</th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td><a href="/crash?id={{$c.ID}}">{{$c.Description}}</a></td>
		<td>{{$c.Count}}</td>
		<td>{{$c.LastTime}}</td>
		<td>
			{{if $c.Triaged}}
				<a href="/report?id={{$c.ID}}">{{$c.Triaged}}</a>
			{{end}}
		</td>
	</tr>
	{{end}}
</table>
<br>

<b>Log:</b>
<br>
<textarea id="log_textarea" readonly rows="20">
{{.Log}}
</textarea>
<script>
	var textarea = document.getElementById("log_textarea");
	textarea.scrollTop = textarea.scrollHeight;
</script>
<br>
<br>

<b>Per-call coverage:</b>
<br>
{{range $c := $.Calls}}
	{{$c.Name}}
		<a href='/corpus?call={{$c.Name}}'>inputs:{{$c.Inputs}}</a>
		<a href='/cover?call={{$c.Name}}'>cover:{{$c.Cover}}</a>
		<a href='/cover?call={{$c.Name}}&unique=1'>unique:{{$c.UniqueCover}}</a>
		<a href='/prio?call={{$c.Name}}'>prio</a> <br>
{{end}}
</body></html>
`)))

var crashTemplate = template.Must(template.New("").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>{{.Description}}</title>
	{{STYLE}}
</head>
<body>
<b>{{.Description}}</b>
<br><br>

{{if .Triaged}}
Report: <a href="/report?id={{.ID}}">{{.Triaged}}</a>
{{end}}
<br><br>

<table>
	<tr>
		<th>#</th>
		<th>Log</th>
		<th>Report</th>
		<th>Time</th>
		<th>Tag</th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td>{{$c.Index}}</td>
		<td><a href="/file?name={{$c.Log}}">log</a></td>
		{{if $c.Report}}
			<td><a href="/file?name={{$c.Report}}">report</a></td>
		{{else}}
			<td></td>
		{{end}}
		<td>{{$c.Time}}</td>
		<td>{{$c.Tag}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)))

var corpusTemplate = template.Must(template.New("").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>syzkaller corpus</title>
	{{STYLE}}
</head>
<body>
{{range $c := $}}
	<span title="{{$c.Full}}">{{$c.Short}}</span>
		<a href='/cover?call={{$c.N}}'>cover:{{$c.Cover}}</a>
		<a href='/cover?call={{$c.N}}&unique=1'>unique:{{$c.UniqueCover}}</a>
		<br>
{{end}}
</body></html>
`)))

type UIPrioData struct {
	Call  string
	Prios []UIPrio
}

type UIPrio struct {
	Call string
	Prio float32
}

type UIPrioArray []UIPrio

func (a UIPrioArray) Len() int           { return len(a) }
func (a UIPrioArray) Less(i, j int) bool { return a[i].Prio > a[j].Prio }
func (a UIPrioArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var prioTemplate = template.Must(template.New("").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>syzkaller priorities</title>
	{{STYLE}}
</head>
<body>
Priorities for {{$.Call}} <br> <br>
{{range $p := $.Prios}}
	{{printf "%.4f\t%s" $p.Prio $p.Call}} <br>
{{end}}
</body></html>
`)))

func addStyle(html string) string {
	return strings.Replace(html, "{{STYLE}}", htmlStyle, -1)
}

const htmlStyle = `
	<style type="text/css" media="screen">
		table {
			border-collapse:collapse;
			border:1px solid;
		}
		table caption {
			font-weight: bold;
		}
		table td {
			border:1px solid;
			padding: 3px;
		}
		table th {
			border:1px solid;
			padding: 3px;
		}
		textarea {
			width:100%;
		}
	</style>
`
