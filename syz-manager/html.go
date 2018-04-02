// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
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

	"github.com/google/syzkaller/pkg/cover"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

const dateFormat = "Jan 02 2006 15:04:05 MST"

func (mgr *Manager) initHTTP() {
	http.HandleFunc("/", mgr.httpSummary)
	http.HandleFunc("/syscalls", mgr.httpSyscalls)
	http.HandleFunc("/corpus", mgr.httpCorpus)
	http.HandleFunc("/crash", mgr.httpCrash)
	http.HandleFunc("/cover", mgr.httpCover)
	http.HandleFunc("/prio", mgr.httpPrio)
	http.HandleFunc("/file", mgr.httpFile)
	http.HandleFunc("/report", mgr.httpReport)
	http.HandleFunc("/rawcover", mgr.httpRawCover)
	// Browsers like to request this, without special handler this goes to / handler.
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	ln, err := net.Listen("tcp4", mgr.cfg.HTTP)
	if err != nil {
		Fatalf("failed to listen on %v: %v", mgr.cfg.HTTP, err)
	}
	Logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		Fatalf("failed to serve http: %v", err)
	}()
}

func (mgr *Manager) httpSummary(w http.ResponseWriter, r *http.Request) {
	data := &UISummaryData{
		Name:  mgr.cfg.Name,
		Log:   CachedLogOutput(),
		Stats: mgr.collectStats(),
	}

	var err error
	if data.Crashes, err = mgr.collectCrashes(mgr.cfg.Workdir); err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}

	if err := summaryTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err),
			http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	data := &UISyscallsData{
		Name: mgr.cfg.Name,
	}
	for c, cc := range mgr.collectSyscallInfo() {
		data.Calls = append(data.Calls, UICallType{
			Name:   c,
			Inputs: cc.count,
			Cover:  len(cc.cov),
		})
	}
	sort.Sort(UICallTypeArray(data.Calls))

	if err := syscallsTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err),
			http.StatusInternalServerError)
		return
	}
}

type CallCov struct {
	count int
	cov   cover.Cover
}

func (mgr *Manager) collectStats() []UIStat {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var stats []UIStat
	stats = append(stats, UIStat{Name: "uptime", Value: fmt.Sprint(time.Since(mgr.startTime) / 1e9 * 1e9)})
	stats = append(stats, UIStat{Name: "fuzzing", Value: fmt.Sprint(mgr.fuzzingTime / 60e9 * 60e9)})
	stats = append(stats, UIStat{Name: "corpus", Value: fmt.Sprint(len(mgr.corpus))})
	stats = append(stats, UIStat{Name: "triage queue", Value: fmt.Sprint(len(mgr.candidates))})
	stats = append(stats, UIStat{Name: "cover", Value: fmt.Sprint(len(mgr.corpusCover)), Link: "/cover"})
	stats = append(stats, UIStat{Name: "signal", Value: fmt.Sprint(mgr.corpusSignal.Len())})
	stats = append(stats, UIStat{Name: "syscalls", Value: fmt.Sprint(len(mgr.enabledCalls)), Link: "/syscalls"})

	secs := uint64(1)
	if !mgr.firstConnect.IsZero() {
		secs = uint64(time.Since(mgr.firstConnect))/1e9 + 1
	}

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
	stats = append(stats, intStats...)
	return stats
}

func (mgr *Manager) collectSyscallInfo() map[string]*CallCov {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	calls := make(map[string]*CallCov)
	for _, inp := range mgr.corpus {
		if calls[inp.Call] == nil {
			calls[inp.Call] = new(CallCov)
		}
		cc := calls[inp.Call]
		cc.count++
		cc.cov.Merge(inp.Cover)
	}
	return calls
}

func (mgr *Manager) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	crash := readCrash(mgr.cfg.Workdir, crashID, nil, true)
	if crash == nil {
		http.Error(w, fmt.Sprintf("failed to read crash info"), http.StatusInternalServerError)
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
	for sig, inp := range mgr.corpus {
		if call != inp.Call {
			continue
		}
		p, err := mgr.target.Deserialize(inp.Prog)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		data = append(data, UIInput{
			Short: p.String(),
			Full:  string(inp.Prog),
			Cover: len(inp.Cover),
			Sig:   sig,
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

	if mgr.cfg.Vmlinux == "" {
		http.Error(w, fmt.Sprintf("no vmlinux in config file"), http.StatusInternalServerError)
		return
	}
	var cov cover.Cover
	if sig := r.FormValue("input"); sig != "" {
		cov.Merge(mgr.corpus[sig].Cover)
	} else {
		call := r.FormValue("call")
		for _, inp := range mgr.corpus {
			if call == "" || call == inp.Call {
				cov.Merge(inp.Cover)
			}
		}
	}

	if err := generateCoverHTML(w, mgr.cfg.Vmlinux, cov); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
	runtime.GC()
}

func (mgr *Manager) httpPrio(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.minimizeCorpus()
	call := r.FormValue("call")
	idx := -1
	for i, c := range mgr.target.Syscalls {
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
		data.Prios = append(data.Prios, UIPrio{mgr.target.Syscalls[i].Name, p})
	}
	sort.Sort(UIPrioArray(data.Prios))

	if err := prioTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpFile(w http.ResponseWriter, r *http.Request) {
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
	rep, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.report"))
	log, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.stats.log"))
	stats, _ := ioutil.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.stats"))

	commitDesc := ""
	if len(tag) != 0 {
		commitDesc = fmt.Sprintf(" on commit %s.", trimNewLines(tag))
	}
	fmt.Fprintf(w, "Syzkaller hit '%s' bug%s.\n\n", trimNewLines(desc), commitDesc)
	if len(rep) != 0 {
		fmt.Fprintf(w, "%s\n\n", rep)
	}
	if len(prog) == 0 && len(cprog) == 0 {
		fmt.Fprintf(w, "The bug is not reproducible.\n")
	} else {
		fmt.Fprintf(w, "Syzkaller reproducer:\n%s\n\n", prog)
		if len(cprog) != 0 {
			fmt.Fprintf(w, "C reproducer:\n%s\n\n", cprog)
		}
	}
	if len(stats) > 0 {
		fmt.Fprintf(w, "Reproducing stats:\n%s\n\n", stats)
	}
	if len(log) > 0 {
		fmt.Fprintf(w, "Reproducing log:\n%s\n\n", log)
	}
}

func (mgr *Manager) httpRawCover(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	base, err := getVMOffset(mgr.cfg.Vmlinux)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get vmlinux base: %v", err), http.StatusInternalServerError)
		return
	}

	var cov cover.Cover
	for _, inp := range mgr.corpus {
		cov.Merge(inp.Cover)
	}
	pcs := make([]uint64, 0, len(cov))
	for pc := range cov {
		pcs = append(pcs, cover.RestorePC(pc, base)-callLen)
	}
	sort.Slice(pcs, func(i, j int) bool {
		return pcs[i] < pcs[j]
	})

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	buf := bufio.NewWriter(w)
	for _, pc := range pcs {
		fmt.Fprintf(buf, "0x%x\n", pc)
	}
	buf.Flush()
}

func (mgr *Manager) collectCrashes(workdir string) ([]*UICrashType, error) {
	// Note: mu is not locked here.
	reproReply := make(chan map[string]bool)
	mgr.reproRequest <- reproReply
	repros := <-reproReply

	crashdir := filepath.Join(workdir, "crashes")
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	var crashTypes []*UICrashType
	for _, dir := range dirs {
		crash := readCrash(workdir, dir, repros, false)
		if crash != nil {
			crashTypes = append(crashTypes, crash)
		}
	}
	sort.Sort(UICrashTypeArray(crashTypes))
	return crashTypes, nil
}

func readCrash(workdir, dir string, repros map[string]bool, full bool) *UICrashType {
	if len(dir) != 40 {
		return nil
	}
	crashdir := filepath.Join(workdir, "crashes")
	descFile, err := os.Open(filepath.Join(crashdir, dir, "description"))
	if err != nil {
		return nil
	}
	defer descFile.Close()
	desc, err := ioutil.ReadAll(descFile)
	if err != nil || len(desc) == 0 {
		return nil
	}
	desc = trimNewLines(desc)
	stat, err := descFile.Stat()
	if err != nil {
		return nil
	}
	modTime := stat.ModTime()
	descFile.Close()

	files, err := osutil.ListDir(filepath.Join(crashdir, dir))
	if err != nil {
		return nil
	}
	var crashes []*UICrash
	reproAttempts := 0
	hasRepro, hasCRepro := false, false
	reports := make(map[string]bool)
	for _, f := range files {
		if strings.HasPrefix(f, "log") {
			index, err := strconv.ParseUint(f[3:], 10, 64)
			if err == nil {
				crashes = append(crashes, &UICrash{
					Index: int(index),
				})
			}
		} else if strings.HasPrefix(f, "report") {
			reports[f] = true
		} else if f == "repro.prog" {
			hasRepro = true
		} else if f == "repro.cprog" {
			hasCRepro = true
		} else if f == "repro.report" {
		} else if f == "repro0" || f == "repro1" || f == "repro2" {
			reproAttempts++
		}
	}

	if full {
		for _, crash := range crashes {
			index := strconv.Itoa(crash.Index)
			crash.Log = filepath.Join("crashes", dir, "log"+index)
			if stat, err := os.Stat(filepath.Join(workdir, crash.Log)); err == nil {
				crash.Time = stat.ModTime()
				crash.TimeStr = crash.Time.Format(dateFormat)
			}
			tag, _ := ioutil.ReadFile(filepath.Join(crashdir, dir, "tag"+index))
			crash.Tag = string(tag)
			reportFile := filepath.Join("crashes", dir, "report"+index)
			if osutil.IsExist(filepath.Join(workdir, reportFile)) {
				crash.Report = reportFile
			}
		}
		sort.Sort(UICrashArray(crashes))
	}

	triaged := ""
	if hasRepro {
		if hasCRepro {
			triaged = "has C repro"
		} else {
			triaged = "has repro"
		}
	} else if repros[string(desc)] {
		triaged = "reproducing"
	} else if reproAttempts >= maxReproAttempts {
		triaged = "non-reproducible"
	}
	return &UICrashType{
		Description: string(desc),
		LastTime:    modTime.Format(dateFormat),
		ID:          dir,
		Count:       len(crashes),
		Triaged:     triaged,
		Crashes:     crashes,
	}
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
	Crashes []*UICrashType
	Log     string
}

type UISyscallsData struct {
	Name  string
	Calls []UICallType
}

type UICrashType struct {
	Description string
	LastTime    string
	ID          string
	Count       int
	Triaged     string
	Crashes     []*UICrash
}

type UICrash struct {
	Index   int
	Time    time.Time
	TimeStr string
	Log     string
	Report  string
	Tag     string
}

type UIStat struct {
	Name  string
	Value string
	Link  string
}

type UICallType struct {
	Name   string
	Inputs int
	Cover  int
}

type UIInput struct {
	Short string
	Full  string
	Calls int
	Cover int
	Sig   string
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

type UICrashTypeArray []*UICrashType

func (a UICrashTypeArray) Len() int           { return len(a) }
func (a UICrashTypeArray) Less(i, j int) bool { return a[i].Description < a[j].Description }
func (a UICrashTypeArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type UICrashArray []*UICrash

func (a UICrashArray) Len() int           { return len(a) }
func (a UICrashArray) Less(i, j int) bool { return a[i].Time.After(a[j].Time) }
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
</body></html>
`)))

var syscallsTemplate = template.Must(template.New("").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{STYLE}}
</head>
<body>
<b>Per-call coverage:</b>
<br>
{{range $c := $.Calls}}
	{{$c.Name}}
		<a href='/corpus?call={{$c.Name}}'>inputs:{{$c.Inputs}}</a>
		<a href='/cover?call={{$c.Name}}'>cover:{{$c.Cover}}</a>
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
		<td>{{$c.TimeStr}}</td>
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
		<a href='/cover?input={{$c.Sig}}'>cover:{{$c.Cover}}</a>
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
