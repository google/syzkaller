// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sort"
	"strconv"
	"time"
	"unsafe"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

func (mgr *Manager) initHttp() {
	http.HandleFunc("/", mgr.httpInfo)
	http.HandleFunc("/corpus", mgr.httpCorpus)
	http.HandleFunc("/cover", mgr.httpCover)
	http.HandleFunc("/prio", mgr.httpPrio)

	ln, err := net.Listen("tcp4", mgr.cfg.Http)
	if err != nil {
		fatalf("failed to listen on %v: %v", mgr.cfg.Http, err)
	}
	logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		log.Fatalf("failed to serve http: %v", err)
	}()
}

func (mgr *Manager) httpInfo(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	uptime := time.Since(mgr.startTime)
	data := &UIData{
		CorpusSize:  len(mgr.corpus),
		TriageQueue: len(mgr.candidates),
		Uptime:      fmt.Sprintf("%v", uptime),
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
		data.CorpusCoverMem += len(inp.Cover) * int(unsafe.Sizeof(inp.Cover[0]))
	}
	for _, cov := range mgr.corpusCover {
		data.CallCoverMem += len(cov) * int(unsafe.Sizeof(cov[0]))
	}

	secs := uint64(1)
	if !mgr.firstConnect.IsZero() {
		secs = uint64(time.Since(mgr.firstConnect))/1e9 + 1
	}
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
		data.Stats = append(data.Stats, UIStat{Name: k, Value: val})
	}
	sort.Sort(UIStatArray(data.Stats))

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
	data.CoverSize = len(cov)

	if err := htmlTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
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
	}
}

type UIData struct {
	CorpusSize     int
	TriageQueue    int
	CoverSize      int
	CorpusCoverMem int
	CallCoverMem   int
	Uptime         string
	Stats          []UIStat
	Calls          []UICallType
}

type UIStat struct {
	Name  string
	Value string
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

var htmlTemplate = template.Must(template.New("").Parse(`
<!doctype html>
<html>
<head>
    <title>syzkaller</title>
</head>
<body>
Uptime: {{.Uptime}}<br>
Corpus: {{.CorpusSize}}<br>
Triage queue len: {{.TriageQueue}}<br>
Cover mem: {{.CorpusCoverMem}} + {{.CallCoverMem}} <br>
{{if .CoverSize}}<a href='/cover'>Cover: {{.CoverSize}}</a> <br>{{end}}
<br>
Stats: <br>
{{range $stat := $.Stats}}
	{{$stat.Name}}: {{$stat.Value}}<br>
{{end}}
<br>
{{range $c := $.Calls}}
	{{$c.Name}}
		<a href='/corpus?call={{$c.Name}}'>inputs:{{$c.Inputs}}</a>
		<a href='/cover?call={{$c.Name}}'>cover:{{$c.Cover}}</a>
		<a href='/cover?call={{$c.Name}}&unique=1'>unique:{{$c.UniqueCover}}</a>
		<a href='/prio?call={{$c.Name}}'>prio</a> <br>
{{end}}
</body></html>
`))

var corpusTemplate = template.Must(template.New("").Parse(`
<!doctype html>
<html>
<head>
    <title>syzkaller corpus</title>
</head>
<body>
{{range $c := $}}
	<span title="{{$c.Full}}">{{$c.Short}}</span>
		<a href='/cover?call={{$c.N}}'>cover:{{$c.Cover}}</a>
		<a href='/cover?call={{$c.N}}&unique=1'>unique:{{$c.UniqueCover}}</a>
		<br>
{{end}}
</body></html>
`))

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

var prioTemplate = template.Must(template.New("").Parse(`
<!doctype html>
<html>
<head>
    <title>syzkaller priorities</title>
</head>
<body>
Priorities for {{$.Call}} <br> <br>
{{range $p := $.Prios}}
	{{printf "%.4f\t%s" $p.Prio $p.Call}} <br>
{{end}}
</body></html>
`))
