// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

func (mgr *Manager) initHttp() {
	http.HandleFunc("/", mgr.httpInfo)
	http.HandleFunc("/corpus", mgr.httpCorpus)
	http.HandleFunc("/cover", mgr.httpCover)
	http.HandleFunc("/prio", mgr.httpPrio)
	http.HandleFunc("/current_corpus", mgr.httpCurrentCorpus)
	go func() {
		logf(0, "serving http on http://%v", mgr.cfg.Http)
		panic(http.ListenAndServe(mgr.cfg.Http, nil))
	}()
}

func (mgr *Manager) httpInfo(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

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

	data := &UIData{
		Name:             mgr.cfg.Name,
		MasterHttp:       mgr.masterHttp,
		MasterCorpusSize: len(mgr.masterCorpus),
		CorpusSize:       len(mgr.corpus),
		TriageQueue:      len(mgr.candidates),
	}

	var cov cover.Cover
	for c, cc := range calls {
		cov = cover.Union(cov, cc.cov)
		data.Calls = append(data.Calls, UICallType{c, cc.count, len(cc.cov)})
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
	for i, inp := range mgr.corpus {
		if call != inp.Call {
			continue
		}
		p, err := prog.Deserialize(inp.Prog)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
		}
		data = append(data, UIInput{
			Short: p.String(),
			Full:  string(inp.Prog),
			Cover: len(inp.Cover),
			N:     i,
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
	if n, err := strconv.Atoi(call); err == nil && n < len(mgr.corpus) {
		cov = mgr.corpus[n].Cover
	} else {
		for _, inp := range mgr.corpus {
			if call == "" || call == inp.Call {
				cov = cover.Union(cov, cover.Cover(inp.Cover))
			}
		}
	}

	if err := generateCoverHtml(w, mgr.cfg.Vmlinux, cov); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
	}
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

func (mgr *Manager) httpCurrentCorpus(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.minimizeCorpus()
	var hashes []string
	for _, inp := range mgr.corpus {
		hash := hash(inp.Prog)
		hashes = append(hashes, hex.EncodeToString(hash[:]))
	}
	data, err := json.Marshal(&hashes)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal corpus: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

type UIData struct {
	Name             string
	MasterHttp       string
	MasterCorpusSize int
	CorpusSize       int
	TriageQueue      int
	CoverSize        int
	Calls            []UICallType
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
	N     int
}

type UICallTypeArray []UICallType

func (a UICallTypeArray) Len() int           { return len(a) }
func (a UICallTypeArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a UICallTypeArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type UIInputArray []UIInput

func (a UIInputArray) Len() int           { return len(a) }
func (a UIInputArray) Less(i, j int) bool { return a[i].Cover > a[j].Cover }
func (a UIInputArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var htmlTemplate = template.Must(template.New("").Parse(`
<!doctype html>
<html>
<head>
    <title>syzkaller {{.Name}}</title>
</head>
<body>
Manager: {{.Name}} <a href='http://{{.MasterHttp}}'>[master]</a> <br>
Master corpus: {{.MasterCorpusSize}} <br>
Corpus: {{.CorpusSize}}<br>
Triage queue len: {{.TriageQueue}}<br>
<a href='/cover'>Cover: {{.CoverSize}}</a> <br>
<br>
{{range $c := $.Calls}}
	{{$c.Name}} <a href='/corpus?call={{$c.Name}}'>inputs:{{$c.Inputs}}</a> <a href='/cover?call={{$c.Name}}'>cover:{{$c.Cover}}</a> <a href='/prio?call={{$c.Name}}'>prio</a> <br>
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
	<span title="{{$c.Full}}">{{$c.Short}}</span> <a href='/cover?call={{$c.N}}'>cover:{{$c.Cover}}</a> <br>
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
