// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

func (hub *Hub) initHTTP(addr string) {
	http.HandleFunc("/", hub.httpSummary)

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", addr, err)
	}
	log.Logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		log.Fatalf("failed to serve http: %v", err)
	}()
}

func (hub *Hub) httpSummary(w http.ResponseWriter, r *http.Request) {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	data := &UISummaryData{
		Log: log.CachedLogOutput(),
	}
	total := UIManager{
		Name:   "total",
		Corpus: len(hub.st.Corpus.Records),
		Repros: len(hub.st.Repros.Records),
	}
	for name, mgr := range hub.st.Managers {
		total.Added += mgr.Added
		total.Deleted += mgr.Deleted
		total.New += mgr.New
		total.SentRepros += mgr.SentRepros
		total.RecvRepros += mgr.RecvRepros
		data.Managers = append(data.Managers, UIManager{
			Name:       name,
			Corpus:     len(mgr.Corpus.Records),
			Added:      mgr.Added,
			Deleted:    mgr.Deleted,
			New:        mgr.New,
			SentRepros: mgr.SentRepros,
			RecvRepros: mgr.RecvRepros,
		})
	}
	sort.Sort(UIManagerArray(data.Managers))
	data.Managers = append([]UIManager{total}, data.Managers...)
	if err := summaryTemplate.Execute(w, data); err != nil {
		log.Logf(0, "failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func compileTemplate(html string) *template.Template {
	return template.Must(template.New("").Parse(strings.Replace(html, "{{STYLE}}", htmlStyle, -1)))
}

type UISummaryData struct {
	Managers []UIManager
	Log      string
}

type UIManager struct {
	Name       string
	Corpus     int
	Added      int
	Deleted    int
	New        int
	Repros     int
	SentRepros int
	RecvRepros int
}

type UIManagerArray []UIManager

func (a UIManagerArray) Len() int           { return len(a) }
func (a UIManagerArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a UIManagerArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var summaryTemplate = compileTemplate(`
<!doctype html>
<html>
<head>
	<title>syz-hub</title>
	{{STYLE}}
</head>
<body>
<b>syz-hub</b>
<br><br>

<table>
	<caption>Managers:</caption>
	<tr>
		<th>Name</th>
		<th>Corpus</th>
		<th>Added</th>
		<th>Deleted</th>
		<th>New</th>
		<th>Repros</th>
		<th>Sent</th>
		<th>Recv</th>
	</tr>
	{{range $m := $.Managers}}
	<tr>
		<td>{{$m.Name}}</td>
		<td>{{$m.Corpus}}</td>
		<td>{{$m.Added}}</td>
		<td>{{$m.Deleted}}</td>
		<td>{{$m.New}}</td>
		<td>{{$m.Repros}}</td>
		<td>{{$m.SentRepros}}</td>
		<td>{{$m.RecvRepros}}</td>
	</tr>
	{{end}}
</table>
<br><br>

Log:
<br>
<textarea id="log_textarea" readonly rows="50">
{{.Log}}
</textarea>
<script>
	var textarea = document.getElementById("log_textarea");
	textarea.scrollTop = textarea.scrollHeight;
</script>

</body></html>
`)

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
