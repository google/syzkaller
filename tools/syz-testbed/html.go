// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/gorilla/handlers"
)

func (ctx *TestbedContext) setupHTTPServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", ctx.httpMain)
	mux.HandleFunc("/graph", ctx.httpGraph)

	listener, err := net.Listen("tcp", ctx.Config.HTTP)
	if err != nil {
		log.Fatalf("failed to listen on %s", ctx.Config.HTTP)
	}

	log.Printf("handling HTTP on %s", listener.Addr())
	go func() {
		err := http.Serve(listener, handlers.CompressHandler(mux))
		if err != nil {
			log.Fatalf("failed to listen on %v: %v", ctx.Config.HTTP, err)
		}
	}()
}

func (ctx *TestbedContext) getCurrentStatView(r *http.Request) (*StatView, error) {
	views, err := ctx.GetStatViews()
	if err != nil {
		return nil, err
	}
	if len(views) == 0 {
		return nil, fmt.Errorf("no stat views available")
	}
	viewName := r.FormValue("view")
	if viewName != "" {
		var targetView *StatView
		for _, view := range views {
			if view.Name == viewName {
				targetView = &view
				break
			}
		}
		if targetView == nil {
			return nil, fmt.Errorf("the requested view is not found")
		}
		return targetView, nil
	}
	// No specific view is requested.
	// First try to find the first non-empty one.
	for _, view := range views {
		if !view.IsEmpty() {
			return &view, nil
		}
	}
	return &views[0], nil
}

func (ctx *TestbedContext) httpGraph(w http.ResponseWriter, r *http.Request) {
	over := r.FormValue("over")

	if ctx.Config.BenchCmp == "" {
		http.Error(w, "the path to the benchcmp tool is not specified", http.StatusInternalServerError)
		return
	}

	targetView, err := ctx.getCurrentStatView(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}

	// TODO: move syz-benchcmp functionality to pkg/ and just import it?
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		http.Error(w, "failed to create temp folder", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dir)

	file, err := osutil.TempFile("")
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(file)

	benches, err := targetView.SaveAvgBenches(dir)
	if err != nil {
		http.Error(w, "failed to save avg benches", http.StatusInternalServerError)
		return
	}

	args := append([]string{"-all", "-over", over, "-out", file}, benches...)
	if out, err := osutil.RunCmd(time.Hour, "", ctx.Config.BenchCmp, args...); err != nil {
		http.Error(w, "syz-benchcmp failed\n"+string(out), http.StatusInternalServerError)
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		http.Error(w, "failed to read the temporary file", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

type uiStatView struct {
	Name  string
	Table *Table
}

type uiMainPage struct {
	Name       string
	Summary    *Table
	Views      []StatView
	ActiveView uiStatView
}

func (ctx *TestbedContext) httpMain(w http.ResponseWriter, r *http.Request) {
	activeView, err := ctx.getCurrentStatView(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}

	views, err := ctx.GetStatViews()
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}

	uiView := uiStatView{Name: activeView.Name}
	table, err := activeView.StatsTable()
	if err != nil {
		log.Printf("stat table generation failed: %s", err)
	} else {
		uiView.Table = table
	}

	data := &uiMainPage{
		Name:       ctx.Config.Name,
		Summary:    ctx.TestbedStatsTable(),
		Views:      views,
		ActiveView: uiView,
	}

	executeTemplate(w, mainTemplate, data)
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, data interface{}) {
	buf := new(bytes.Buffer)
	if err := templ.Execute(buf, data); err != nil {
		log.Printf("failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

var mainTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
<style>

</style>
</head>
<body>

<header id="topbar">
	<table class="position_table">
		<tbody>
		<tr><td>
		<h1><a href="/">syz-testbed "{{.Name }}"</a></h1>
		</td></tr>
		</tbody>
	</table>
	<table class="position_table">
	<tbody>
	<td class="navigation">
Views:
{{with $main := .}}
{{range $view := .Views}}
<a
{{if eq $view.Name $main.ActiveView.Name}}
class="navigation_tab_selected"
{{else}}
class="navigation_tab"
{{end}}
href="?view={{$view.Name}}">█ {{$view.Name}}</a>
&nbsp;
{{end}}
{{end}}
	</td>
	</tbody>
	</table>
</header>

{{define "Table"}}
{{if .}}
<table class="list_table">
	<tr>
	<th>{{.TopLeftHeader}}</th>
	{{range $c := .ColumnHeaders}}
		<th>{{$c}}</th>
	{{end}}
	</tr>
	{{range $r := .SortedRows}}
	<tr>
		<td>{{$r}}</td>
		{{range $c := $.ColumnHeaders}}
			<td>{{$.Get $r $c}}</td>
		{{end}}
	</tr>
	{{end}}
</table>
{{end}}
{{end}}

{{template "Table" .Summary}}

<b>Stat view "{{$.ActiveView.Name}}"</b><br />
<a href="/graph?view={{.ActiveView.Name}}&over=fuzzing">Graph over time</a> /
<a href="/graph?view={{.ActiveView.Name}}&over=exec+total">Graph over executions</a> <br />
{{template "Table" .ActiveView.Table}}

</body>
</html>
`)
