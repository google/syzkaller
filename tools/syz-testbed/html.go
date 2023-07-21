// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/gorilla/handlers"
)

func (ctx *TestbedContext) setupHTTPServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", ctx.httpMain)
	mux.HandleFunc("/graph", ctx.httpGraph)
	mux.HandleFunc("/favicon.ico", ctx.httpFavicon)

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

func (ctx *TestbedContext) httpFavicon(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Found", http.StatusNotFound)
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
	dir, err := os.MkdirTemp("", "")
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

	data, err := os.ReadFile(file)
	if err != nil {
		http.Error(w, "failed to read the temporary file", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

type uiTable struct {
	Table     *Table
	ColumnURL func(string) string
	RowURL    func(string) string
	Extra     bool
	HasFooter bool
	AlignedBy string
}

const (
	HTMLStatsTable         = "stats"
	HTMLBugsTable          = "bugs"
	HTMLBugCountsTable     = "bug_counts"
	HTMLReprosTable        = "repros"
	HTMLCReprosTable       = "crepros"
	HTMLReproAttemptsTable = "repro_attempts"
	HTMLReproDurationTable = "repro_duration"
)

type uiTableGenerator = func(urlPrefix string, view StatView, r *http.Request) (*uiTable, error)

type uiTableType struct {
	Key       string
	Title     string
	Generator uiTableGenerator
}

type uiStatView struct {
	Name            string
	TableTypes      map[string]uiTableType
	ActiveTableType string
	ActiveTable     *uiTable
	GenTableURL     func(uiTableType) string
}

type uiMainPage struct {
	Name       string
	Summary    uiTable
	Views      []StatView
	ActiveView uiStatView
}

func (ctx *TestbedContext) getTableTypes() []uiTableType {
	allTypeList := []uiTableType{
		{HTMLStatsTable, "Statistics", ctx.httpMainStatsTable},
		{HTMLBugsTable, "Bugs", ctx.genSimpleTableController((StatView).GenerateBugTable, true)},
		{HTMLBugCountsTable, "Bug Counts", ctx.genSimpleTableController((StatView).GenerateBugCountsTable, false)},
		{HTMLReprosTable, "Repros", ctx.genSimpleTableController((StatView).GenerateReproSuccessTable, true)},
		{HTMLCReprosTable, "C Repros", ctx.genSimpleTableController((StatView).GenerateCReproSuccessTable, true)},
		{HTMLReproAttemptsTable, "All Repros", ctx.genSimpleTableController((StatView).GenerateReproAttemptsTable, false)},
		{HTMLReproDurationTable, "Duration", ctx.genSimpleTableController((StatView).GenerateReproDurationTable, true)},
	}
	typeList := []uiTableType{}
	for _, t := range allTypeList {
		if ctx.Target.SupportsHTMLView(t.Key) {
			typeList = append(typeList, t)
		}
	}
	return typeList
}

func (ctx *TestbedContext) genSimpleTableController(method func(view StatView) (*Table, error),
	hasFooter bool) uiTableGenerator {
	return func(urlPrefix string, view StatView, r *http.Request) (*uiTable, error) {
		table, err := method(view)
		if err != nil {
			return nil, fmt.Errorf("table generation failed: %w", err)
		}
		return &uiTable{
			Table:     table,
			HasFooter: hasFooter,
		}, nil
	}
}

func (ctx *TestbedContext) httpMainStatsTable(urlPrefix string, view StatView, r *http.Request) (*uiTable, error) {
	alignBy := r.FormValue("align")
	if alignBy == "" {
		alignBy = "fuzzing"
	}
	table, err := view.AlignedStatsTable(alignBy)
	if err != nil {
		return nil, fmt.Errorf("stat table generation failed: %w", err)
	}
	baseColumn := r.FormValue("base_column")
	if baseColumn != "" {
		err := table.SetRelativeValues(baseColumn)
		if err != nil {
			log.Printf("failed to execute SetRelativeValues: %s", err)
		}
	}

	return &uiTable{
		Table: table,
		Extra: baseColumn != "",
		ColumnURL: func(column string) string {
			if column == baseColumn {
				return ""
			}
			v := url.Values{}
			v.Set("base_column", column)
			v.Set("align", alignBy)
			return urlPrefix + v.Encode()
		},
		RowURL: func(row string) string {
			if row == alignBy {
				return ""
			}
			v := url.Values{}
			v.Set("base_column", baseColumn)
			v.Set("align", row)
			return urlPrefix + v.Encode()
		},
		AlignedBy: alignBy,
	}, nil
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
	tableTypes := ctx.getTableTypes()
	if len(tableTypes) == 0 {
		http.Error(w, "No tables are available", http.StatusInternalServerError)
		return
	}
	uiView.TableTypes = map[string]uiTableType{}
	for _, table := range tableTypes {
		uiView.TableTypes[table.Key] = table
	}
	uiView.ActiveTableType = r.FormValue("table")
	if uiView.ActiveTableType == "" {
		uiView.ActiveTableType = tableTypes[0].Key
	}
	tableType, found := uiView.TableTypes[uiView.ActiveTableType]
	if !found {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	uiView.GenTableURL = func(t uiTableType) string {
		v := url.Values{}
		v.Set("view", activeView.Name)
		v.Set("table", t.Key)
		return "/?" + v.Encode()
	}
	uiView.ActiveTable, err = tableType.Generator(uiView.GenTableURL(tableType)+"&", *activeView, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	data := &uiMainPage{
		Name:       ctx.Config.Name,
		Summary:    uiTable{Table: ctx.TestbedStatsTable()},
		Views:      views,
		ActiveView: uiView,
	}

	executeTemplate(w, mainTemplate, "testbed.html", data)
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, name string, data interface{}) {
	buf := new(bytes.Buffer)
	if err := templ.ExecuteTemplate(buf, name, data); err != nil {
		log.Printf("failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

//go:embed templates
var testbedTemplates embed.FS
var mainTemplate = pages.CreateFromFS(testbedTemplates, "templates/*.html")
