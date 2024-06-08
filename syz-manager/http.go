// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (mgr *Manager) initHTTP() {
	handle := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		http.Handle(pattern, handlers.CompressHandler(http.HandlerFunc(handler)))
	}
	handle("/", mgr.httpSummary)
	handle("/config", mgr.httpConfig)
	handle("/expert_mode", mgr.httpExpertMode)
	handle("/stats", mgr.httpStats)
	handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP)
	handle("/syscalls", mgr.httpSyscalls)
	handle("/corpus", mgr.httpCorpus)
	handle("/corpus.db", mgr.httpDownloadCorpus)
	handle("/crash", mgr.httpCrash)
	handle("/cover", mgr.httpCover)
	handle("/subsystemcover", mgr.httpSubsystemCover)
	handle("/modulecover", mgr.httpModuleCover)
	handle("/prio", mgr.httpPrio)
	handle("/file", mgr.httpFile)
	handle("/report", mgr.httpReport)
	handle("/rawcover", mgr.httpRawCover)
	handle("/rawcoverfiles", mgr.httpRawCoverFiles)
	handle("/filterpcs", mgr.httpFilterPCs)
	handle("/funccover", mgr.httpFuncCover)
	handle("/filecover", mgr.httpFileCover)
	handle("/input", mgr.httpInput)
	handle("/debuginput", mgr.httpDebugInput)
	handle("/modules", mgr.modulesInfo)
	// Browsers like to request this, without special handler this goes to / handler.
	handle("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	log.Logf(0, "serving http on http://%v", mgr.cfg.HTTP)
	go func() {
		err := http.ListenAndServe(mgr.cfg.HTTP, nil)
		if err != nil {
			log.Fatalf("failed to listen on %v: %v", mgr.cfg.HTTP, err)
		}
	}()
}

func (mgr *Manager) httpSummary(w http.ResponseWriter, r *http.Request) {
	revision, link := revisionAndLink()
	data := &UISummaryData{
		Name:         mgr.cfg.Name,
		Revision:     revision,
		RevisionLink: link,
		Expert:       mgr.expertMode,
		Log:          log.CachedLogOutput(),
	}

	level := stats.Simple
	if mgr.expertMode {
		level = stats.All
	}
	for _, stat := range stats.Collect(level) {
		data.Stats = append(data.Stats, UIStat{
			Name:  stat.Name,
			Value: stat.Value,
			Hint:  stat.Desc,
			Link:  stat.Link,
		})
	}

	var err error
	if data.Crashes, err = mgr.collectCrashes(mgr.cfg.Workdir); err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}
	executeTemplate(w, summaryTemplate, data)
}

func revisionAndLink() (string, string) {
	var revision string
	var link string
	if len(prog.GitRevisionBase) > 8 {
		revision = prog.GitRevisionBase[:8]
		link = vcs.LogLink(vcs.SyzkallerRepo, prog.GitRevisionBase)
	} else {
		revision = prog.GitRevisionBase
		link = ""
	}

	return revision, link
}

func (mgr *Manager) httpConfig(w http.ResponseWriter, r *http.Request) {
	data, err := json.MarshalIndent(mgr.cfg, "", "\t")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode json: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (mgr *Manager) httpExpertMode(w http.ResponseWriter, r *http.Request) {
	mgr.expertMode = !mgr.expertMode
	http.Redirect(w, r, "/", http.StatusFound)
}

func (mgr *Manager) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	data := &UISyscallsData{
		Name: mgr.cfg.Name,
	}
	for c, cc := range mgr.collectSyscallInfo() {
		var syscallID *int
		if syscall, ok := mgr.target.SyscallMap[c]; ok {
			syscallID = &syscall.ID
		}
		data.Calls = append(data.Calls, UICallType{
			Name:   c,
			ID:     syscallID,
			Inputs: cc.Count,
			Cover:  len(cc.Cover),
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, syscallsTemplate, data)
}

func (mgr *Manager) httpStats(w http.ResponseWriter, r *http.Request) {
	data, err := stats.RenderHTML()
	if err != nil {
		log.Logf(0, "failed to execute template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (mgr *Manager) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	crash := readCrash(mgr.cfg.Workdir, crashID, nil, mgr.firstConnect.Load(), true)
	if crash == nil {
		http.Error(w, "failed to read crash info", http.StatusInternalServerError)
		return
	}
	executeTemplate(w, crashTemplate, crash)
}

func (mgr *Manager) httpCorpus(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	data := UICorpus{
		Call:     r.FormValue("call"),
		RawCover: mgr.cfg.RawCover,
	}
	for _, inp := range mgr.corpus.Items() {
		if data.Call != "" && data.Call != inp.StringCall() {
			continue
		}
		data.Inputs = append(data.Inputs, &UIInput{
			Sig:   inp.Sig,
			Short: inp.Prog.String(),
			Cover: len(inp.Cover),
		})
	}
	sort.Slice(data.Inputs, func(i, j int) bool {
		a, b := data.Inputs[i], data.Inputs[j]
		if a.Cover != b.Cover {
			return a.Cover > b.Cover
		}
		return a.Short < b.Short
	})
	executeTemplate(w, corpusTemplate, data)
}

func (mgr *Manager) httpDownloadCorpus(w http.ResponseWriter, r *http.Request) {
	corpus := filepath.Join(mgr.cfg.Workdir, "corpus.db")
	file, err := os.Open(corpus)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to open corpus : %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	buf, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read corpus : %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf)
}

const (
	DoHTML int = iota
	DoHTMLTable
	DoModuleCover
	DoCSV
	DoCSVFiles
	DoRawCoverFiles
	DoRawCover
	DoFilterPCs
	DoCoverJSONL
)

func (mgr *Manager) httpCover(w http.ResponseWriter, r *http.Request) {
	if !mgr.cfg.Cover {
		mgr.httpCoverFallback(w, r)
		return
	}
	if r.FormValue("jsonl") == "1" {
		mgr.httpCoverCover(w, r, DoCoverJSONL)
		return
	}
	mgr.httpCoverCover(w, r, DoHTML)
}

func (mgr *Manager) httpSubsystemCover(w http.ResponseWriter, r *http.Request) {
	if !mgr.cfg.Cover {
		mgr.httpCoverFallback(w, r)
		return
	}
	mgr.httpCoverCover(w, r, DoHTMLTable)
}

func (mgr *Manager) httpModuleCover(w http.ResponseWriter, r *http.Request) {
	if !mgr.cfg.Cover {
		mgr.httpCoverFallback(w, r)
		return
	}
	mgr.httpCoverCover(w, r, DoModuleCover)
}

const ctTextPlain = "text/plain; charset=utf-8"
const ctApplicationJSON = "application/json"

func (mgr *Manager) httpCoverCover(w http.ResponseWriter, r *http.Request, funcFlag int) {
	if !mgr.cfg.Cover {
		http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		return
	}

	// Don't hold the mutex while creating report generator and generating the report,
	// these operations take lots of time.
	if !mgr.serv.checkDone.Load() {
		http.Error(w, "coverage is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}

	rg, err := getReportGenerator(mgr.cfg, mgr.serv.modules)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}

	if r.FormValue("flush") != "" {
		defer func() {
			resetReportGenerator()
			debug.FreeOSMemory()
		}()
	}

	mgr.mu.Lock()
	var progs []cover.Prog
	if sig := r.FormValue("input"); sig != "" {
		inp := mgr.corpus.Item(sig)
		if inp == nil {
			http.Error(w, "unknown input hash", http.StatusInternalServerError)
			return
		}
		if r.FormValue("update_id") != "" {
			updateID, err := strconv.Atoi(r.FormValue("update_id"))
			if err != nil || updateID < 0 || updateID >= len(inp.Updates) {
				http.Error(w, "bad call_id", http.StatusBadRequest)
				return
			}
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.ProgData),
				PCs:  coverToPCs(mgr.cfg, inp.Updates[updateID].RawCover),
			})
		} else {
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.ProgData),
				PCs:  coverToPCs(mgr.cfg, inp.Cover),
			})
		}
	} else {
		call := r.FormValue("call")
		for _, inp := range mgr.corpus.Items() {
			if call != "" && call != inp.StringCall() {
				continue
			}
			progs = append(progs, cover.Prog{
				Sig:  inp.Sig,
				Data: string(inp.ProgData),
				PCs:  coverToPCs(mgr.cfg, inp.Cover),
			})
		}
	}
	mgr.mu.Unlock()

	var coverFilter map[uint64]struct{}
	if r.FormValue("filter") != "" || funcFlag == DoFilterPCs {
		if mgr.serv.coverFilter == nil {
			http.Error(w, "cover is not filtered in config", http.StatusInternalServerError)
			return
		}
		coverFilter = mgr.serv.coverFilter
	}

	params := cover.HandlerParams{
		Progs:  progs,
		Filter: coverFilter,
		Debug:  r.FormValue("debug") != "",
		Force:  r.FormValue("force") != "",
	}

	type handlerFuncType func(w io.Writer, params cover.HandlerParams) error
	flagToFunc := map[int]struct {
		Do          handlerFuncType
		contentType string
	}{
		DoHTML:          {rg.DoHTML, ""},
		DoHTMLTable:     {rg.DoHTMLTable, ""},
		DoModuleCover:   {rg.DoModuleCover, ""},
		DoCSV:           {rg.DoCSV, ctTextPlain},
		DoCSVFiles:      {rg.DoCSVFiles, ctTextPlain},
		DoRawCoverFiles: {rg.DoRawCoverFiles, ctTextPlain},
		DoRawCover:      {rg.DoRawCover, ctTextPlain},
		DoFilterPCs:     {rg.DoFilterPCs, ctTextPlain},
		DoCoverJSONL:    {rg.DoCoverJSONL, ctApplicationJSON},
	}

	if ct := flagToFunc[funcFlag].contentType; ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	if err := flagToFunc[funcFlag].Do(w, params); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
}

func (mgr *Manager) httpCoverFallback(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	calls := make(map[int][]int)
	for s := range mgr.corpus.Signal() {
		id, errno := prog.DecodeFallbackSignal(uint64(s))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{}
	for call := range mgr.targetEnabledSyscalls {
		errnos := calls[call.ID]
		sort.Ints(errnos)
		successful := 0
		for len(errnos) != 0 && errnos[0] == 0 {
			successful++
			errnos = errnos[1:]
		}
		data.Calls = append(data.Calls, UIFallbackCall{
			Name:       call.Name,
			Successful: successful,
			Errnos:     errnos,
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, fallbackCoverTemplate, data)
}

func (mgr *Manager) httpFuncCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoCSV)
}

func (mgr *Manager) httpFileCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoCSVFiles)
}

func (mgr *Manager) httpPrio(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	callName := r.FormValue("call")
	call := mgr.target.SyscallMap[callName]
	if call == nil {
		http.Error(w, fmt.Sprintf("unknown call: %v", callName), http.StatusInternalServerError)
		return
	}

	var corpus []*prog.Prog
	for _, inp := range mgr.corpus.Items() {
		corpus = append(corpus, inp.Prog)
	}
	prios := mgr.target.CalculatePriorities(corpus)

	data := &UIPrioData{Call: callName}
	for i, p := range prios[call.ID] {
		data.Prios = append(data.Prios, UIPrio{mgr.target.Syscalls[i].Name, p})
	}
	sort.Slice(data.Prios, func(i, j int) bool {
		return data.Prios[i].Prio > data.Prios[j].Prio
	})
	executeTemplate(w, prioTemplate, data)
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

func (mgr *Manager) httpInput(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	inp := mgr.corpus.Item(r.FormValue("sig"))
	if inp == nil {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.ProgData)
}

func (mgr *Manager) httpDebugInput(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	inp := mgr.corpus.Item(r.FormValue("sig"))
	if inp == nil {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	getIDs := func(callID int) []int {
		ret := []int{}
		for id, update := range inp.Updates {
			if update.Call == callID {
				ret = append(ret, id)
			}
		}
		return ret
	}
	data := []UIRawCallCover{}
	for pos, line := range strings.Split(string(inp.ProgData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		data = append(data, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      line,
			UpdateIDs: getIDs(pos),
		})
	}
	extraIDs := getIDs(-1)
	if len(extraIDs) > 0 {
		data = append(data, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      ".extra",
			UpdateIDs: extraIDs,
		})
	}
	executeTemplate(w, rawCoverTemplate, data)
}

func (mgr *Manager) modulesInfo(w http.ResponseWriter, r *http.Request) {
	if mgr.serv.canonicalModules == nil {
		fmt.Fprintf(w, "module information not retrieved yet, please retry after fuzzing starts\n")
		return
	}
	// NewCanonicalizer() is initialized with serv.modules.
	modules, err := json.MarshalIndent(mgr.serv.modules, "", "\t")
	if err != nil {
		fmt.Fprintf(w, "unable to create JSON modules info: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(modules)
}

var alphaNumRegExp = regexp.MustCompile(`^[a-zA-Z0-9]*$`)

func isAlphanumeric(s string) bool {
	return alphaNumRegExp.MatchString(s)
}

func (mgr *Manager) httpReport(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	crashID := r.FormValue("id")
	if !isAlphanumeric(crashID) {
		http.Error(w, "wrong id", http.StatusBadRequest)
		return
	}

	desc, err := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "description"))
	if err != nil {
		http.Error(w, "failed to read description file", http.StatusInternalServerError)
		return
	}
	tag, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.tag"))
	prog, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.prog"))
	cprog, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.cprog"))
	rep, _ := os.ReadFile(filepath.Join(mgr.crashdir, crashID, "repro.report"))

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
}

func (mgr *Manager) httpRawCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoRawCover)
}

func (mgr *Manager) httpRawCoverFiles(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoRawCoverFiles)
}

func (mgr *Manager) httpFilterPCs(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoFilterPCs)
}

func (mgr *Manager) collectCrashes(workdir string) ([]*UICrashType, error) {
	// Note: mu is not locked here.
	var repros map[string]bool
	if !mgr.cfg.VMLess {
		reproReply := make(chan map[string]bool)
		mgr.reproRequest <- reproReply
		repros = <-reproReply
	}

	crashdir := filepath.Join(workdir, "crashes")
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	var crashTypes []*UICrashType
	for _, dir := range dirs {
		crash := readCrash(workdir, dir, repros, mgr.firstConnect.Load(), false)
		if crash != nil {
			crashTypes = append(crashTypes, crash)
		}
	}
	sort.Slice(crashTypes, func(i, j int) bool {
		return strings.ToLower(crashTypes[i].Description) < strings.ToLower(crashTypes[j].Description)
	})
	return crashTypes, nil
}

func readCrash(workdir, dir string, repros map[string]bool, start int64, full bool) *UICrashType {
	if len(dir) != 40 {
		return nil
	}
	crashdir := filepath.Join(workdir, "crashes")
	descFile, err := os.Open(filepath.Join(crashdir, dir, "description"))
	if err != nil {
		return nil
	}
	defer descFile.Close()
	descBytes, err := io.ReadAll(descFile)
	if err != nil || len(descBytes) == 0 {
		return nil
	}
	desc := string(trimNewLines(descBytes))
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
	strace := ""
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
		} else if f == "strace.log" {
			strace = filepath.Join("crashes", dir, f)
		}
	}

	if full {
		for _, crash := range crashes {
			index := strconv.Itoa(crash.Index)
			crash.Log = filepath.Join("crashes", dir, "log"+index)
			if stat, err := os.Stat(filepath.Join(workdir, crash.Log)); err == nil {
				crash.Time = stat.ModTime()
				crash.Active = start != 0 && crash.Time.Unix() >= start
			}
			tag, _ := os.ReadFile(filepath.Join(crashdir, dir, "tag"+index))
			crash.Tag = string(tag)
			reportFile := filepath.Join("crashes", dir, "report"+index)
			if osutil.IsExist(filepath.Join(workdir, reportFile)) {
				crash.Report = reportFile
			}
		}
		sort.Slice(crashes, func(i, j int) bool {
			return crashes[i].Time.After(crashes[j].Time)
		})
	}

	triaged := reproStatus(hasRepro, hasCRepro, repros[desc], reproAttempts >= maxReproAttempts)
	return &UICrashType{
		Description: desc,
		LastTime:    modTime,
		Active:      start != 0 && modTime.Unix() >= start,
		ID:          dir,
		Count:       len(crashes),
		Triaged:     triaged,
		Strace:      strace,
		Crashes:     crashes,
	}
}

func reproStatus(hasRepro, hasCRepro, reproducing, nonReproducible bool) string {
	status := ""
	if hasRepro {
		status = "has repro"
		if hasCRepro {
			status = "has C repro"
		}
	} else if reproducing {
		status = "reproducing"
	} else if nonReproducible {
		status = "non-reproducible"
	}
	return status
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, data interface{}) {
	buf := new(bytes.Buffer)
	if err := templ.Execute(buf, data); err != nil {
		log.Logf(0, "failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

func trimNewLines(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data
}

type UISummaryData struct {
	Name         string
	Revision     string
	RevisionLink string
	Expert       bool
	Stats        []UIStat
	Crashes      []*UICrashType
	Log          string
}

type UISyscallsData struct {
	Name  string
	Calls []UICallType
}

type UICrashType struct {
	Description string
	LastTime    time.Time
	Active      bool
	ID          string
	Count       int
	Triaged     string
	Strace      string
	Crashes     []*UICrash
}

type UICrash struct {
	Index  int
	Time   time.Time
	Active bool
	Log    string
	Report string
	Tag    string
}

type UIStat struct {
	Name  string
	Value string
	Hint  string
	Link  string
}

type UICallType struct {
	Name   string
	ID     *int
	Inputs int
	Cover  int
}

type UICorpus struct {
	Call     string
	RawCover bool
	Inputs   []*UIInput
}

type UIInput struct {
	Sig   string
	Short string
	Cover int
}

var summaryTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Name}} syzkaller</title>
	{{HEAD}}
</head>
<body>
<b>{{.Name }} syzkaller</b>
<a href='/config'>[config]</a>
<a href='{{.RevisionLink}}'>{{.Revision}}</a>
<a class="navigation_tab" href='expert_mode'>{{if .Expert}}disable{{else}}enable{{end}} expert mode</a>
<br>

<table class="list_table">
	<caption><a href='/stats'>Stats 📈</a></caption>
	{{range $s := $.Stats}}
	<tr>
		<td class="stat_name" title="{{$s.Hint}}">{{$s.Name}}</td>
		<td class="stat_value">
			{{if $s.Link}}
				<a href="{{$s.Link}}">{{$s.Value}}</a>
			{{else}}
				{{$s.Value}}
			{{end}}
		</td>
	</tr>
	{{end}}
</table>

<table class="list_table">
	<caption>Crashes:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Description', textSort)" href="#">Description</a></th>
		<th><a onclick="return sortTable(this, 'Count', numSort)" href="#">Count</a></th>
		<th><a onclick="return sortTable(this, 'Last Time', textSort, true)" href="#">Last Time</a></th>
		<th><a onclick="return sortTable(this, 'Report', textSort)" href="#">Report</a></th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td class="title"><a href="/crash?id={{$c.ID}}">{{$c.Description}}</a></td>
		<td class="stat {{if not $c.Active}}inactive{{end}}">{{$c.Count}}</td>
		<td class="time {{if not $c.Active}}inactive{{end}}">{{formatTime $c.LastTime}}</td>
		<td>
			{{if $c.Triaged}}
				<a href="/report?id={{$c.ID}}">{{$c.Triaged}}</a>
			{{end}}
			{{if $c.Strace}}
				<a href="/file?name={{$c.Strace}}">Strace</a>
			{{end}}
		</td>
	</tr>
	{{end}}
</table>

<b>Log:</b>
<br>
<textarea id="log_textarea" readonly rows="20" wrap=off>
{{.Log}}
</textarea>
<script>
	var textarea = document.getElementById("log_textarea");
	textarea.scrollTop = textarea.scrollHeight;
</script>
</body></html>
`)

var syscallsTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Per-syscall coverage:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Syscall', textSort)" href="#">Syscall</a></th>
		<th><a onclick="return sortTable(this, 'Inputs', numSort)" href="#">Inputs</a></th>
		<th><a onclick="return sortTable(this, 'Coverage', numSort)" href="#">Coverage</a></th>
		<th>Prio</th>
	</tr>
	{{range $c := $.Calls}}
	<tr>
		<td>{{$c.Name}}{{if $c.ID }} [{{$c.ID}}]{{end}}</td>
		<td><a href='/corpus?call={{$c.Name}}'>{{$c.Inputs}}</a></td>
		<td><a href='/cover?call={{$c.Name}}'>{{$c.Cover}}</a></td>
		<td><a href='/prio?call={{$c.Name}}'>prio</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var crashTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Description}}</title>
	{{HEAD}}
</head>
<body>
<b>{{.Description}}</b>

{{if .Triaged}}
Report: <a href="/report?id={{.ID}}">{{.Triaged}}</a>
{{end}}

<table class="list_table">
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
		<td>
			{{if $c.Report}}
				<a href="/file?name={{$c.Report}}">report</a></td>
			{{end}}
		</td>
		<td class="time {{if not $c.Active}}inactive{{end}}">{{formatTime $c.Time}}</td>
		<td class="tag {{if not $c.Active}}inactive{{end}}" title="{{$c.Tag}}">{{formatTagHash $c.Tag}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

var corpusTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller corpus</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Corpus{{if $.Call}} for {{$.Call}}{{end}}:</caption>
	<tr>
		<th>Coverage</th>
		<th>Program</th>
	</tr>
	{{range $inp := $.Inputs}}
	<tr>
		<td>
			<a href='/cover?input={{$inp.Sig}}'>{{$inp.Cover}}</a>
	{{if $.RawCover}}
		/ <a href="/debuginput?sig={{$inp.Sig}}">[raw]</a>
	{{end}}
		</td>
		<td><a href="/input?sig={{$inp.Sig}}">{{$inp.Short}}</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIPrioData struct {
	Call  string
	Prios []UIPrio
}

type UIPrio struct {
	Call string
	Prio int32
}

var prioTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller priorities</title>
	{{HEAD}}
</head>
<body>
<table class="list_table">
	<caption>Priorities for {{$.Call}}:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Prio', floatSort)" href="#">Prio</a></th>
		<th><a onclick="return sortTable(this, 'Call', textSort)" href="#">Call</a></th>
	</tr>
	{{range $p := $.Prios}}
	<tr>
		<td>{{printf "%5v" $p.Prio}}</td>
		<td><a href='/prio?call={{$p.Call}}'>{{$p.Call}}</a></td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIFallbackCoverData struct {
	Calls []UIFallbackCall
}

type UIFallbackCall struct {
	Name       string
	Successful int
	Errnos     []int
}

var fallbackCoverTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller coverage</title>
	{{HEAD}}
</head>
<body>
<table class="list_table">
	<tr>
		<th>Call</th>
		<th>Successful</th>
		<th>Errnos</th>
	</tr>
	{{range $c := $.Calls}}
	<tr>
		<td>{{$c.Name}}</td>
		<td>{{if $c.Successful}}{{$c.Successful}}{{end}}</td>
		<td>{{range $e := $c.Errnos}}{{$e}}&nbsp;{{end}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)

type UIRawCallCover struct {
	Sig       string
	Call      string
	UpdateIDs []int
}

var rawCoverTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller raw cover</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>Raw cover</caption>
	<tr>
		<th>Line</th>
		<th>Links</th>
	</tr>
	{{range $line := .}}
	<tr>
		<td>{{$line.Call}}</td>
		<td>
		{{range $id := $line.UpdateIDs}}
		<a href="/rawcover?input={{$line.Sig}}&update_id={{$id}}">[{{$id}}]</a>
		{{end}}
</td>
	</tr>
	{{end}}
</table>
</body></html>
`)
