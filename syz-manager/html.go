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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
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
	data := &UISummaryData{
		Name:  mgr.cfg.Name,
		Log:   log.CachedLogOutput(),
		Stats: mgr.collectStats(),
	}

	var err error
	if data.Crashes, err = mgr.collectCrashes(mgr.cfg.Workdir); err != nil {
		http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
		return
	}
	executeTemplate(w, summaryTemplate, data)
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
			Inputs: cc.count,
			Cover:  len(cc.cov),
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, syscallsTemplate, data)
}

func (mgr *Manager) collectStats() []UIStat {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	configName := mgr.cfg.Name
	if configName == "" {
		configName = "config"
	}
	rawStats := mgr.stats.all()
	head := prog.GitRevisionBase
	stats := []UIStat{
		{Name: "revision", Value: fmt.Sprint(head[:8]), Link: vcs.LogLink(vcs.SyzkallerRepo, head)},
		{Name: "config", Value: configName, Link: "/config"},
		{Name: "uptime", Value: fmt.Sprint(time.Since(mgr.startTime) / 1e9 * 1e9)},
		{Name: "fuzzing", Value: fmt.Sprint(mgr.fuzzingTime / 60e9 * 60e9)},
		{Name: "corpus", Value: fmt.Sprint(len(mgr.corpus)), Link: "/corpus"},
		{Name: "triage queue", Value: fmt.Sprint(len(mgr.candidates))},
		{Name: "signal", Value: fmt.Sprint(rawStats["signal"])},
		{Name: "coverage", Value: fmt.Sprint(rawStats["coverage"]), Link: "/cover"},
	}
	if mgr.coverFilter != nil {
		stats = append(stats, UIStat{
			Name: "filtered coverage",
			Value: fmt.Sprintf("%v / %v (%v%%)",
				rawStats["filtered coverage"], len(mgr.coverFilter),
				rawStats["filtered coverage"]*100/uint64(len(mgr.coverFilter))),
			Link: "/cover?filter=yes",
		})
	}
	delete(rawStats, "signal")
	delete(rawStats, "coverage")
	delete(rawStats, "filtered coverage")
	if mgr.checkResult != nil {
		stats = append(stats, UIStat{
			Name:  "syscalls",
			Value: fmt.Sprint(len(mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox])),
			Link:  "/syscalls",
		})
	}

	secs := uint64(1)
	if !mgr.firstConnect.IsZero() {
		secs = uint64(time.Since(mgr.firstConnect))/1e9 + 1
	}
	intStats := convertStats(rawStats, secs)
	sort.Slice(intStats, func(i, j int) bool {
		return intStats[i].Name < intStats[j].Name
	})
	stats = append(stats, intStats...)
	return stats
}

func convertStats(stats map[string]uint64, secs uint64) []UIStat {
	var intStats []UIStat
	for k, v := range stats {
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
	return intStats
}

func (mgr *Manager) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	crash := readCrash(mgr.cfg.Workdir, crashID, nil, mgr.startTime, true)
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
	for sig, inp := range mgr.corpus {
		if data.Call != "" && data.Call != inp.Call {
			continue
		}
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		data.Inputs = append(data.Inputs, &UIInput{
			Sig:   sig,
			Short: p.String(),
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
)

func (mgr *Manager) httpCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoHTML, true)
}

func (mgr *Manager) httpSubsystemCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoHTMLTable, true)
}

func (mgr *Manager) httpModuleCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoModuleCover, true)
}

func (mgr *Manager) httpCoverCover(w http.ResponseWriter, r *http.Request, funcFlag int, isHTMLCover bool) {
	if !mgr.cfg.Cover {
		if isHTMLCover {
			mgr.httpCoverFallback(w, r)
		} else {
			http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		}
		return
	}

	// Don't hold the mutex while creating report generator and generating the report,
	// these operations take lots of time.
	mgr.mu.Lock()
	initialized := mgr.modulesInitialized
	mgr.mu.Unlock()
	if !initialized {
		http.Error(w, "coverage is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}

	rg, err := getReportGenerator(mgr.cfg, mgr.modules)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}

	mgr.mu.Lock()
	var progs []cover.Prog
	if sig := r.FormValue("input"); sig != "" {
		inp := mgr.corpus[sig]
		if r.FormValue("update_id") != "" {
			updateID, err := strconv.Atoi(r.FormValue("update_id"))
			if err != nil || updateID < 0 || updateID >= len(inp.Updates) {
				http.Error(w, "bad call_id", http.StatusBadRequest)
			}
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog),
				PCs:  coverToPCs(rg, inp.Updates[updateID].RawCover),
			})
		} else {
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog),
				PCs:  coverToPCs(rg, inp.Cover),
			})
		}
	} else {
		call := r.FormValue("call")
		for sig, inp := range mgr.corpus {
			if call != "" && call != inp.Call {
				continue
			}
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog),
				PCs:  coverToPCs(rg, inp.Cover),
			})
		}
	}
	mgr.mu.Unlock()

	var coverFilter map[uint32]uint32
	if r.FormValue("filter") != "" {
		coverFilter = mgr.coverFilter
	}

	if funcFlag == DoRawCoverFiles {
		if err := rg.DoRawCoverFiles(w, progs, coverFilter); err != nil {
			http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
			return
		}
		runtime.GC()
		return
	} else if funcFlag == DoRawCover {
		rg.DoRawCover(w, progs, coverFilter)
		return
	} else if funcFlag == DoFilterPCs {
		rg.DoFilterPCs(w, progs, coverFilter)
		return
	}

	do := rg.DoHTML
	if funcFlag == DoHTMLTable {
		do = rg.DoHTMLTable
	} else if funcFlag == DoModuleCover {
		do = rg.DoModuleCover
	} else if funcFlag == DoCSV {
		do = rg.DoCSV
	} else if funcFlag == DoCSVFiles {
		do = rg.DoCSVFiles
	}

	if err := do(w, progs, coverFilter); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
	runtime.GC()
}

func (mgr *Manager) httpCoverFallback(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	var maxSignal signal.Signal
	for _, inp := range mgr.corpus {
		maxSignal.Merge(inp.Signal.Deserialize())
	}
	calls := make(map[int][]int)
	for s := range maxSignal {
		id, errno := prog.DecodeFallbackSignal(uint32(s))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{}
	for _, id := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		errnos := calls[id]
		sort.Ints(errnos)
		successful := 0
		for len(errnos) != 0 && errnos[0] == 0 {
			successful++
			errnos = errnos[1:]
		}
		data.Calls = append(data.Calls, UIFallbackCall{
			Name:       mgr.target.Syscalls[id].Name,
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
	mgr.httpCoverCover(w, r, DoCSV, false)
}

func (mgr *Manager) httpFileCover(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoCSVFiles, false)
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
	for _, inp := range mgr.corpus {
		p, err := mgr.target.Deserialize(inp.Prog, prog.NonStrict)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to deserialize program: %v", err), http.StatusInternalServerError)
			return
		}
		corpus = append(corpus, p)
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
	inp, ok := mgr.corpus[r.FormValue("sig")]
	if !ok {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.Prog)
}

func (mgr *Manager) httpDebugInput(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	inp, ok := mgr.corpus[r.FormValue("sig")]
	if !ok {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	getIDs := func(callID int) []int {
		ret := []int{}
		for id, update := range inp.Updates {
			if update.CallID == callID {
				ret = append(ret, id)
			}
		}
		return ret
	}
	data := []UIRawCallCover{}
	for pos, line := range strings.Split(string(inp.Prog), "\n") {
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

func (mgr *Manager) httpReport(w http.ResponseWriter, r *http.Request) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	crashID := r.FormValue("id")
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
	mgr.httpCoverCover(w, r, DoRawCover, false)
}

func (mgr *Manager) httpRawCoverFiles(w http.ResponseWriter, r *http.Request) {
	mgr.httpCoverCover(w, r, DoRawCoverFiles, false)
}

func (mgr *Manager) httpFilterPCs(w http.ResponseWriter, r *http.Request) {
	if mgr.coverFilter == nil {
		fmt.Fprintf(w, "cover is not filtered in config.\n")
		return
	}
	mgr.httpCoverCover(w, r, DoFilterPCs, false)
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
		crash := readCrash(workdir, dir, repros, mgr.startTime, false)
		if crash != nil {
			crashTypes = append(crashTypes, crash)
		}
	}
	sort.Slice(crashTypes, func(i, j int) bool {
		return strings.ToLower(crashTypes[i].Description) < strings.ToLower(crashTypes[j].Description)
	})
	return crashTypes, nil
}

func readCrash(workdir, dir string, repros map[string]bool, start time.Time, full bool) *UICrashType {
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
				crash.Active = crash.Time.After(start)
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
		Active:      modTime.After(start),
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
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>
<b>{{.Name }} syzkaller</b>
<br>

<table class="list_table">
	<caption>Stats:</caption>
	{{range $s := $.Stats}}
	<tr>
		<td class="stat_name">{{$s.Name}}</td>
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
