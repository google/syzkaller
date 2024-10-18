// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CoverageInfo struct {
	Modules         []*vminfo.KernelModule
	ReportGenerator *ReportGeneratorWrapper
	CoverFilter     map[uint64]struct{}
}

type HTTPServer struct {
	// To be set once.
	Cfg        *mgrconfig.Config
	StartTime  time.Time
	Corpus     *corpus.Corpus
	CrashStore *CrashStore

	// Set dynamically.
	Fuzzer          atomic.Pointer[fuzzer.Fuzzer]
	Cover           atomic.Pointer[CoverageInfo]
	ReproLoop       atomic.Pointer[ReproLoop]
	Pools           sync.Map     // string => dispatcher.Pool[*vm.Instance]
	EnabledSyscalls atomic.Value // map[*prog.Syscall]bool

	// Internal state.
	expertMode bool
}

func (serv *HTTPServer) Serve() {
	handle := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		http.Handle(pattern, handlers.CompressHandler(http.HandlerFunc(handler)))
	}
	handle("/", serv.httpSummary)
	handle("/config", serv.httpConfig)
	handle("/expert_mode", serv.httpExpertMode)
	handle("/stats", serv.httpStats)
	handle("/vms", serv.httpVMs)
	handle("/vm", serv.httpVM)
	handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP)
	handle("/syscalls", serv.httpSyscalls)
	handle("/corpus", serv.httpCorpus)
	handle("/corpus.db", serv.httpDownloadCorpus)
	handle("/crash", serv.httpCrash)
	handle("/cover", serv.httpCover)
	handle("/subsystemcover", serv.httpSubsystemCover)
	handle("/modulecover", serv.httpModuleCover)
	handle("/prio", serv.httpPrio)
	handle("/file", serv.httpFile)
	handle("/report", serv.httpReport)
	handle("/rawcover", serv.httpRawCover)
	handle("/rawcoverfiles", serv.httpRawCoverFiles)
	handle("/filterpcs", serv.httpFilterPCs)
	handle("/funccover", serv.httpFuncCover)
	handle("/filecover", serv.httpFileCover)
	handle("/input", serv.httpInput)
	handle("/debuginput", serv.httpDebugInput)
	handle("/modules", serv.modulesInfo)
	handle("/jobs", serv.httpJobs)
	// Browsers like to request this, without special handler this goes to / handler.
	handle("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	log.Logf(0, "serving http on http://%v", serv.Cfg.HTTP)
	err := http.ListenAndServe(serv.Cfg.HTTP, nil)
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", serv.Cfg.HTTP, err)
	}
}

func (serv *HTTPServer) httpSummary(w http.ResponseWriter, r *http.Request) {
	revision, link := revisionAndLink()
	data := &UISummaryData{
		Name:         serv.Cfg.Name,
		Revision:     revision,
		RevisionLink: link,
		Expert:       serv.expertMode,
		Log:          log.CachedLogOutput(),
	}

	level := stat.Simple
	if serv.expertMode {
		level = stat.All
	}
	for _, stat := range stat.Collect(level) {
		data.Stats = append(data.Stats, UIStat{
			Name:  stat.Name,
			Value: stat.Value,
			Hint:  stat.Desc,
			Link:  stat.Link,
		})
	}

	var err error
	if data.Crashes, err = serv.collectCrashes(serv.Cfg.Workdir); err != nil {
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

func (serv *HTTPServer) httpConfig(w http.ResponseWriter, r *http.Request) {
	data, err := json.MarshalIndent(serv.Cfg, "", "\t")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode json: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (serv *HTTPServer) httpExpertMode(w http.ResponseWriter, r *http.Request) {
	serv.expertMode = !serv.expertMode
	http.Redirect(w, r, "/", http.StatusFound)
}

func (serv *HTTPServer) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	var calls map[string]*corpus.CallCov
	if obj := serv.EnabledSyscalls.Load(); obj != nil {
		calls = serv.Corpus.CallCover()
		// Add enabled, but not yet covered calls.
		for call := range obj.(map[*prog.Syscall]bool) {
			if calls[call.Name] == nil {
				calls[call.Name] = new(corpus.CallCov)
			}
		}
	}
	data := &UISyscallsData{
		Name: serv.Cfg.Name,
	}
	for c, cc := range calls {
		var syscallID *int
		if syscall, ok := serv.Cfg.Target.SyscallMap[c]; ok {
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

func (serv *HTTPServer) httpStats(w http.ResponseWriter, r *http.Request) {
	executeTemplate(w, pages.StatsTemplate, stat.RenderGraphs())
}

const DefaultPool = ""

func (serv *HTTPServer) httpVMs(w http.ResponseWriter, r *http.Request) {
	poolObj, ok := serv.Pools.Load(r.FormValue("pool"))
	if !ok {
		http.Error(w, "no such VM pool is known (yet)", http.StatusInternalServerError)
		return
	}
	pool := poolObj.(*dispatcher.Pool[*vm.Instance])
	data := &UIVMData{
		Name: serv.Cfg.Name,
	}
	// TODO: we could also query vmLoop for VMs that are idle (waiting to start reproducing),
	// and query the exact bug that is being reproduced by a VM.
	for id, state := range pool.State() {
		name := fmt.Sprintf("#%d", id)
		info := UIVMInfo{
			Name:  name,
			State: "unknown",
			Since: time.Since(state.LastUpdate),
		}
		switch state.State {
		case dispatcher.StateOffline:
			info.State = "offline"
		case dispatcher.StateBooting:
			info.State = "booting"
		case dispatcher.StateWaiting:
			info.State = "waiting"
		case dispatcher.StateRunning:
			info.State = "running: " + state.Status
		}
		if state.Reserved {
			info.State = "[reserved] " + info.State
		}
		if state.MachineInfo != nil {
			info.MachineInfo = fmt.Sprintf("/vm?type=machine-info&id=%d", id)
		}
		if state.DetailedStatus != nil {
			info.DetailedStatus = fmt.Sprintf("/vm?type=detailed-status&id=%v", id)
		}
		data.VMs = append(data.VMs, info)
	}
	executeTemplate(w, vmsTemplate, data)
}

func (serv *HTTPServer) httpVM(w http.ResponseWriter, r *http.Request) {
	poolObj, ok := serv.Pools.Load(r.FormValue("pool"))
	if !ok {
		http.Error(w, "no such VM pool is known (yet)", http.StatusInternalServerError)
		return
	}
	pool := poolObj.(*dispatcher.Pool[*vm.Instance])

	w.Header().Set("Content-Type", ctTextPlain)
	id, err := strconv.Atoi(r.FormValue("id"))
	infos := pool.State()
	if err != nil || id < 0 || id >= len(infos) {
		http.Error(w, "invalid instance id", http.StatusBadRequest)
		return
	}
	info := infos[id]
	switch r.FormValue("type") {
	case "machine-info":
		if info.MachineInfo != nil {
			w.Write(info.MachineInfo())
		}
	case "detailed-status":
		if info.DetailedStatus != nil {
			w.Write(info.DetailedStatus())
		}
	default:
		w.Write([]byte("unknown info type"))
	}
}

func makeUICrashType(info *BugInfo, startTime time.Time, repros map[string]bool) *UICrashType {
	var crashes []*UICrash
	for _, crash := range info.Crashes {
		crashes = append(crashes, &UICrash{
			CrashInfo: crash,
			Active:    crash.Time.After(startTime),
		})
	}
	triaged := reproStatus(info.HasRepro, info.HasCRepro, repros[info.Title],
		info.ReproAttempts >= MaxReproAttempts)
	return &UICrashType{
		Description: info.Title,
		LastTime:    info.LastTime,
		Active:      info.LastTime.After(startTime),
		ID:          info.ID,
		Count:       len(info.Crashes),
		Triaged:     triaged,
		Strace:      info.StraceFile,
		Crashes:     crashes,
	}
}

var crashIDRe = regexp.MustCompile(`^\w+$`)

func (serv *HTTPServer) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	if !crashIDRe.MatchString(crashID) {
		http.Error(w, "invalid crash ID", http.StatusBadRequest)
		return
	}
	info, err := serv.CrashStore.BugInfo(crashID, true)
	if err != nil {
		http.Error(w, "failed to read crash info", http.StatusInternalServerError)
		return
	}
	crash := makeUICrashType(info, serv.StartTime, nil)
	executeTemplate(w, crashTemplate, crash)
}

func (serv *HTTPServer) httpCorpus(w http.ResponseWriter, r *http.Request) {
	data := UICorpus{
		Call:     r.FormValue("call"),
		RawCover: serv.Cfg.RawCover,
	}
	for _, inp := range serv.Corpus.Items() {
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

func (serv *HTTPServer) httpDownloadCorpus(w http.ResponseWriter, r *http.Request) {
	corpus := filepath.Join(serv.Cfg.Workdir, "corpus.db")
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
	DoSubsystemCover
	DoModuleCover
	DoFuncCover
	DoFileCover
	DoRawCoverFiles
	DoRawCover
	DoFilterPCs
	DoCoverJSONL
)

func (serv *HTTPServer) httpCover(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		serv.httpCoverFallback(w, r)
		return
	}
	if r.FormValue("jsonl") == "1" {
		serv.httpCoverCover(w, r, DoCoverJSONL)
		return
	}
	serv.httpCoverCover(w, r, DoHTML)
}

func (serv *HTTPServer) httpSubsystemCover(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		serv.httpCoverFallback(w, r)
		return
	}
	serv.httpCoverCover(w, r, DoSubsystemCover)
}

func (serv *HTTPServer) httpModuleCover(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		serv.httpCoverFallback(w, r)
		return
	}
	serv.httpCoverCover(w, r, DoModuleCover)
}

const ctTextPlain = "text/plain; charset=utf-8"
const ctApplicationJSON = "application/json"

func (serv *HTTPServer) httpCoverCover(w http.ResponseWriter, r *http.Request, funcFlag int) {
	if !serv.Cfg.Cover {
		http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		return
	}

	coverInfo := serv.Cover.Load()
	if coverInfo == nil {
		http.Error(w, "coverage is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}

	rg, err := coverInfo.ReportGenerator.Get()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}

	if r.FormValue("flush") != "" {
		defer func() {
			coverInfo.ReportGenerator.Reset()
			debug.FreeOSMemory()
		}()
	}

	var progs []cover.Prog
	if sig := r.FormValue("input"); sig != "" {
		inp := serv.Corpus.Item(sig)
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
				Data: string(inp.Prog.Serialize()),
				PCs:  CoverToPCs(serv.Cfg, inp.Updates[updateID].RawCover),
			})
		} else {
			progs = append(progs, cover.Prog{
				Sig:  sig,
				Data: string(inp.Prog.Serialize()),
				PCs:  CoverToPCs(serv.Cfg, inp.Cover),
			})
		}
	} else {
		call := r.FormValue("call")
		for _, inp := range serv.Corpus.Items() {
			if call != "" && call != inp.StringCall() {
				continue
			}
			progs = append(progs, cover.Prog{
				Sig:  inp.Sig,
				Data: string(inp.Prog.Serialize()),
				PCs:  CoverToPCs(serv.Cfg, inp.Cover),
			})
		}
	}

	var coverFilter map[uint64]struct{}
	if r.FormValue("filter") != "" || funcFlag == DoFilterPCs {
		if coverInfo.CoverFilter == nil {
			http.Error(w, "cover is not filtered in config", http.StatusInternalServerError)
			return
		}
		coverFilter = coverInfo.CoverFilter
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
		DoHTML:           {rg.DoHTML, ""},
		DoSubsystemCover: {rg.DoSubsystemCover, ""},
		DoModuleCover:    {rg.DoModuleCover, ""},
		DoFuncCover:      {rg.DoFuncCover, ctTextPlain},
		DoFileCover:      {rg.DoFileCover, ctTextPlain},
		DoRawCoverFiles:  {rg.DoRawCoverFiles, ctTextPlain},
		DoRawCover:       {rg.DoRawCover, ctTextPlain},
		DoFilterPCs:      {rg.DoFilterPCs, ctTextPlain},
		DoCoverJSONL:     {rg.DoCoverJSONL, ctApplicationJSON},
	}

	if ct := flagToFunc[funcFlag].contentType; ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	if err := flagToFunc[funcFlag].Do(w, params); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
}

func (serv *HTTPServer) httpCoverFallback(w http.ResponseWriter, r *http.Request) {
	calls := make(map[int][]int)
	for s := range serv.Corpus.Signal() {
		id, errno := prog.DecodeFallbackSignal(uint64(s))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{}
	if obj := serv.EnabledSyscalls.Load(); obj != nil {
		for call := range obj.(map[*prog.Syscall]bool) {
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
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, fallbackCoverTemplate, data)
}

func (serv *HTTPServer) httpFuncCover(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoFuncCover)
}

func (serv *HTTPServer) httpFileCover(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoFileCover)
}

func (serv *HTTPServer) httpPrio(w http.ResponseWriter, r *http.Request) {
	callName := r.FormValue("call")
	call := serv.Cfg.Target.SyscallMap[callName]
	if call == nil {
		http.Error(w, fmt.Sprintf("unknown call: %v", callName), http.StatusInternalServerError)
		return
	}

	var corpus []*prog.Prog
	for _, inp := range serv.Corpus.Items() {
		corpus = append(corpus, inp.Prog)
	}
	prios := serv.Cfg.Target.CalculatePriorities(corpus)

	data := &UIPrioData{Call: callName}
	for i, p := range prios[call.ID] {
		data.Prios = append(data.Prios, UIPrio{serv.Cfg.Target.Syscalls[i].Name, p})
	}
	sort.Slice(data.Prios, func(i, j int) bool {
		return data.Prios[i].Prio > data.Prios[j].Prio
	})
	executeTemplate(w, prioTemplate, data)
}

func (serv *HTTPServer) httpFile(w http.ResponseWriter, r *http.Request) {
	file := filepath.Clean(r.FormValue("name"))
	if !strings.HasPrefix(file, "crashes/") && !strings.HasPrefix(file, "corpus/") {
		http.Error(w, "oh, oh, oh!", http.StatusInternalServerError)
		return
	}
	file = filepath.Join(serv.Cfg.Workdir, file)
	f, err := os.Open(file)
	if err != nil {
		http.Error(w, "failed to open the file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, f)
}

func (serv *HTTPServer) httpInput(w http.ResponseWriter, r *http.Request) {
	inp := serv.Corpus.Item(r.FormValue("sig"))
	if inp == nil {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.Prog.Serialize())
}

func (serv *HTTPServer) httpDebugInput(w http.ResponseWriter, r *http.Request) {
	inp := serv.Corpus.Item(r.FormValue("sig"))
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
	for pos, line := range strings.Split(string(inp.Prog.Serialize()), "\n") {
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

func (serv *HTTPServer) modulesInfo(w http.ResponseWriter, r *http.Request) {
	var modules []*vminfo.KernelModule
	if obj := serv.Cover.Load(); obj != nil {
		modules = obj.Modules
	} else {
		http.Error(w, "info is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}
	jsonModules, err := json.MarshalIndent(modules, "", "\t")
	if err != nil {
		fmt.Fprintf(w, "unable to create JSON modules info: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonModules)
}

var alphaNumRegExp = regexp.MustCompile(`^[a-zA-Z0-9]*$`)

func isAlphanumeric(s string) bool {
	return alphaNumRegExp.MatchString(s)
}

func (serv *HTTPServer) httpReport(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	if !isAlphanumeric(crashID) {
		http.Error(w, "wrong id", http.StatusBadRequest)
		return
	}

	info, err := serv.CrashStore.Report(crashID)
	if err != nil {
		http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	commitDesc := ""
	if info.Tag != "" {
		commitDesc = fmt.Sprintf(" on commit %s.", info.Tag)
	}
	fmt.Fprintf(w, "Syzkaller hit '%s' bug%s.\n\n", info.Title, commitDesc)
	if len(info.Report) != 0 {
		fmt.Fprintf(w, "%s\n\n", info.Report)
	}
	if len(info.Prog) == 0 && len(info.CProg) == 0 {
		fmt.Fprintf(w, "The bug is not reproducible.\n")
	} else {
		fmt.Fprintf(w, "Syzkaller reproducer:\n%s\n\n", info.Prog)
		if len(info.CProg) != 0 {
			fmt.Fprintf(w, "C reproducer:\n%s\n\n", info.CProg)
		}
	}
}

func (serv *HTTPServer) httpRawCover(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoRawCover)
}

func (serv *HTTPServer) httpRawCoverFiles(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoRawCoverFiles)
}

func (serv *HTTPServer) httpFilterPCs(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoFilterPCs)
}

func (serv *HTTPServer) collectCrashes(workdir string) ([]*UICrashType, error) {
	var repros map[string]bool
	if reproLoop := serv.ReproLoop.Load(); reproLoop != nil {
		repros = reproLoop.Reproducing()
	}
	list, err := serv.CrashStore.BugList()
	if err != nil {
		return nil, err
	}
	var ret []*UICrashType
	for _, info := range list {
		ret = append(ret, makeUICrashType(info, serv.StartTime, repros))
	}
	return ret, nil
}

func (serv *HTTPServer) httpJobs(w http.ResponseWriter, r *http.Request) {
	var list []*fuzzer.JobInfo
	if fuzzer := serv.Fuzzer.Load(); fuzzer != nil {
		list = fuzzer.RunningJobs()
	}
	if key := r.FormValue("id"); key != "" {
		for _, item := range list {
			if item.ID() == key {
				w.Write(item.Bytes())
				return
			}
		}
		http.Error(w, "invalid job id (the job has likely already finished)", http.StatusBadRequest)
		return
	}
	jobType := r.FormValue("type")
	data := UIJobList{
		Title: fmt.Sprintf("%s jobs", jobType),
	}
	switch jobType {
	case "triage":
	case "smash":
	case "hints":
	default:
		http.Error(w, "unknown job type", http.StatusBadRequest)
		return
	}
	for _, item := range list {
		if item.Type != jobType {
			continue
		}
		data.Jobs = append(data.Jobs, UIJobInfo{
			ID:    item.ID(),
			Short: item.Name,
			Execs: item.Execs.Load(),
			Calls: strings.Join(item.Calls, ", "),
		})
	}
	sort.Slice(data.Jobs, func(i, j int) bool {
		a, b := data.Jobs[i], data.Jobs[j]
		return a.Short < b.Short
	})
	executeTemplate(w, jobListTemplate, data)
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

type UISummaryData struct {
	Name         string
	Revision     string
	RevisionLink string
	Expert       bool
	Stats        []UIStat
	Crashes      []*UICrashType
	Log          string
}

type UIVMData struct {
	Name string
	VMs  []UIVMInfo
}

type UIVMInfo struct {
	Name           string
	State          string
	Since          time.Duration
	MachineInfo    string
	DetailedStatus string
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
	*CrashInfo
	Active bool
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

var vmsTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>

<table class="list_table">
	<caption>VM Info:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Name', textSort)" href="#">Name</a></th>
		<th><a onclick="return sortTable(this, 'State', textSort)" href="#">State</a></th>
		<th><a onclick="return sortTable(this, 'Since', timeSort)" href="#">Since</a></th>
		<th><a onclick="return sortTable(this, 'Machine Info', timeSort)" href="#">Machine Info</a></th>
		<th><a onclick="return sortTable(this, 'Status', timeSort)" href="#">Status</a></th>
	</tr>
	{{range $vm := $.VMs}}
	<tr>
		<td>{{$vm.Name}}</td>
		<td>{{$vm.State}}</td>
		<td>{{formatDuration $vm.Since}}</td>
		<td>{{optlink $vm.MachineInfo "info"}}</td>
		<td>{{optlink $vm.DetailedStatus "status"}}</td>
	</tr>
	{{end}}
</table>
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

type UIJobList struct {
	Title string
	Jobs  []UIJobInfo
}

type UIJobInfo struct {
	ID    string
	Short string
	Calls string
	Execs int32
}

var jobListTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>{{.Title}}</title>
	{{HEAD}}
<style>
table td {
	max-width: 600pt;
	word-break: break-all;
	overflow-wrap: break-word;
	white-space: normal;
}
</style>
</head>
<body>

<table class="list_table">
	<caption>{{.Title}} ({{len .Jobs}}):</caption>
	<tr>
		<th>Program</th>
		<th>Calls</th>
		<th>Execs</th>
	</tr>
	{{range $job := $.Jobs}}
	<tr>
		<td><a href='/jobs?id={{$job.ID}}'>{{$job.Short}}</a></td>
		<td>{{$job.Calls}}</td>
		<td>{{$job.Execs}}</td>
	</tr>
	{{end}}
</table>
</body></html>
`)
