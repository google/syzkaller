// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bytes"
	"context"
	"embed"
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
	// To be set before calling Serve.
	Cfg         *mgrconfig.Config
	StartTime   time.Time
	CrashStore  *CrashStore
	DiffStore   *DiffFuzzerStore
	ReproLoop   *ReproLoop
	Pool        *vm.Dispatcher
	Pools       map[string]*vm.Dispatcher
	TogglePause func(paused bool)

	// Can be set dynamically after calling Serve.
	Corpus          atomic.Pointer[corpus.Corpus]
	Fuzzer          atomic.Pointer[fuzzer.Fuzzer]
	Cover           atomic.Pointer[CoverageInfo]
	EnabledSyscalls atomic.Value // map[*prog.Syscall]bool

	// Internal state.
	expertMode bool
	paused     bool
}

func (serv *HTTPServer) Serve(ctx context.Context) error {
	if serv.Cfg.HTTP == "" {
		return fmt.Errorf("starting a disabled HTTP server")
	}
	if serv.Pool != nil {
		serv.Pools = map[string]*vm.Dispatcher{"": serv.Pool}
	}
	handle := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		http.Handle(pattern, handlers.CompressHandler(http.HandlerFunc(handler)))
	}
	// keep-sorted start
	handle("/", serv.httpMain)
	handle("/action", serv.httpAction)
	handle("/addcandidate", serv.httpAddCandidate)
	handle("/config", serv.httpConfig)
	handle("/corpus", serv.httpCorpus)
	handle("/corpus.db", serv.httpDownloadCorpus)
	handle("/cover", serv.httpCover)
	handle("/coverprogs", serv.httpPrograms)
	handle("/debuginput", serv.httpDebugInput)
	handle("/file", serv.httpFile)
	handle("/filecover", serv.httpFileCover)
	handle("/filterpcs", serv.httpFilterPCs)
	handle("/funccover", serv.httpFuncCover)
	handle("/input", serv.httpInput)
	handle("/jobs", serv.httpJobs)
	handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP)
	handle("/modulecover", serv.httpModuleCover)
	handle("/modules", serv.modulesInfo)
	handle("/prio", serv.httpPrio)
	handle("/rawcover", serv.httpRawCover)
	handle("/rawcoverfiles", serv.httpRawCoverFiles)
	handle("/stats", serv.httpStats)
	handle("/subsystemcover", serv.httpSubsystemCover)
	handle("/syscalls", serv.httpSyscalls)
	handle("/vm", serv.httpVM)
	handle("/vms", serv.httpVMs)
	// keep-sorted end
	if serv.CrashStore != nil {
		handle("/crash", serv.httpCrash)
		handle("/report", serv.httpReport)
	}
	// Browsers like to request this, without special handler this goes to / handler.
	handle("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	log.Logf(0, "serving http on http://%v", serv.Cfg.HTTP)
	server := &http.Server{Addr: serv.Cfg.HTTP}
	go func() {
		// The http server package unfortunately does not natively take a context.Context.
		// Let's emulate it via server.Shutdown()
		<-ctx.Done()
		server.Close()
	}()

	err := server.ListenAndServe()
	if err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (serv *HTTPServer) httpAction(w http.ResponseWriter, r *http.Request) {
	switch r.FormValue("toggle") {
	case "expert":
		serv.expertMode = !serv.expertMode
	case "pause":
		if serv.TogglePause == nil {
			http.Error(w, "pause is not implemented", http.StatusNotImplemented)
			return
		}
		serv.paused = !serv.paused
		serv.TogglePause(serv.paused)
	}
	http.Redirect(w, r, r.FormValue("url"), http.StatusFound)
}

func (serv *HTTPServer) httpMain(w http.ResponseWriter, r *http.Request) {
	data := &UISummaryData{
		UIPageHeader: serv.pageHeader(r, "syzkaller"),
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
	if serv.CrashStore != nil {
		var err error
		if data.Crashes, err = serv.collectCrashes(serv.Cfg.Workdir); err != nil {
			http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
			return
		}
	}
	if serv.DiffStore != nil {
		data.PatchedOnly, data.AffectsBoth, data.InProgress = serv.collectDiffCrashes()
	}
	executeTemplate(w, mainTemplate, data)
}

func (serv *HTTPServer) httpConfig(w http.ResponseWriter, r *http.Request) {
	serv.jsonPage(w, r, "config", serv.Cfg)
}

func (serv *HTTPServer) jsonPage(w http.ResponseWriter, r *http.Request, title string, data any) {
	text, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode json: %v", err), http.StatusInternalServerError)
		return
	}
	serv.textPage(w, r, title, text)
}

func (serv *HTTPServer) textPage(w http.ResponseWriter, r *http.Request, title string, text []byte) {
	if r.FormValue("raw") != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(text)
		return
	}
	data := &UITextPage{
		UIPageHeader: serv.pageHeader(r, title),
		Text:         text,
	}
	executeTemplate(w, textTemplate, data)
}

func (serv *HTTPServer) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	var calls map[string]*corpus.CallCov
	total := make(map[string]int)
	fuzzerObj := serv.Fuzzer.Load()
	syscallsObj := serv.EnabledSyscalls.Load()
	corpusObj := serv.Corpus.Load()
	if corpusObj != nil && syscallsObj != nil {
		calls = corpusObj.CallCover()
		// Add enabled, but not yet covered calls.
		for call := range syscallsObj.(map[*prog.Syscall]bool) {
			if calls[call.Name] == nil {
				calls[call.Name] = new(corpus.CallCov)
			}
		}
		// Count number of programs that include each call.
		last := make(map[string]*prog.Prog)
		for _, inp := range corpusObj.Items() {
			for _, call := range inp.Prog.Calls {
				name := call.Meta.Name
				if last[name] != inp.Prog {
					total[name]++
				}
				last[name] = inp.Prog
			}
		}
	}
	data := &UISyscallsData{
		UIPageHeader: serv.pageHeader(r, "syscalls"),
	}
	for c, cc := range calls {
		var syscallID *int
		if syscall, ok := serv.Cfg.Target.SyscallMap[c]; ok {
			syscallID = &syscall.ID
		}
		coverOverflows, compsOverflows := 0, 0
		if fuzzerObj != nil {
			idx := len(serv.Cfg.Target.Syscalls)
			if c != prog.ExtraCallName {
				idx = serv.Cfg.Target.SyscallMap[c].ID
			}
			coverOverflows = int(fuzzerObj.Syscalls[idx].CoverOverflows.Load())
			compsOverflows = int(fuzzerObj.Syscalls[idx].CompsOverflows.Load())
		}
		data.Calls = append(data.Calls, UICallType{
			Name:           c,
			ID:             syscallID,
			Inputs:         cc.Count,
			Total:          total[c],
			Cover:          len(cc.Cover),
			CoverOverflows: coverOverflows,
			CompsOverflows: compsOverflows,
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, syscallsTemplate, data)
}

func (serv *HTTPServer) httpStats(w http.ResponseWriter, r *http.Request) {
	html, err := pages.StatsHTML()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := &UITextPage{
		UIPageHeader: serv.pageHeader(r, "stats"),
		HTML:         html,
	}
	executeTemplate(w, textTemplate, data)
}

func (serv *HTTPServer) httpVMs(w http.ResponseWriter, r *http.Request) {
	pool := serv.Pools[r.FormValue("pool")]
	if pool == nil {
		http.Error(w, "no such VM pool is known (yet)", http.StatusInternalServerError)
		return
	}
	data := &UIVMData{
		UIPageHeader: serv.pageHeader(r, "VMs"),
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
	pool := serv.Pools[r.FormValue("pool")]
	if pool == nil {
		http.Error(w, "no such VM pool is known (yet)", http.StatusInternalServerError)
		return
	}

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

func makeUICrashType(info *BugInfo, startTime time.Time, repros map[string]bool) UICrashType {
	var crashes []UICrash
	for _, crash := range info.Crashes {
		crashes = append(crashes, UICrash{
			CrashInfo: *crash,
			Active:    crash.Time.After(startTime),
		})
	}
	triaged := reproStatus(info.HasRepro, info.HasCRepro, repros[info.Title],
		info.ReproAttempts >= MaxReproAttempts)
	return UICrashType{
		Description:   info.Title,
		FirstTime:     info.FirstTime,
		LastTime:      info.LastTime,
		New:           info.FirstTime.After(startTime),
		Active:        info.LastTime.After(startTime),
		ID:            info.ID,
		Count:         len(info.Crashes),
		Triaged:       triaged,
		Strace:        info.StraceFile,
		Crashes:       crashes,
		ReproAttempts: info.ReproAttempts,
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
	data := UICrashPage{
		UIPageHeader: serv.pageHeader(r, info.Title),
		UICrashType:  makeUICrashType(info, serv.StartTime, nil),
	}
	executeTemplate(w, crashTemplate, data)
}

func (serv *HTTPServer) httpCorpus(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	data := UICorpusPage{
		UIPageHeader: serv.pageHeader(r, "corpus"),
		Call:         r.FormValue("call"),
		RawCover:     serv.Cfg.RawCover,
	}
	for _, inp := range corpus.Items() {
		if data.Call != "" && data.Call != inp.StringCall() {
			continue
		}
		data.Inputs = append(data.Inputs, UIInput{
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
	DoCoverPrograms
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

func (serv *HTTPServer) httpPrograms(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		return
	}
	if r.FormValue("jsonl") != "1" {
		http.Error(w, "only ?jsonl=1 param is supported", http.StatusBadRequest)
		return
	}
	serv.httpCoverCover(w, r, DoCoverPrograms)
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

	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
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
		inp := corpus.Item(sig)
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
		for _, inp := range corpus.Items() {
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
		DoCoverPrograms:  {rg.DoCoverPrograms, ctApplicationJSON},
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
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	calls := make(map[int][]int)
	for s := range corpus.Signal() {
		id, errno := prog.DecodeFallbackSignal(uint64(s))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{
		UIPageHeader: serv.pageHeader(r, "fallback coverage"),
	}
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
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}

	callName := r.FormValue("call")
	call := serv.Cfg.Target.SyscallMap[callName]
	if call == nil {
		http.Error(w, fmt.Sprintf("unknown call: %v", callName), http.StatusInternalServerError)
		return
	}

	var progs []*prog.Prog
	for _, inp := range corpus.Items() {
		progs = append(progs, inp.Prog)
	}

	var enabled map[*prog.Syscall]bool
	if obj := serv.EnabledSyscalls.Load(); obj != nil {
		enabled = obj.(map[*prog.Syscall]bool)
	}
	prios, generatable := serv.Cfg.Target.CalculatePriorities(progs, enabled)

	data := &UIPrioData{
		UIPageHeader: serv.pageHeader(r, "syscall priorities"),
		Call:         callName,
	}
	for i, p := range prios[call.ID] {
		syscall := serv.Cfg.Target.Syscalls[i]
		if !generatable[syscall] {
			continue
		}
		data.Prios = append(data.Prios, UIPrio{syscall.Name, p})
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
	data, err := os.ReadFile(filepath.Join(serv.Cfg.Workdir, file))
	if err != nil {
		http.Error(w, "failed to read the file", http.StatusInternalServerError)
		return
	}
	serv.textPage(w, r, "file", data)
}

func (serv *HTTPServer) httpInput(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	inp := corpus.Item(r.FormValue("sig"))
	if inp == nil {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.Prog.Serialize())
}

func (serv *HTTPServer) httpDebugInput(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	inp := corpus.Item(r.FormValue("sig"))
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
	var calls []UIRawCallCover
	for pos, line := range strings.Split(string(inp.Prog.Serialize()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		calls = append(calls, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      line,
			UpdateIDs: getIDs(pos),
		})
	}
	extraIDs := getIDs(-1)
	if len(extraIDs) > 0 {
		calls = append(calls, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      prog.ExtraCallName,
			UpdateIDs: extraIDs,
		})
	}
	data := UIRawCoverPage{
		UIPageHeader: serv.pageHeader(r, "raw coverage"),
		Calls:        calls,
	}
	executeTemplate(w, rawCoverTemplate, data)
}

func (serv *HTTPServer) modulesInfo(w http.ResponseWriter, r *http.Request) {
	cover := serv.Cover.Load()
	if cover == nil {
		http.Error(w, "info is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}
	serv.jsonPage(w, r, "modules", cover.Modules)
}

func (serv *HTTPServer) httpAddCandidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST method supported", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseMultipartForm(20 << 20)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form: %v", err), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to retrieve file from form-data: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read file: %v", err), http.StatusBadRequest)
		return
	}
	prog, err := ParseSeed(serv.Cfg.Target, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse seed: %v", err), http.StatusBadRequest)
		return
	}
	if !prog.OnlyContains(serv.Fuzzer.Load().Config.EnabledCalls) {
		http.Error(w, "contains disabled syscall", http.StatusBadRequest)
		return
	}
	var flags fuzzer.ProgFlags
	flags |= fuzzer.ProgMinimized
	flags |= fuzzer.ProgSmashed
	candidates := []fuzzer.Candidate{{
		Prog:  prog,
		Flags: flags,
	}}
	serv.Fuzzer.Load().AddCandidates(candidates)
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

func (serv *HTTPServer) collectDiffCrashes() (patchedOnly, both, inProgress *UIDiffTable) {
	for _, item := range serv.allDiffCrashes() {
		if item.PatchedOnly() {
			if patchedOnly == nil {
				patchedOnly = &UIDiffTable{Title: "Patched-only"}
			}
			patchedOnly.List = append(patchedOnly.List, item)
		} else if item.AffectsBoth() {
			if both == nil {
				both = &UIDiffTable{Title: "Affects both"}
			}
			both.List = append(both.List, item)
		} else {
			if inProgress == nil {
				inProgress = &UIDiffTable{Title: "In Progress"}
			}
			inProgress.List = append(inProgress.List, item)
		}
	}
	return
}

func (serv *HTTPServer) allDiffCrashes() []UIDiffBug {
	repros := serv.ReproLoop.Reproducing()
	var list []UIDiffBug
	for _, bug := range serv.DiffStore.List() {
		list = append(list, UIDiffBug{
			DiffBug:     bug,
			Reproducing: repros[bug.Title],
		})
	}
	sort.Slice(list, func(i, j int) bool {
		first, second := list[i], list[j]
		firstPatched, secondPatched := first.PatchedOnly(), second.PatchedOnly()
		if firstPatched != secondPatched {
			return firstPatched
		}
		return first.Title < second.Title
	})
	return list
}

func (serv *HTTPServer) collectCrashes(workdir string) ([]UICrashType, error) {
	list, err := serv.CrashStore.BugList()
	if err != nil {
		return nil, err
	}
	repros := serv.ReproLoop.Reproducing()
	var ret []UICrashType
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
		UIPageHeader: serv.pageHeader(r, fmt.Sprintf("%s jobs", jobType)),
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
	UIPageHeader
	Stats       []UIStat
	Crashes     []UICrashType
	PatchedOnly *UIDiffTable
	AffectsBoth *UIDiffTable
	InProgress  *UIDiffTable
	Log         string
}

type UIDiffTable struct {
	Title string
	List  []UIDiffBug
}

type UIVMData struct {
	UIPageHeader
	VMs []UIVMInfo
}

type UIVMInfo struct {
	Name           string
	State          string
	Since          time.Duration
	MachineInfo    string
	DetailedStatus string
}

type UISyscallsData struct {
	UIPageHeader
	Calls []UICallType
}

type UICrashPage struct {
	UIPageHeader
	UICrashType
}

type UICrashType struct {
	Description   string
	FirstTime     time.Time
	LastTime      time.Time
	New           bool // was first found in the current run
	Active        bool // was found in the current run
	ID            string
	Count         int
	Triaged       string
	Strace        string
	ReproAttempts int
	Crashes       []UICrash
}

type UICrash struct {
	CrashInfo
	Active bool
}

type UIDiffBug struct {
	DiffBug
	Reproducing bool
}

type UIStat struct {
	Name  string
	Value string
	Hint  string
	Link  string
}

type UICallType struct {
	Name           string
	ID             *int
	Inputs         int
	Total          int
	Cover          int
	CoverOverflows int
	CompsOverflows int
}

type UICorpusPage struct {
	UIPageHeader
	Call     string
	RawCover bool
	Inputs   []UIInput
}

type UIInput struct {
	Sig   string
	Short string
	Cover int
}

type UIPageHeader struct {
	PageTitle string
	// Relative page URL w/o GET parameters (e.g. "/stats").
	URLPath string
	// Relative page URL with GET parameters/fragment/etc (e.g. "/stats?foo=1#bar").
	CurrentURL string
	// syzkaller build git revision and link.
	GitRevision     string
	GitRevisionLink string
	ExpertMode      bool
	Paused          bool
}

func (serv *HTTPServer) pageHeader(r *http.Request, title string) UIPageHeader {
	revision, revisionLink := prog.GitRevisionBase, ""
	if len(revision) > 8 {
		revisionLink = vcs.LogLink(vcs.SyzkallerRepo, revision)
		revision = revision[:8]
	}
	url := r.URL
	url.Scheme = ""
	url.Host = ""
	url.User = nil
	return UIPageHeader{
		PageTitle:       title,
		URLPath:         r.URL.Path,
		CurrentURL:      url.String(),
		GitRevision:     revision,
		GitRevisionLink: revisionLink,
		ExpertMode:      serv.expertMode,
		Paused:          serv.paused,
	}
}

func createPage(name string, data any) *template.Template {
	templ := pages.Create(fmt.Sprintf(string(mustReadHTML("common")), mustReadHTML(name)))
	templTypes = append(templTypes, templType{
		templ: templ,
		data:  data,
	})
	return templ
}

type templType struct {
	templ *template.Template
	data  any
}

var templTypes []templType

type UIPrioData struct {
	UIPageHeader
	Call  string
	Prios []UIPrio
}

type UIPrio struct {
	Call string
	Prio int32
}

type UIFallbackCoverData struct {
	UIPageHeader
	Calls []UIFallbackCall
}

type UIFallbackCall struct {
	Name       string
	Successful int
	Errnos     []int
}

type UIRawCoverPage struct {
	UIPageHeader
	Calls []UIRawCallCover
}

type UIRawCallCover struct {
	Sig       string
	Call      string
	UpdateIDs []int
}

type UIJobList struct {
	UIPageHeader
	Jobs []UIJobInfo
}

type UIJobInfo struct {
	ID    string
	Short string
	Calls string
	Execs int32
}

type UITextPage struct {
	UIPageHeader
	Text []byte
	HTML template.HTML
}

var (
	mainTemplate          = createPage("main", UISummaryData{})
	syscallsTemplate      = createPage("syscalls", UISyscallsData{})
	vmsTemplate           = createPage("vms", UIVMData{})
	crashTemplate         = createPage("crash", UICrashPage{})
	corpusTemplate        = createPage("corpus", UICorpusPage{})
	prioTemplate          = createPage("prio", UIPrioData{})
	fallbackCoverTemplate = createPage("fallback_cover", UIFallbackCoverData{})
	rawCoverTemplate      = createPage("raw_cover", UIRawCoverPage{})
	jobListTemplate       = createPage("job_list", UIJobList{})
	textTemplate          = createPage("text", UITextPage{})
)

//go:embed html/*.html
var htmlFiles embed.FS

func mustReadHTML(name string) []byte {
	data, err := htmlFiles.ReadFile("html/" + name + ".html")
	if err != nil {
		panic(err)
	}
	return data
}
