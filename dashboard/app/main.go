// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/memcache"
)

// This file contains web UI http handlers.

func initHTTPHandlers() {
	http.Handle("/", handlerWrapper(handleMain))
	http.Handle("/bug", handlerWrapper(handleBug))
	http.Handle("/text", handlerWrapper(handleText))
	http.Handle("/admin", handlerWrapper(handleAdmin))
	http.Handle("/x/.config", handlerWrapper(handleTextX(textKernelConfig)))
	http.Handle("/x/log.txt", handlerWrapper(handleTextX(textCrashLog)))
	http.Handle("/x/report.txt", handlerWrapper(handleTextX(textCrashReport)))
	http.Handle("/x/repro.syz", handlerWrapper(handleTextX(textReproSyz)))
	http.Handle("/x/repro.c", handlerWrapper(handleTextX(textReproC)))
	http.Handle("/x/patch.diff", handlerWrapper(handleTextX(textPatch)))
	http.Handle("/x/bisect.txt", handlerWrapper(handleTextX(textLog)))
	http.Handle("/x/error.txt", handlerWrapper(handleTextX(textError)))
	for ns := range config.Namespaces {
		http.Handle("/"+ns, handlerWrapper(handleMain))
		http.Handle("/"+ns+"/fixed", handlerWrapper(handleFixed))
		http.Handle("/"+ns+"/invalid", handlerWrapper(handleInvalid))
	}
}

type uiMainPage struct {
	Header         *uiHeader
	Now            time.Time
	Decommissioned bool
	Managers       []*uiManager
	Groups         []*uiBugGroup
}

type uiTerminalPage struct {
	Header *uiHeader
	Now    time.Time
	Bugs   *uiBugGroup
}

type uiAdminPage struct {
	Header        *uiHeader
	Log           []byte
	Managers      []*uiManager
	Jobs          *uiJobList
	MemcacheStats *memcache.Statistics
}

type uiManager struct {
	Now                   time.Time
	Namespace             string
	Name                  string
	Link                  string
	CoverLink             string
	CurrentBuild          *uiBuild
	FailedBuildBugLink    string
	FailedSyzBuildBugLink string
	LastActive            time.Time
	LastActiveBad         bool // highlight LastActive in red
	CurrentUpTime         time.Duration
	MaxCorpus             int64
	MaxCover              int64
	TotalFuzzingTime      time.Duration
	TotalCrashes          int64
	TotalExecs            int64
	TotalExecsBad         bool // highlight TotalExecs in red
}

type uiBuild struct {
	Time                time.Time
	SyzkallerCommit     string
	SyzkallerCommitLink string
	SyzkallerCommitDate time.Time
	KernelAlias         string
	KernelCommit        string
	KernelCommitLink    string
	KernelCommitTitle   string
	KernelCommitDate    time.Time
	KernelConfigLink    string
}

type uiCommit struct {
	Hash   string
	Title  string
	Link   string
	Author string
	CC     []string
	Date   time.Time
}

type uiBugPage struct {
	Header        *uiHeader
	Now           time.Time
	Bug           *uiBug
	BisectCause   *uiJob
	BisectFix     *uiJob
	DupOf         *uiBugGroup
	Dups          *uiBugGroup
	Similar       *uiBugGroup
	SampleReport  []byte
	Crashes       *uiCrashTable
	FixBisections *uiCrashTable
	TestPatchJobs *uiJobList
}

type uiBugGroup struct {
	Now           time.Time
	Caption       string
	Fragment      string
	Namespace     string
	ShowNamespace bool
	ShowPatch     bool
	ShowPatched   bool
	ShowStatus    bool
	ShowIndex     int
	Bugs          []*uiBug
}

type uiJobList struct {
	PerBug bool
	Jobs   []*uiJob
}

type uiBug struct {
	Namespace       string
	Title           string
	NumCrashes      int64
	NumCrashesBad   bool
	BisectCauseDone bool
	BisectFixDone   bool
	FirstTime       time.Time
	LastTime        time.Time
	ReportedTime    time.Time
	ClosedTime      time.Time
	ReproLevel      dashapi.ReproLevel
	ReportingIndex  int
	Status          string
	Link            string
	ExternalLink    string
	CreditEmail     string
	Commits         []*uiCommit
	PatchedOn       []string
	MissingOn       []string
	NumManagers     int
}

type uiCrash struct {
	Manager      string
	Time         time.Time
	Maintainers  string
	LogLink      string
	ReportLink   string
	ReproSyzLink string
	ReproCLink   string
	*uiBuild
}

type uiCrashTable struct {
	Crashes        []*uiCrash
	Caption        string
	HasMaintainers bool
}

type uiJob struct {
	Type            JobType
	Created         time.Time
	BugLink         string
	ExternalLink    string
	User            string
	Reporting       string
	Namespace       string
	Manager         string
	BugTitle        string
	BugID           string
	KernelAlias     string
	KernelCommit    string
	PatchLink       string
	Attempts        int
	Started         time.Time
	Finished        time.Time
	Duration        time.Duration
	CrashTitle      string
	CrashLogLink    string
	CrashReportLink string
	LogLink         string
	ErrorLink       string
	Commit          *uiCommit   // for conclusive bisection
	Commits         []*uiCommit // for inconclusive bisection
	Crash           *uiCrash
	Reported        bool
}

// handleMain serves main page.
func handleMain(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	accessLevel := accessLevel(c, r)
	managers, err := loadManagers(c, accessLevel, hdr.Namespace)
	if err != nil {
		return err
	}
	manager := r.FormValue("manager")
	groups, err := fetchNamespaceBugs(c, accessLevel, hdr.Namespace, manager)
	if err != nil {
		return err
	}
	data := &uiMainPage{
		Header:         hdr,
		Decommissioned: config.Namespaces[hdr.Namespace].Decommissioned,
		Now:            timeNow(c),
		Groups:         groups,
		Managers:       managers,
	}
	return serveTemplate(w, "main.html", data)
}

func handleFixed(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleTerminalBugList(c, w, r, &TerminalBug{
		Status:    BugStatusFixed,
		Subpage:   "/fixed",
		ShowPatch: true,
	})
}

func handleInvalid(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleTerminalBugList(c, w, r, &TerminalBug{
		Status:    BugStatusInvalid,
		Subpage:   "/invalid",
		ShowPatch: false,
	})
}

type TerminalBug struct {
	Status    int
	Subpage   string
	ShowPatch bool
}

func handleTerminalBugList(c context.Context, w http.ResponseWriter, r *http.Request, typ *TerminalBug) error {
	accessLevel := accessLevel(c, r)
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	hdr.Subpage = typ.Subpage
	manager := r.FormValue("manager")
	bugs, err := fetchTerminalBugs(c, accessLevel, hdr.Namespace, manager, typ)
	if err != nil {
		return err
	}
	data := &uiTerminalPage{
		Header: hdr,
		Now:    timeNow(c),
		Bugs:   bugs,
	}
	return serveTemplate(w, "terminal.html", data)
}

func handleAdmin(c context.Context, w http.ResponseWriter, r *http.Request) error {
	accessLevel := accessLevel(c, r)
	if accessLevel != AccessAdmin {
		return ErrAccess
	}
	switch action := r.FormValue("action"); action {
	case "":
	case "memcache_flush":
		if err := memcache.Flush(c); err != nil {
			return fmt.Errorf("failed to flush memcache: %v", err)
		}
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	memcacheStats, err := memcache.Stats(c)
	if err != nil {
		return err
	}
	managers, err := loadManagers(c, accessLevel, "")
	if err != nil {
		return err
	}
	errorLog, err := fetchErrorLogs(c)
	if err != nil {
		return err
	}
	jobs, err := loadRecentJobs(c)
	if err != nil {
		return err
	}
	data := &uiAdminPage{
		Header:        hdr,
		Log:           errorLog,
		Managers:      managers,
		Jobs:          &uiJobList{Jobs: jobs},
		MemcacheStats: memcacheStats,
	}
	return serveTemplate(w, "admin.html", data)
}

// handleBug serves page about a single bug (which is passed in id argument).
func handleBug(c context.Context, w http.ResponseWriter, r *http.Request) error {
	bug, err := findBugByID(c, r)
	if err != nil {
		return ErrDontLog{err}
	}
	accessLevel := accessLevel(c, r)
	if err := checkAccessLevel(c, r, bug.sanitizeAccess(accessLevel)); err != nil {
		return err
	}
	hdr, err := commonHeader(c, r, w, bug.Namespace)
	if err != nil {
		return err
	}
	state, err := loadReportingState(c)
	if err != nil {
		return err
	}
	managers, err := managerList(c, bug.Namespace)
	if err != nil {
		return err
	}
	var dupOf *uiBugGroup
	if bug.DupOf != "" {
		dup := new(Bug)
		if err := db.Get(c, db.NewKey(c, "Bug", bug.DupOf, 0, nil), dup); err != nil {
			return err
		}
		if accessLevel >= dup.sanitizeAccess(accessLevel) {
			dupOf = &uiBugGroup{
				Now:     timeNow(c),
				Caption: "Duplicate of",
				Bugs:    []*uiBug{createUIBug(c, dup, state, managers)},
			}
		}
	}
	uiBug := createUIBug(c, bug, state, managers)
	crashes, sampleReport, err := loadCrashesForBug(c, bug)
	if err != nil {
		return err
	}
	crashesTable := &uiCrashTable{
		Crashes: crashes,
		Caption: fmt.Sprintf("Crashes (%d)", bug.NumCrashes),
	}
	for _, crash := range crashesTable.Crashes {
		if crash.Maintainers != "" {
			crashesTable.HasMaintainers = true
			break
		}
	}
	dups, err := loadDupsForBug(c, r, bug, state, managers)
	if err != nil {
		return err
	}
	similar, err := loadSimilarBugs(c, r, bug, state)
	if err != nil {
		return err
	}
	var bisectCause *uiJob
	if bug.BisectCause > BisectPending {
		bisectCause, err = getUIJob(c, bug, JobBisectCause)
		if err != nil {
			return err
		}
	}
	var bisectFix *uiJob
	if bug.BisectFix > BisectPending {
		bisectFix, err = getUIJob(c, bug, JobBisectFix)
		if err != nil {
			return err
		}
	}
	testPatchJobs, err := loadTestPatchJobs(c, bug)
	if err != nil {
		return err
	}
	data := &uiBugPage{
		Header:       hdr,
		Now:          timeNow(c),
		Bug:          uiBug,
		BisectCause:  bisectCause,
		BisectFix:    bisectFix,
		DupOf:        dupOf,
		Dups:         dups,
		Similar:      similar,
		SampleReport: sampleReport,
		Crashes:      crashesTable,
		TestPatchJobs: &uiJobList{
			PerBug: true,
			Jobs:   testPatchJobs,
		},
	}
	// bug.BisectFix is set to BisectNot in two cases :
	// - no fix bisections have been performed on the bug
	// - fix bisection was performed but resulted in a crash on HEAD
	if bug.BisectFix == BisectNot {
		fixBisections, err := loadFixBisectionsForBug(c, bug)
		if err != nil {
			return err
		}
		if len(fixBisections) != 0 {
			data.FixBisections = &uiCrashTable{
				Crashes: fixBisections,
				Caption: "Fix bisection attempts",
			}
		}
	}
	return serveTemplate(w, "bug.html", data)
}

func findBugByID(c context.Context, r *http.Request) (*Bug, error) {
	if id := r.FormValue("id"); id != "" {
		bug := new(Bug)
		bugKey := db.NewKey(c, "Bug", id, 0, nil)
		err := db.Get(c, bugKey, bug)
		return bug, err
	}
	if extID := r.FormValue("extid"); extID != "" {
		bug, _, err := findBugByReportingID(c, extID)
		return bug, err
	}
	return nil, fmt.Errorf("mandatory parameter id/extid is missing")
}

func getUIJob(c context.Context, bug *Bug, jobType JobType) (*uiJob, error) {
	job, crash, jobKey, _, err := loadBisectJob(c, bug, jobType)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, bug.Namespace, crash.BuildID)
	if err != nil {
		return nil, err
	}
	return makeUIJob(job, jobKey, bug, crash, build), nil
}

// handleText serves plain text blobs (crash logs, reports, reproducers, etc).
func handleTextImpl(c context.Context, w http.ResponseWriter, r *http.Request, tag string) error {
	var id int64
	if x := r.FormValue("x"); x != "" {
		xid, err := strconv.ParseUint(x, 16, 64)
		if err != nil || xid == 0 {
			return ErrDontLog{fmt.Errorf("failed to parse text id: %v", err)}
		}
		id = int64(xid)
	} else {
		// Old link support, don't remove.
		xid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || xid == 0 {
			return ErrDontLog{fmt.Errorf("failed to parse text id: %v", err)}
		}
		id = xid
	}
	bug, crash, err := checkTextAccess(c, r, tag, id)
	if err != nil {
		return err
	}
	data, ns, err := getText(c, tag, id)
	if err != nil {
		if strings.Contains(err.Error(), "datastore: no such entity") {
			err = ErrDontLog{err}
		}
		return err
	}
	if err := checkAccessLevel(c, r, config.Namespaces[ns].AccessLevel); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Unfortunately filename does not work in chrome on linux due to:
	// https://bugs.chromium.org/p/chromium/issues/detail?id=608342
	w.Header().Set("Content-Disposition", "inline; filename="+textFilename(tag))
	augmentRepro(c, w, tag, bug, crash)
	w.Write(data)
	return nil
}

func augmentRepro(c context.Context, w http.ResponseWriter, tag string, bug *Bug, crash *Crash) {
	if tag == textReproSyz || tag == textReproC {
		// Users asked for the bug link in reproducers (in case you only saved the repro link).
		if bug != nil {
			prefix := "#"
			if tag == textReproC {
				prefix = "//"
			}
			fmt.Fprintf(w, "%v %v/bug?id=%v\n", prefix, appURL(c), bug.keyHash())
		}
	}
	if tag == textReproSyz {
		// Add link to documentation and repro opts for syzkaller reproducers.
		w.Write([]byte(syzReproPrefix))
		if crash != nil {
			fmt.Fprintf(w, "#%s\n", crash.ReproOpts)
		}
	}
}

func handleText(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleTextImpl(c, w, r, r.FormValue("tag"))
}

func handleTextX(tag string) contextHandler {
	return func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		return handleTextImpl(c, w, r, tag)
	}
}

func textFilename(tag string) string {
	switch tag {
	case textKernelConfig:
		return ".config"
	case textCrashLog:
		return "log.txt"
	case textCrashReport:
		return "report.txt"
	case textReproSyz:
		return "repro.syz"
	case textReproC:
		return "repro.c"
	case textPatch:
		return "patch.diff"
	case textLog:
		return "bisect.txt"
	case textError:
		return "error.txt"
	default:
		return "text.txt"
	}
}

func fetchNamespaceBugs(c context.Context, accessLevel AccessLevel, ns, manager string) ([]*uiBugGroup, error) {
	filter := func(query *db.Query) *db.Query {
		query = query.Filter("Namespace=", ns)
		if manager != "" {
			query = query.Filter("HappenedOn=", manager)
		}
		return query
	}
	bugs, _, err := loadAllBugs(c, filter)
	if err != nil {
		return nil, err
	}
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return nil, err
	}
	groups := make(map[int][]*uiBug)
	bugMap := make(map[string]*uiBug)
	var dups []*Bug
	for _, bug := range bugs {
		if bug.Status == BugStatusFixed || bug.Status == BugStatusInvalid {
			continue
		}
		if accessLevel < bug.sanitizeAccess(accessLevel) {
			continue
		}
		if bug.Status == BugStatusDup {
			dups = append(dups, bug)
			continue
		}
		uiBug := createUIBug(c, bug, state, managers)
		bugMap[bug.keyHash()] = uiBug
		id := uiBug.ReportingIndex
		if len(uiBug.Commits) != 0 {
			id = -1
		}
		groups[id] = append(groups[id], uiBug)
	}
	for _, dup := range dups {
		bug := bugMap[dup.DupOf]
		if bug == nil {
			continue // this can be an invalid bug which we filtered above
		}
		mergeUIBug(c, bug, dup)
	}
	cfg := config.Namespaces[ns]
	var uiGroups []*uiBugGroup
	for index, bugs := range groups {
		sort.Slice(bugs, func(i, j int) bool {
			if bugs[i].Namespace != bugs[j].Namespace {
				return bugs[i].Namespace < bugs[j].Namespace
			}
			if bugs[i].ClosedTime != bugs[j].ClosedTime {
				return bugs[i].ClosedTime.After(bugs[j].ClosedTime)
			}
			return bugs[i].ReportedTime.After(bugs[j].ReportedTime)
		})
		caption, fragment, showPatched := "", "", false
		switch index {
		case -1:
			caption, showPatched = "fix pending", true
			fragment = "pending"
		case len(cfg.Reporting) - 1:
			caption, showPatched = "open", false
			fragment = "open"
		default:
			reporting := &cfg.Reporting[index]
			caption, showPatched = reporting.DisplayTitle, false
			fragment = reporting.Name
		}
		uiGroups = append(uiGroups, &uiBugGroup{
			Now:         timeNow(c),
			Caption:     caption,
			Fragment:    fragment,
			Namespace:   ns,
			ShowPatched: showPatched,
			ShowIndex:   index,
			Bugs:        bugs,
		})
	}
	sort.Slice(uiGroups, func(i, j int) bool {
		return uiGroups[i].ShowIndex > uiGroups[j].ShowIndex
	})
	return uiGroups, nil
}

func fetchTerminalBugs(c context.Context, accessLevel AccessLevel,
	ns, manager string, typ *TerminalBug) (*uiBugGroup, error) {
	bugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		query = query.Filter("Namespace=", ns).
			Filter("Status=", typ.Status)
		if manager != "" {
			query = query.Filter("HappenedOn=", manager)
		}
		return query
	})
	if err != nil {
		return nil, err
	}
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return nil, err
	}
	res := &uiBugGroup{
		Now:       timeNow(c),
		ShowPatch: typ.ShowPatch,
		Namespace: ns,
	}
	for _, bug := range bugs {
		if accessLevel < bug.sanitizeAccess(accessLevel) {
			continue
		}
		res.Bugs = append(res.Bugs, createUIBug(c, bug, state, managers))
	}
	sort.Slice(res.Bugs, func(i, j int) bool {
		return res.Bugs[i].ClosedTime.After(res.Bugs[j].ClosedTime)
	})
	return res, nil
}

func loadDupsForBug(c context.Context, r *http.Request, bug *Bug, state *ReportingState, managers []string) (
	*uiBugGroup, error) {
	bugHash := bug.keyHash()
	var dups []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Status=", BugStatusDup).
		Filter("DupOf=", bugHash).
		GetAll(c, &dups)
	if err != nil {
		return nil, err
	}
	var results []*uiBug
	accessLevel := accessLevel(c, r)
	for _, dup := range dups {
		if accessLevel < dup.sanitizeAccess(accessLevel) {
			continue
		}
		results = append(results, createUIBug(c, dup, state, managers))
	}
	group := &uiBugGroup{
		Now:         timeNow(c),
		Caption:     "duplicates",
		ShowPatched: true,
		ShowStatus:  true,
		Bugs:        results,
	}
	return group, nil
}

func loadSimilarBugs(c context.Context, r *http.Request, bug *Bug, state *ReportingState) (*uiBugGroup, error) {
	var similar []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Title=", bug.Title).
		GetAll(c, &similar)
	if err != nil {
		return nil, err
	}
	managers := make(map[string][]string)
	var results []*uiBug
	accessLevel := accessLevel(c, r)
	domain := config.Namespaces[bug.Namespace].SimilarityDomain
	for _, similar := range similar {
		if accessLevel < similar.sanitizeAccess(accessLevel) {
			continue
		}
		if similar.Namespace == bug.Namespace && similar.Seq == bug.Seq {
			continue
		}
		if config.Namespaces[similar.Namespace].SimilarityDomain != domain {
			continue
		}
		if managers[similar.Namespace] == nil {
			mgrs, err := managerList(c, similar.Namespace)
			if err != nil {
				return nil, err
			}
			managers[similar.Namespace] = mgrs
		}
		results = append(results, createUIBug(c, similar, state, managers[similar.Namespace]))
	}
	group := &uiBugGroup{
		Now:           timeNow(c),
		Caption:       "similar bugs",
		ShowNamespace: true,
		ShowPatched:   true,
		ShowStatus:    true,
		Bugs:          results,
	}
	return group, nil
}

func createUIBug(c context.Context, bug *Bug, state *ReportingState, managers []string) *uiBug {
	reportingIdx, status, link := 0, "", ""
	var reported time.Time
	var err error
	if bug.Status == BugStatusOpen {
		_, _, _, _, reportingIdx, status, link, err = needReport(c, "", state, bug)
		reported = bug.Reporting[reportingIdx].Reported
		if err != nil {
			status = err.Error()
		}
		if status == "" {
			status = "???"
		}
	} else {
		for i := range bug.Reporting {
			bugReporting := &bug.Reporting[i]
			if i == len(bug.Reporting)-1 ||
				bug.Status == BugStatusInvalid && !bugReporting.Closed.IsZero() &&
					bug.Reporting[i+1].Closed.IsZero() ||
				(bug.Status == BugStatusFixed || bug.Status == BugStatusDup) &&
					bugReporting.Closed.IsZero() {
				reportingIdx = i
				reported = bugReporting.Reported
				link = bugReporting.Link
				switch bug.Status {
				case BugStatusInvalid:
					status = "closed as invalid"
					if bugReporting.Auto {
						status = "auto-" + status
					}
				case BugStatusFixed:
					status = "fixed"
				case BugStatusDup:
					status = "closed as dup"
				default:
					status = fmt.Sprintf("unknown (%v)", bug.Status)
				}
				status = fmt.Sprintf("%v on %v", status, html.FormatTime(bug.Closed))
				break
			}
		}
	}
	creditEmail, err := email.AddAddrContext(ownEmail(c), bug.Reporting[reportingIdx].ID)
	if err != nil {
		log.Errorf(c, "failed to generate credit email: %v", err)
	}
	id := bug.keyHash()
	uiBug := &uiBug{
		Namespace:       bug.Namespace,
		Title:           bug.displayTitle(),
		BisectCauseDone: bug.BisectCause > BisectPending,
		BisectFixDone:   bug.BisectFix > BisectPending,
		NumCrashes:      bug.NumCrashes,
		FirstTime:       bug.FirstTime,
		LastTime:        bug.LastTime,
		ReportedTime:    reported,
		ClosedTime:      bug.Closed,
		ReproLevel:      bug.ReproLevel,
		ReportingIndex:  reportingIdx,
		Status:          status,
		Link:            bugLink(id),
		ExternalLink:    link,
		CreditEmail:     creditEmail,
		NumManagers:     len(managers),
	}
	updateBugBadness(c, uiBug)
	if len(bug.Commits) != 0 {
		for i, com := range bug.Commits {
			cfg := config.Namespaces[bug.Namespace]
			info := bug.getCommitInfo(i)
			uiBug.Commits = append(uiBug.Commits, &uiCommit{
				Hash:  info.Hash,
				Title: com,
				Link:  vcs.CommitLink(cfg.Repos[0].URL, info.Hash),
			})
		}
		for _, mgr := range managers {
			found := false
			for _, mgr1 := range bug.PatchedOn {
				if mgr == mgr1 {
					found = true
					break
				}
			}
			if found {
				uiBug.PatchedOn = append(uiBug.PatchedOn, mgr)
			} else {
				uiBug.MissingOn = append(uiBug.MissingOn, mgr)
			}
		}
		sort.Strings(uiBug.PatchedOn)
		sort.Strings(uiBug.MissingOn)
	}
	return uiBug
}

func mergeUIBug(c context.Context, bug *uiBug, dup *Bug) {
	bug.NumCrashes += dup.NumCrashes
	bug.BisectCauseDone = bug.BisectCauseDone || dup.BisectCause > BisectPending
	bug.BisectFixDone = bug.BisectFixDone || dup.BisectFix > BisectPending
	if bug.LastTime.Before(dup.LastTime) {
		bug.LastTime = dup.LastTime
	}
	if bug.ReproLevel < dup.ReproLevel {
		bug.ReproLevel = dup.ReproLevel
	}
	updateBugBadness(c, bug)
}

func updateBugBadness(c context.Context, bug *uiBug) {
	bug.NumCrashesBad = bug.NumCrashes >= 10000 && timeNow(c).Sub(bug.LastTime) < 24*time.Hour
}

func loadCrashesForBug(c context.Context, bug *Bug) ([]*uiCrash, []byte, error) {
	bugKey := bug.key(c)
	// We can have more than maxCrashes crashes, if we have lots of reproducers.
	crashes, _, err := queryCrashesForBug(c, bugKey, 2*maxCrashes+200)
	if err != nil || len(crashes) == 0 {
		return nil, nil, err
	}
	builds := make(map[string]*Build)
	var results []*uiCrash
	for _, crash := range crashes {
		build := builds[crash.BuildID]
		if build == nil {
			build, err = loadBuild(c, bug.Namespace, crash.BuildID)
			if err != nil {
				return nil, nil, err
			}
			builds[crash.BuildID] = build
		}
		results = append(results, makeUICrash(crash, build))
	}
	sampleReport, _, err := getText(c, textCrashReport, crashes[0].Report)
	if err != nil {
		return nil, nil, err
	}
	return results, sampleReport, nil
}

func loadFixBisectionsForBug(c context.Context, bug *Bug) ([]*uiCrash, error) {
	bugKey := bug.key(c)
	jobs, _, err := queryJobsForBug(c, bugKey, JobBisectFix)
	if err != nil {
		return nil, err
	}
	var results []*uiCrash
	for _, job := range jobs {
		crash, err := queryCrashForJob(c, job, bugKey)
		if err != nil {
			return nil, err
		}
		if crash == nil {
			continue
		}
		build, err := loadBuild(c, bug.Namespace, job.BuildID)
		if err != nil {
			return nil, err
		}
		results = append(results, makeUICrash(crash, build))
	}
	return results, nil
}

func makeUICrash(crash *Crash, build *Build) *uiCrash {
	ui := &uiCrash{
		Manager:      crash.Manager,
		Time:         crash.Time,
		Maintainers:  strings.Join(crash.Maintainers, ", "),
		LogLink:      textLink(textCrashLog, crash.Log),
		ReportLink:   textLink(textCrashReport, crash.Report),
		ReproSyzLink: textLink(textReproSyz, crash.ReproSyz),
		ReproCLink:   textLink(textReproC, crash.ReproC),
	}
	if build != nil {
		ui.uiBuild = makeUIBuild(build)
	}
	return ui
}

func makeUIBuild(build *Build) *uiBuild {
	return &uiBuild{
		Time:                build.Time,
		SyzkallerCommit:     build.SyzkallerCommit,
		SyzkallerCommitLink: vcs.LogLink(vcs.SyzkallerRepo, build.SyzkallerCommit),
		SyzkallerCommitDate: build.SyzkallerCommitDate,
		KernelAlias:         kernelRepoInfo(build).Alias,
		KernelCommit:        build.KernelCommit,
		KernelCommitLink:    vcs.LogLink(build.KernelRepo, build.KernelCommit),
		KernelCommitTitle:   build.KernelCommitTitle,
		KernelCommitDate:    build.KernelCommitDate,
		KernelConfigLink:    textLink(textKernelConfig, build.KernelConfig),
	}
}

func loadManagers(c context.Context, accessLevel AccessLevel, ns string) ([]*uiManager, error) {
	now := timeNow(c)
	date := timeDate(now)
	managers, managerKeys, err := loadManagerList(c, accessLevel, ns)
	if err != nil {
		return nil, err
	}
	var buildKeys []*db.Key
	var statsKeys []*db.Key
	for i, mgr := range managers {
		if mgr.CurrentBuild != "" {
			buildKeys = append(buildKeys, buildKey(c, mgr.Namespace, mgr.CurrentBuild))
		}
		if timeDate(mgr.LastAlive) == date {
			statsKeys = append(statsKeys,
				db.NewKey(c, "ManagerStats", "", int64(date), managerKeys[i]))
		}
	}
	builds := make([]*Build, len(buildKeys))
	if err := db.GetMulti(c, buildKeys, builds); err != nil {
		return nil, err
	}
	uiBuilds := make(map[string]*uiBuild)
	for _, build := range builds {
		uiBuilds[build.Namespace+"|"+build.ID] = makeUIBuild(build)
	}
	stats := make([]*ManagerStats, len(statsKeys))
	if err := db.GetMulti(c, statsKeys, stats); err != nil {
		return nil, fmt.Errorf("fetching manager stats: %v", err)
	}
	var fullStats []*ManagerStats
	for _, mgr := range managers {
		if timeDate(mgr.LastAlive) != date {
			fullStats = append(fullStats, &ManagerStats{})
			continue
		}
		fullStats = append(fullStats, stats[0])
		stats = stats[1:]
	}
	var results []*uiManager
	for i, mgr := range managers {
		stats := fullStats[i]
		link := mgr.Link
		if accessLevel < AccessUser {
			link = ""
		}
		ui := &uiManager{
			Now:                   timeNow(c),
			Namespace:             mgr.Namespace,
			Name:                  mgr.Name,
			Link:                  link,
			CoverLink:             config.CoverPath + mgr.Name + ".html",
			CurrentBuild:          uiBuilds[mgr.Namespace+"|"+mgr.CurrentBuild],
			FailedBuildBugLink:    bugLink(mgr.FailedBuildBug),
			FailedSyzBuildBugLink: bugLink(mgr.FailedSyzBuildBug),
			LastActive:            mgr.LastAlive,
			LastActiveBad:         now.Sub(mgr.LastAlive) > 6*time.Hour,
			CurrentUpTime:         mgr.CurrentUpTime,
			MaxCorpus:             stats.MaxCorpus,
			MaxCover:              stats.MaxCover,
			TotalFuzzingTime:      stats.TotalFuzzingTime,
			TotalCrashes:          stats.TotalCrashes,
			TotalExecs:            stats.TotalExecs,
			TotalExecsBad:         stats.TotalExecs == 0,
		}
		if config.Namespaces[mgr.Namespace].Decommissioned {
			// Don't show bold red highlight for decommissioned namespaces.
			ui.Link = ""
			ui.FailedBuildBugLink = ""
			ui.FailedSyzBuildBugLink = ""
			ui.CurrentUpTime = 0
			ui.LastActiveBad = false
			ui.TotalExecsBad = false
		}
		results = append(results, ui)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Namespace != results[j].Namespace {
			return results[i].Namespace < results[j].Namespace
		}
		return results[i].Name < results[j].Name
	})
	return results, nil
}

func loadManagerList(c context.Context, accessLevel AccessLevel, ns string) ([]*Manager, []*db.Key, error) {
	managers, keys, err := loadAllManagers(c, ns)
	if err != nil {
		return nil, nil, err
	}
	var filtered []*Manager
	var filteredKeys []*db.Key
	for i, mgr := range managers {
		cfg := config.Namespaces[mgr.Namespace]
		if accessLevel < cfg.AccessLevel {
			continue
		}
		if ns == "" && cfg.Decommissioned {
			continue
		}
		filtered = append(filtered, mgr)
		filteredKeys = append(filteredKeys, keys[i])
	}
	return filtered, filteredKeys, nil
}

func loadRecentJobs(c context.Context) ([]*uiJob, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Order("-Created").
		Limit(80).
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	var results []*uiJob
	for i, job := range jobs {
		results = append(results, makeUIJob(job, keys[i], nil, nil, nil))
	}
	return results, nil
}

func loadTestPatchJobs(c context.Context, bug *Bug) ([]*uiJob, error) {
	bugKey := bug.key(c)
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Ancestor(bugKey).
		Filter("Type=", JobTestPatch).
		Filter("Finished>=", time.Time{}).
		Order("-Finished").
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	var results []*uiJob
	for i, job := range jobs {
		results = append(results, makeUIJob(job, keys[i], nil, nil, nil))
	}
	return results, nil
}

func makeUIJob(job *Job, jobKey *db.Key, bug *Bug, crash *Crash, build *Build) *uiJob {
	ui := &uiJob{
		Type:            job.Type,
		Created:         job.Created,
		BugLink:         bugLink(jobKey.Parent().StringID()),
		ExternalLink:    job.Link,
		User:            job.User,
		Reporting:       job.Reporting,
		Namespace:       job.Namespace,
		Manager:         job.Manager,
		BugTitle:        job.BugTitle,
		KernelAlias:     kernelRepoInfoRaw(job.Namespace, job.KernelRepo, job.KernelBranch).Alias,
		PatchLink:       textLink(textPatch, job.Patch),
		Attempts:        job.Attempts,
		Started:         job.Started,
		Finished:        job.Finished,
		CrashTitle:      job.CrashTitle,
		CrashLogLink:    textLink(textCrashLog, job.CrashLog),
		CrashReportLink: textLink(textCrashReport, job.CrashReport),
		LogLink:         textLink(textLog, job.Log),
		ErrorLink:       textLink(textError, job.Error),
		Reported:        job.Reported,
	}
	if !job.Finished.IsZero() {
		ui.Duration = job.Finished.Sub(job.Started)
	}
	if job.Type == JobBisectCause || job.Type == JobBisectFix {
		// We don't report these yet (or at all), see pollCompletedJobs.
		if len(job.Commits) != 1 ||
			bug != nil && (len(bug.Commits) != 0 || bug.Status != BugStatusOpen) {
			ui.Reported = true
		}
	}
	for _, com := range job.Commits {
		ui.Commits = append(ui.Commits, &uiCommit{
			Hash:   com.Hash,
			Title:  com.Title,
			Author: fmt.Sprintf("%v <%v>", com.AuthorName, com.Author),
			CC:     strings.Split(com.CC, "|"),
			Date:   com.Date,
		})
	}
	if len(ui.Commits) == 1 {
		ui.Commit = ui.Commits[0]
		ui.Commits = nil
	}
	if crash != nil {
		ui.Crash = makeUICrash(crash, build)
	}
	return ui
}

func fetchErrorLogs(c context.Context) ([]byte, error) {
	const (
		minLogLevel  = 3
		maxLines     = 100
		maxLineLen   = 1000
		reportPeriod = 7 * 24 * time.Hour
	)
	q := &log.Query{
		StartTime:     time.Now().Add(-reportPeriod),
		AppLogs:       true,
		ApplyMinLevel: true,
		MinLevel:      minLogLevel,
	}
	result := q.Run(c)
	var lines []string
	for i := 0; i < maxLines; i++ {
		rec, err := result.Next()
		if rec == nil {
			break
		}
		if err != nil {
			entry := fmt.Sprintf("ERROR FETCHING LOGS: %v\n", err)
			lines = append(lines, entry)
			break
		}
		for _, al := range rec.AppLogs {
			if al.Level < minLogLevel {
				continue
			}
			text := strings.Replace(al.Message, "\n", " ", -1)
			text = strings.Replace(text, "\r", "", -1)
			if len(text) > maxLineLen {
				text = text[:maxLineLen]
			}
			res := ""
			if !strings.Contains(rec.Resource, "method=log_error") {
				res = fmt.Sprintf(" (%v)", rec.Resource)
			}
			entry := fmt.Sprintf("%v: %v%v\n", al.Time.Format("Jan 02 15:04"), text, res)
			lines = append(lines, entry)
		}
	}
	buf := new(bytes.Buffer)
	for i := len(lines) - 1; i >= 0; i-- {
		buf.WriteString(lines[i])
	}
	return buf.Bytes(), nil
}

func bugLink(id string) string {
	if id == "" {
		return ""
	}
	return "/bug?id=" + id
}
