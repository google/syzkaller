// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

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
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// This file contains web UI http handlers.

func initHTTPHandlers() {
	http.Handle("/", handlerWrapper(handleMain))
	http.Handle("/bug", handlerWrapper(handleBug))
	http.Handle("/text", handlerWrapper(handleText))
	http.Handle("/x/.config", handlerWrapper(handleTextX(textKernelConfig)))
	http.Handle("/x/log.txt", handlerWrapper(handleTextX(textCrashLog)))
	http.Handle("/x/repro.syz", handlerWrapper(handleTextX(textReproSyz)))
	http.Handle("/x/repro.c", handlerWrapper(handleTextX(textReproC)))
	http.Handle("/x/patch.diff", handlerWrapper(handleTextX(textPatch)))
	http.Handle("/x/error.txt", handlerWrapper(handleTextX(textError)))
}

type uiMain struct {
	Header        *uiHeader
	Now           time.Time
	Log           []byte
	Managers      []*uiManager
	Jobs          []*uiJob
	BugNamespaces []*uiBugNamespace
}

type uiManager struct {
	Namespace          string
	Name               string
	Link               string
	CurrentBuild       *uiBuild
	FailedBuildBugLink string
	LastActive         time.Time
	LastActiveBad      bool
	CurrentUpTime      time.Duration
	MaxCorpus          int64
	MaxCover           int64
	TotalFuzzingTime   time.Duration
	TotalCrashes       int64
	TotalExecs         int64
}

type uiBuild struct {
	Time             time.Time
	SyzkallerCommit  string
	KernelAlias      string
	KernelCommit     string
	KernelConfigLink string
}

type uiBugPage struct {
	Header       *uiHeader
	Now          time.Time
	Bug          *uiBug
	DupOf        *uiBugGroup
	Dups         *uiBugGroup
	Similar      *uiBugGroup
	SampleReport []byte
	Crashes      []*uiCrash
}

type uiBugNamespace struct {
	Name       string
	Caption    string
	CoverLink  string
	FixedLink  string
	FixedCount int
	Groups     []*uiBugGroup
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

type uiBug struct {
	Namespace      string
	Title          string
	NumCrashes     int64
	NumCrashesBad  bool
	FirstTime      time.Time
	LastTime       time.Time
	ReportedTime   time.Time
	ClosedTime     time.Time
	ReproLevel     dashapi.ReproLevel
	ReportingIndex int
	Status         string
	Link           string
	ExternalLink   string
	CreditEmail    string
	Commits        string
	PatchedOn      []string
	MissingOn      []string
	NumManagers    int
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

type uiJob struct {
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
	CrashTitle      string
	CrashLogLink    string
	CrashReportLink string
	ErrorLink       string
	Reported        bool
}

// handleMain serves main page.
func handleMain(c context.Context, w http.ResponseWriter, r *http.Request) error {
	var errorLog []byte
	var managers []*uiManager
	var jobs []*uiJob
	if accessLevel(c, r) == AccessAdmin && r.FormValue("fixed") == "" {
		var err error
		errorLog, err = fetchErrorLogs(c)
		if err != nil {
			return err
		}
		managers, err = loadManagers(c)
		if err != nil {
			return err
		}
		jobs, err = loadRecentJobs(c)
		if err != nil {
			return err
		}
	}
	bugNamespaces, err := fetchBugs(c, r)
	if err != nil {
		return err
	}
	data := &uiMain{
		Header:        commonHeader(c, r),
		Now:           timeNow(c),
		Log:           errorLog,
		Managers:      managers,
		Jobs:          jobs,
		BugNamespaces: bugNamespaces,
	}
	return serveTemplate(w, "main.html", data)
}

// handleBug serves page about a single bug (which is passed in id argument).
func handleBug(c context.Context, w http.ResponseWriter, r *http.Request) error {
	bug := new(Bug)
	if id := r.FormValue("id"); id != "" {
		bugKey := datastore.NewKey(c, "Bug", id, 0, nil)
		if err := datastore.Get(c, bugKey, bug); err != nil {
			return err
		}
	} else if extID := r.FormValue("extid"); extID != "" {
		var err error
		bug, _, err = findBugByReportingID(c, extID)
		if err != nil {
			return err
		}
	} else {
		return ErrDontLog(fmt.Errorf("mandatory parameter id/extid is missing"))
	}
	accessLevel := accessLevel(c, r)
	if err := checkAccessLevel(c, r, bug.sanitizeAccess(accessLevel)); err != nil {
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
		if err := datastore.Get(c, datastore.NewKey(c, "Bug", bug.DupOf, 0, nil), dup); err != nil {
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
	dups, err := loadDupsForBug(c, r, bug, state, managers)
	if err != nil {
		return err
	}
	similar, err := loadSimilarBugs(c, r, bug, state)
	if err != nil {
		return err
	}
	data := &uiBugPage{
		Header:       commonHeader(c, r),
		Now:          timeNow(c),
		Bug:          uiBug,
		DupOf:        dupOf,
		Dups:         dups,
		Similar:      similar,
		SampleReport: sampleReport,
		Crashes:      crashes,
	}
	return serveTemplate(w, "bug.html", data)
}

// handleText serves plain text blobs (crash logs, reports, reproducers, etc).
func handleTextImpl(c context.Context, w http.ResponseWriter, r *http.Request, tag string) error {
	var id int64
	if x := r.FormValue("x"); x != "" {
		xid, err := strconv.ParseUint(x, 16, 64)
		if err != nil || xid == 0 {
			return ErrDontLog(fmt.Errorf("failed to parse text id: %v", err))
		}
		id = int64(xid)
	} else {
		// Old link support, don't remove.
		xid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || xid == 0 {
			return ErrDontLog(fmt.Errorf("failed to parse text id: %v", err))
		}
		id = xid
	}
	crash, err := checkTextAccess(c, r, tag, id)
	if err != nil {
		return err
	}
	data, ns, err := getText(c, tag, id)
	if err != nil {
		return err
	}
	if err := checkAccessLevel(c, r, config.Namespaces[ns].AccessLevel); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Unfortunately filename does not work in chrome on linux due to:
	// https://bugs.chromium.org/p/chromium/issues/detail?id=608342
	w.Header().Set("Content-Disposition", "inline; filename="+textFilename(tag))
	if tag == textReproSyz {
		// Add link to documentation and repro opts for syzkaller reproducers.
		w.Write([]byte(syzReproPrefix))
		if crash != nil {
			fmt.Fprintf(w, "#%s\n", crash.ReproOpts)
		}
	}
	w.Write(data)
	return nil
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
	case textError:
		return "error.txt"
	default:
		return "text.txt"
	}
}

func fetchBugs(c context.Context, r *http.Request) ([]*uiBugNamespace, error) {
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	accessLevel := accessLevel(c, r)
	onlyFixed := r.FormValue("fixed")
	var res []*uiBugNamespace
	for ns, cfg := range config.Namespaces {
		if accessLevel < cfg.AccessLevel {
			continue
		}
		if onlyFixed != "" && onlyFixed != ns {
			continue
		}
		uiNamespace, err := fetchNamespaceBugs(c, accessLevel, ns, state, onlyFixed != "")
		if err != nil {
			return nil, err
		}
		res = append(res, uiNamespace)
	}
	sort.Sort(uiBugNamespaceSorter(res))
	return res, nil
}

func fetchNamespaceBugs(c context.Context, accessLevel AccessLevel, ns string,
	state *ReportingState, onlyFixed bool) (*uiBugNamespace, error) {
	query := datastore.NewQuery("Bug").Filter("Namespace=", ns)
	if onlyFixed {
		query = query.Filter("Status=", BugStatusFixed)
	}
	var bugs []*Bug
	_, err := query.GetAll(c, &bugs)
	if err != nil {
		return nil, err
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return nil, err
	}
	fixedCount := 0
	groups := make(map[int][]*uiBug)
	bugMap := make(map[string]*uiBug)
	var dups []*Bug
	for _, bug := range bugs {
		if bug.Status == BugStatusFixed {
			fixedCount++
		}
		if bug.Status == BugStatusInvalid || bug.Status == BugStatusFixed != onlyFixed {
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
		bugMap[bugKeyHash(bug.Namespace, bug.Title, bug.Seq)] = uiBug
		id := uiBug.ReportingIndex
		if bug.Status == BugStatusFixed {
			id = -1
		} else if uiBug.Commits != "" {
			id = -2
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
	var uiGroups []*uiBugGroup
	for index, bugs := range groups {
		sort.Sort(uiBugSorter(bugs))
		caption, fragment, showPatch, showPatched := "", "", false, false
		switch index {
		case -1:
			caption, showPatch, showPatched = "fixed", true, false
		case -2:
			caption, showPatch, showPatched = "fix pending", false, true
			fragment = ns + "-pending"
		case len(config.Namespaces[ns].Reporting) - 1:
			caption, showPatch, showPatched = "open", false, false
			fragment = ns + "-open"
		default:
			reporting := &config.Namespaces[ns].Reporting[index]
			caption, showPatch, showPatched = reporting.DisplayTitle, false, false
			fragment = ns + "-" + reporting.Name
		}
		uiGroups = append(uiGroups, &uiBugGroup{
			Now:         timeNow(c),
			Caption:     fmt.Sprintf("%v (%v)", caption, len(bugs)),
			Fragment:    fragment,
			Namespace:   ns,
			ShowPatch:   showPatch,
			ShowPatched: showPatched,
			ShowIndex:   index,
			Bugs:        bugs,
		})
	}
	sort.Sort(uiBugGroupSorter(uiGroups))
	fixedLink := ""
	if !onlyFixed {
		fixedLink = fmt.Sprintf("?fixed=%v", ns)
	}
	cfg := config.Namespaces[ns]
	uiNamespace := &uiBugNamespace{
		Name:       ns,
		Caption:    cfg.DisplayTitle,
		CoverLink:  cfg.CoverLink,
		FixedCount: fixedCount,
		FixedLink:  fixedLink,
		Groups:     uiGroups,
	}
	return uiNamespace, nil
}

func loadDupsForBug(c context.Context, r *http.Request, bug *Bug, state *ReportingState, managers []string) (
	*uiBugGroup, error) {
	bugHash := bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
	var dups []*Bug
	_, err := datastore.NewQuery("Bug").
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
	_, err := datastore.NewQuery("Bug").
		Filter("Title=", bug.Title).
		GetAll(c, &similar)
	if err != nil {
		return nil, err
	}
	managers := make(map[string][]string)
	var results []*uiBug
	accessLevel := accessLevel(c, r)
	for _, similar := range similar {
		if accessLevel < similar.sanitizeAccess(accessLevel) {
			continue
		}
		if similar.Namespace == bug.Namespace && similar.Seq == bug.Seq {
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
				case BugStatusFixed:
					status = "fixed"
				case BugStatusDup:
					status = "closed as dup"
				default:
					status = fmt.Sprintf("unknown (%v)", bug.Status)
				}
				status = fmt.Sprintf("%v on %v", status, formatTime(bug.Closed))
				break
			}
		}
	}
	creditEmail, err := email.AddAddrContext(ownEmail(c), bug.Reporting[reportingIdx].ID)
	if err != nil {
		log.Errorf(c, "failed to generate credit email: %v", err)
	}
	id := bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
	uiBug := &uiBug{
		Namespace:      bug.Namespace,
		Title:          bug.displayTitle(),
		NumCrashes:     bug.NumCrashes,
		FirstTime:      bug.FirstTime,
		LastTime:       bug.LastTime,
		ReportedTime:   reported,
		ClosedTime:     bug.Closed,
		ReproLevel:     bug.ReproLevel,
		ReportingIndex: reportingIdx,
		Status:         status,
		Link:           bugLink(id),
		ExternalLink:   link,
		CreditEmail:    creditEmail,
		NumManagers:    len(managers),
	}
	updateBugBadness(c, uiBug)
	if len(bug.Commits) != 0 {
		uiBug.Commits = bug.Commits[0]
		if len(bug.Commits) > 1 {
			uiBug.Commits = fmt.Sprintf("%q", bug.Commits)
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
	bugHash := bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
	bugKey := datastore.NewKey(c, "Bug", bugHash, 0, nil)
	// We can have more than maxCrashes crashes, if we have lots of reproducers.
	crashes, _, err := queryCrashesForBug(c, bugKey, maxCrashes+200)
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
		ui := &uiCrash{
			Manager:      crash.Manager,
			Time:         crash.Time,
			Maintainers:  fmt.Sprintf("%q", crash.Maintainers),
			LogLink:      textLink(textCrashLog, crash.Log),
			ReportLink:   textLink(textCrashReport, crash.Report),
			ReproSyzLink: textLink(textReproSyz, crash.ReproSyz),
			ReproCLink:   textLink(textReproC, crash.ReproC),
			uiBuild:      makeUIBuild(build),
		}
		results = append(results, ui)
	}
	sampleReport, _, err := getText(c, textCrashReport, crashes[0].Report)
	if err != nil {
		return nil, nil, err
	}
	return results, sampleReport, nil
}

func makeUIBuild(build *Build) *uiBuild {
	return &uiBuild{
		Time:             build.Time,
		SyzkallerCommit:  build.SyzkallerCommit,
		KernelAlias:      kernelRepoInfo(build).Alias,
		KernelCommit:     build.KernelCommit,
		KernelConfigLink: textLink(textKernelConfig, build.KernelConfig),
	}
}

func loadManagers(c context.Context) ([]*uiManager, error) {
	now := timeNow(c)
	date := timeDate(now)
	managers, managerKeys, err := loadAllManagers(c)
	if err != nil {
		return nil, err
	}
	var buildKeys []*datastore.Key
	var statsKeys []*datastore.Key
	for i, mgr := range managers {
		if mgr.CurrentBuild != "" {
			buildKeys = append(buildKeys, buildKey(c, mgr.Namespace, mgr.CurrentBuild))
		}
		if timeDate(mgr.LastAlive) == date {
			statsKeys = append(statsKeys,
				datastore.NewKey(c, "ManagerStats", "", int64(date), managerKeys[i]))
		}
	}
	builds := make([]*Build, len(buildKeys))
	if err := datastore.GetMulti(c, buildKeys, builds); err != nil {
		return nil, err
	}
	uiBuilds := make(map[string]*uiBuild)
	for _, build := range builds {
		uiBuilds[build.Namespace+"|"+build.ID] = makeUIBuild(build)
	}
	stats := make([]*ManagerStats, len(statsKeys))
	if err := datastore.GetMulti(c, statsKeys, stats); err != nil {
		return nil, err
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
		results = append(results, &uiManager{
			Namespace:          mgr.Namespace,
			Name:               mgr.Name,
			Link:               mgr.Link,
			CurrentBuild:       uiBuilds[mgr.Namespace+"|"+mgr.CurrentBuild],
			FailedBuildBugLink: bugLink(mgr.FailedBuildBug),
			LastActive:         mgr.LastAlive,
			LastActiveBad:      now.Sub(mgr.LastAlive) > 12*time.Hour,
			CurrentUpTime:      mgr.CurrentUpTime,
			MaxCorpus:          stats.MaxCorpus,
			MaxCover:           stats.MaxCover,
			TotalFuzzingTime:   stats.TotalFuzzingTime,
			TotalCrashes:       stats.TotalCrashes,
			TotalExecs:         stats.TotalExecs,
		})
	}
	sort.Sort(uiManagerSorter(results))
	return results, nil
}

func loadRecentJobs(c context.Context) ([]*uiJob, error) {
	var jobs []*Job
	keys, err := datastore.NewQuery("Job").
		Order("-Created").
		Limit(20).
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	var results []*uiJob
	for i, job := range jobs {
		ui := &uiJob{
			Created:         job.Created,
			BugLink:         bugLink(keys[i].Parent().StringID()),
			ExternalLink:    job.Link,
			User:            job.User,
			Reporting:       job.Reporting,
			Namespace:       job.Namespace,
			Manager:         job.Manager,
			BugTitle:        job.BugTitle,
			KernelAlias:     kernelRepoInfoRaw(job.KernelRepo, job.KernelBranch).Alias,
			PatchLink:       textLink(textPatch, job.Patch),
			Attempts:        job.Attempts,
			Started:         job.Started,
			Finished:        job.Finished,
			CrashTitle:      job.CrashTitle,
			CrashLogLink:    textLink(textCrashLog, job.CrashLog),
			CrashReportLink: textLink(textCrashReport, job.CrashReport),
			ErrorLink:       textLink(textError, job.Error),
		}
		results = append(results, ui)
	}
	return results, nil
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

type uiManagerSorter []*uiManager

func (a uiManagerSorter) Len() int      { return len(a) }
func (a uiManagerSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a uiManagerSorter) Less(i, j int) bool {
	if a[i].Namespace != a[j].Namespace {
		return a[i].Namespace < a[j].Namespace
	}
	return a[i].Name < a[j].Name
}

type uiBugSorter []*uiBug

func (a uiBugSorter) Len() int      { return len(a) }
func (a uiBugSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a uiBugSorter) Less(i, j int) bool {
	if a[i].Namespace != a[j].Namespace {
		return a[i].Namespace < a[j].Namespace
	}
	if a[i].ClosedTime != a[j].ClosedTime {
		return a[i].ClosedTime.After(a[j].ClosedTime)
	}
	return a[i].ReportedTime.After(a[j].ReportedTime)
}

type uiBugGroupSorter []*uiBugGroup

func (a uiBugGroupSorter) Len() int           { return len(a) }
func (a uiBugGroupSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a uiBugGroupSorter) Less(i, j int) bool { return a[i].ShowIndex > a[j].ShowIndex }

type uiBugNamespaceSorter []*uiBugNamespace

func (a uiBugNamespaceSorter) Len() int           { return len(a) }
func (a uiBugNamespaceSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a uiBugNamespaceSorter) Less(i, j int) bool { return a[i].Caption < a[j].Caption }
