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
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// This file contains web UI http handlers.

func init() {
	http.Handle("/", handlerWrapper(handleMain))
	http.Handle("/bug", handlerWrapper(handleBug))
	http.Handle("/text", handlerWrapper(handleText))
}

type uiMain struct {
	Header    *uiHeader
	Now       time.Time
	Log       []byte
	Managers  []*uiManager
	Jobs      []*uiJob
	BugGroups []*uiBugGroup
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
	KernelRepo       string
	KernelBranch     string
	KernelCommit     string
	KernelConfigLink string
}

type uiBugPage struct {
	Header  *uiHeader
	Now     time.Time
	Bug     *uiBug
	DupOf   *uiBugGroup
	Dups    *uiBugGroup
	Similar *uiBugGroup
	Crashes []*uiCrash
}

type uiBugGroup struct {
	Now           time.Time
	Caption       string
	Namespace     string
	ShowNamespace bool
	Bugs          []*uiBug
}

type uiBug struct {
	Namespace      string
	Title          string
	NumCrashes     int64
	NumCrashesBad  bool
	FirstTime      time.Time
	LastTime       time.Time
	ReproLevel     dashapi.ReproLevel
	ReportingIndex int
	Status         string
	Link           string
	ExternalLink   string
	Commits        string
	PatchedOn      []string
	MissingOn      []string
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
	KernelRepo      string
	KernelBranch    string
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
	h, err := commonHeader(c)
	if err != nil {
		return err
	}
	errorLog, err := fetchErrorLogs(c)
	if err != nil {
		return err
	}
	managers, err := loadManagers(c)
	if err != nil {
		return err
	}
	jobs, err := loadRecentJobs(c)
	if err != nil {
		return err
	}
	groups, err := fetchBugs(c)
	if err != nil {
		return err
	}
	data := &uiMain{
		Header:    h,
		Now:       timeNow(c),
		Log:       errorLog,
		Managers:  managers,
		Jobs:      jobs,
		BugGroups: groups,
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
		return fmt.Errorf("mandatory parameter id/extid is missing")
	}
	h, err := commonHeader(c)
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
		if err := datastore.Get(c, datastore.NewKey(c, "Bug", bug.DupOf, 0, nil), dup); err != nil {
			return err
		}
		dupOf = &uiBugGroup{
			Now:     timeNow(c),
			Caption: "Duplicate of",
			Bugs:    []*uiBug{createUIBug(c, dup, state, managers)},
		}
	}
	uiBug := createUIBug(c, bug, state, managers)
	crashes, err := loadCrashesForBug(c, bug)
	if err != nil {
		return err
	}
	dups, err := loadDupsForBug(c, bug, state, managers)
	if err != nil {
		return err
	}
	similar, err := loadSimilarBugs(c, bug, state)
	if err != nil {
		return err
	}
	data := &uiBugPage{
		Header:  h,
		Now:     timeNow(c),
		Bug:     uiBug,
		DupOf:   dupOf,
		Dups:    dups,
		Similar: similar,
		Crashes: crashes,
	}
	return serveTemplate(w, "bug.html", data)
}

// handleText serves plain text blobs (crash logs, reports, reproducers, etc).
func handleText(c context.Context, w http.ResponseWriter, r *http.Request) error {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse text id: %v", err)
	}
	data, err := getText(c, r.FormValue("tag"), id)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
	return nil
}

func fetchBugs(c context.Context) ([]*uiBugGroup, error) {
	var bugs []*Bug
	_, err := datastore.NewQuery("Bug").
		Filter("Status=", BugStatusOpen).
		GetAll(c, &bugs)
	if err != nil {
		return nil, err
	}
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	managers := make(map[string][]string)
	for ns := range config.Namespaces {
		mgrs, err := managerList(c, ns)
		if err != nil {
			return nil, err
		}
		managers[ns] = mgrs
	}
	groups := make(map[string][]*uiBug)
	for _, bug := range bugs {
		uiBug := createUIBug(c, bug, state, managers[bug.Namespace])
		groups[bug.Namespace] = append(groups[bug.Namespace], uiBug)
	}
	now := timeNow(c)
	var res []*uiBugGroup
	for ns, bugs := range groups {
		sort.Sort(uiBugSorter(bugs))
		res = append(res, &uiBugGroup{
			Now:       now,
			Caption:   fmt.Sprintf("%v (%v)", ns, len(bugs)),
			Namespace: ns,
			Bugs:      bugs,
		})
	}
	sort.Sort(uiBugGroupSorter(res))
	return res, nil
}

func loadDupsForBug(c context.Context, bug *Bug, state *ReportingState, managers []string) (
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
	for _, dup := range dups {
		results = append(results, createUIBug(c, dup, state, managers))
	}
	group := &uiBugGroup{
		Now:     timeNow(c),
		Caption: "Duplicates",
		Bugs:    results,
	}
	return group, nil
}

func loadSimilarBugs(c context.Context, bug *Bug, state *ReportingState) (*uiBugGroup, error) {
	var similar []*Bug
	_, err := datastore.NewQuery("Bug").
		Filter("Title=", bug.Title).
		GetAll(c, &similar)
	if err != nil {
		return nil, err
	}
	managers := make(map[string][]string)
	var results []*uiBug
	for _, similar := range similar {
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
		Caption:       "Similar Bugs",
		ShowNamespace: true,
		Bugs:          results,
	}
	return group, nil
}

func createUIBug(c context.Context, bug *Bug, state *ReportingState, managers []string) *uiBug {
	reportingIdx, status, link := 0, "", ""
	var err error
	if bug.Status == BugStatusOpen {
		_, _, _, reportingIdx, status, link, err = needReport(c, "", state, bug)
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
				bug.Status == BugStatusInvalid && !bug.Reporting[i].Closed.IsZero() &&
					bug.Reporting[i+1].Closed.IsZero() ||
				(bug.Status == BugStatusFixed || bug.Status == BugStatusDup) &&
					bug.Reporting[i].Closed.IsZero() {
				reportingIdx = i
				link = bugReporting.Link
				switch bug.Status {
				case BugStatusInvalid:
					status = "invalid"
				case BugStatusFixed:
					status = "fixed"
				case BugStatusDup:
					status = "dup"
				default:
					status = fmt.Sprintf("unknown (%v)", bug.Status)
				}
				status = fmt.Sprintf("%v: closed as %v on %v",
					bugReporting.Name, status, formatTime(bug.Closed))
				break
			}
		}
	}
	id := bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
	uiBug := &uiBug{
		Namespace:      bug.Namespace,
		Title:          bug.displayTitle(),
		NumCrashes:     bug.NumCrashes,
		NumCrashesBad:  bug.NumCrashes >= 10000 && timeNow(c).Sub(bug.LastTime) < 24*time.Hour,
		FirstTime:      bug.FirstTime,
		LastTime:       bug.LastTime,
		ReproLevel:     bug.ReproLevel,
		ReportingIndex: reportingIdx,
		Status:         status,
		Link:           bugLink(id),
		ExternalLink:   link,
		PatchedOn:      bug.PatchedOn,
	}
	if len(bug.Commits) != 0 {
		uiBug.Commits = fmt.Sprintf("%q", bug.Commits)
		for _, mgr := range managers {
			found := false
			for _, mgr1 := range bug.PatchedOn {
				if mgr == mgr1 {
					found = true
					break
				}
			}
			if !found {
				uiBug.MissingOn = append(uiBug.MissingOn, mgr)
			}
		}
		sort.Strings(uiBug.MissingOn)
	}
	return uiBug
}

func loadCrashesForBug(c context.Context, bug *Bug) ([]*uiCrash, error) {
	bugHash := bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
	bugKey := datastore.NewKey(c, "Bug", bugHash, 0, nil)
	// We can have more than maxCrashes crashes, if we have lots of reproducers.
	crashes, _, err := queryCrashesForBug(c, bugKey, maxCrashes+200)
	if err != nil {
		return nil, err
	}
	builds := make(map[string]*Build)
	var results []*uiCrash
	for _, crash := range crashes {
		build := builds[crash.BuildID]
		if build == nil {
			build, err = loadBuild(c, bug.Namespace, crash.BuildID)
			if err != nil {
				return nil, err
			}
			builds[crash.BuildID] = build
		}
		ui := &uiCrash{
			Manager:      crash.Manager,
			Time:         crash.Time,
			Maintainers:  fmt.Sprintf("%q", crash.Maintainers),
			LogLink:      textLink("CrashLog", crash.Log),
			ReportLink:   textLink("CrashReport", crash.Report),
			ReproSyzLink: textLink("ReproSyz", crash.ReproSyz),
			ReproCLink:   textLink("ReproC", crash.ReproC),
			uiBuild:      makeUIBuild(build),
		}
		results = append(results, ui)
	}
	return results, nil
}

func makeUIBuild(build *Build) *uiBuild {
	return &uiBuild{
		Time:             build.Time,
		SyzkallerCommit:  build.SyzkallerCommit,
		KernelRepo:       build.KernelRepo,
		KernelBranch:     build.KernelBranch,
		KernelCommit:     build.KernelCommit,
		KernelConfigLink: textLink("KernelConfig", build.KernelConfig),
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
			KernelRepo:      job.KernelRepo,
			KernelBranch:    job.KernelBranch,
			PatchLink:       textLink("Patch", job.Patch),
			Attempts:        job.Attempts,
			Started:         job.Started,
			Finished:        job.Finished,
			CrashTitle:      job.CrashTitle,
			CrashLogLink:    textLink("CrashLog", job.CrashLog),
			CrashReportLink: textLink("CrashReport", job.CrashReport),
			ErrorLink:       textLink("Error", job.Error),
		}
		results = append(results, ui)
	}
	return results, nil
}

func fetchErrorLogs(c context.Context) ([]byte, error) {
	const (
		minLogLevel  = 2
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
			entry := fmt.Sprintf("%v: %v%v\n", formatTime(al.Time), text, res)
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
	if a[i].ReportingIndex != a[j].ReportingIndex {
		return a[i].ReportingIndex > a[j].ReportingIndex
	}
	if (a[i].Link != "") != (a[j].Link != "") {
		return a[i].Link != ""
	}
	if a[i].ReproLevel != a[j].ReproLevel {
		return a[i].ReproLevel > a[j].ReproLevel
	}
	return a[i].FirstTime.After(a[j].FirstTime)
}

type uiBugGroupSorter []*uiBugGroup

func (a uiBugGroupSorter) Len() int           { return len(a) }
func (a uiBugGroupSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a uiBugGroupSorter) Less(i, j int) bool { return a[i].Caption < a[j].Caption }
