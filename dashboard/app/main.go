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
	Log       []byte
	BugGroups []*uiBugGroup
}

type uiBugPage struct {
	Header  *uiHeader
	Bug     *uiBug
	Crashes []*uiCrash
}

type uiBugGroup struct {
	Namespace string
	Bugs      []*uiBug
}

type uiBug struct {
	Namespace      string
	ID             string
	Title          string
	NumCrashes     int64
	FirstTime      time.Time
	LastTime       time.Time
	ReproLevel     dashapi.ReproLevel
	ReportingIndex int
	Status         string
	Link           string
	Commits        string
	PatchedOn      []string
	MissingOn      []string
}

type uiCrash struct {
	Manager          string
	Time             time.Time
	Maintainers      string
	LogLink          string
	ReportLink       string
	ReproSyzLink     string
	ReproCLink       string
	SyzkallerCommit  string
	KernelRepo       string
	KernelBranch     string
	KernelCommit     string
	KernelConfigLink string
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
	groups, err := fetchBugs(c)
	if err != nil {
		return err
	}
	data := &uiMain{
		Header:    h,
		Log:       errorLog,
		BugGroups: groups,
	}
	return templates.ExecuteTemplate(w, "main.html", data)
}

// handleBug serves page about a single bug (which is passed in id argument).
func handleBug(c context.Context, w http.ResponseWriter, r *http.Request) error {
	bug := new(Bug)
	bugKey := datastore.NewKey(c, "Bug", r.FormValue("id"), 0, nil)
	if err := datastore.Get(c, bugKey, bug); err != nil {
		return err
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
	uiBug := createUIBug(c, bug, state, managers)
	crashes, err := loadCrashesForBug(c, bug)
	if err != nil {
		return err
	}
	data := &uiBugPage{
		Header:  h,
		Bug:     uiBug,
		Crashes: crashes,
	}
	return templates.ExecuteTemplate(w, "bug.html", data)
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
	var res []*uiBugGroup
	for ns, bugs := range groups {
		sort.Sort(uiBugSorter(bugs))
		res = append(res, &uiBugGroup{
			Namespace: ns,
			Bugs:      bugs,
		})
	}
	sort.Sort(uiBugGroupSorter(res))
	return res, nil
}

func createUIBug(c context.Context, bug *Bug, state *ReportingState, managers []string) *uiBug {
	_, _, _, reportingIdx, status, link, err := needReport(c, "", state, bug)
	if err != nil {
		status = err.Error()
	}
	if status == "" {
		status = "???"
	}
	uiBug := &uiBug{
		Namespace:      bug.Namespace,
		ID:             bugKeyHash(bug.Namespace, bug.Title, bug.Seq),
		Title:          bug.displayTitle(),
		NumCrashes:     bug.NumCrashes,
		FirstTime:      bug.FirstTime,
		LastTime:       bug.LastTime,
		ReproLevel:     bug.ReproLevel,
		ReportingIndex: reportingIdx,
		Status:         status,
		Link:           link,
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
	crashes, err := queryCrashesForBug(c, bugKey, 100)
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
			Manager:          crash.Manager,
			Time:             crash.Time,
			Maintainers:      fmt.Sprintf("%q", crash.Maintainers),
			LogLink:          textLink("CrashLog", crash.Log),
			ReportLink:       textLink("CrashReport", crash.Report),
			ReproSyzLink:     textLink("ReproSyz", crash.ReproSyz),
			ReproCLink:       textLink("ReproC", crash.ReproC),
			SyzkallerCommit:  build.SyzkallerCommit,
			KernelRepo:       build.KernelRepo,
			KernelBranch:     build.KernelBranch,
			KernelCommit:     build.KernelCommit,
			KernelConfigLink: textLink("KernelConfig", build.KernelConfig),
		}
		results = append(results, ui)
	}
	return results, nil
}

func fetchErrorLogs(c context.Context) ([]byte, error) {
	const (
		minLogLevel  = 2
		maxLines     = 100
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

type uiBugSorter []*uiBug

func (a uiBugSorter) Len() int      { return len(a) }
func (a uiBugSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a uiBugSorter) Less(i, j int) bool {
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
func (a uiBugGroupSorter) Less(i, j int) bool { return a[i].Namespace < a[j].Namespace }
