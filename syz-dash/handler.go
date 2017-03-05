// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build appengine

package dash

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"appengine"
	ds "appengine/datastore"
	"appengine/user"
)

func init() {
	http.Handle("/", handlerWrapper(handleAuth(handleDash)))
	http.Handle("/bug", handlerWrapper(handleAuth(handleBug)))
	http.Handle("/text", handlerWrapper(handleAuth(handleText)))
	http.Handle("/search", handlerWrapper(handleAuth(handleSearch)))
	http.Handle("/client", handlerWrapper(handleAuth(handleClient)))
}

type aeHandler func(c appengine.Context, w http.ResponseWriter, r *http.Request) error

func handlerWrapper(fn aeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := fn(c, w, r); err != nil {
			c.Errorf("Error: %v", err)
			if err1 := templates.ExecuteTemplate(w, "error.html", err.Error()); err1 != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})
}

func handleAuth(fn aeHandler) aeHandler {
	return func(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
		u := user.Current(c)
		if !u.Admin && (u.AuthDomain != "gmail.com" || !strings.HasSuffix(u.Email, "@google.com")) {
			return fmt.Errorf("You are not authorized to view this. This incident will be reported.")
		}
		return fn(c, w, r)
	}
}

func handleClient(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
	name := r.FormValue("name")
	if name == "" {
		var clients []*Client
		if _, err := ds.NewQuery("Client").GetAll(c, &clients); err != nil {
			return fmt.Errorf("failed to fetch clients: %v", err)
		}
		for _, client := range clients {
			fmt.Fprintf(w, "%v: %v\n", client.Name, client.Key)
		}
		return nil
	}
	if !regexp.MustCompile("^[a-zA-Z0-9-_]{2,100}$").MatchString(name) {
		return fmt.Errorf("bad name")
	}
	key := r.FormValue("key")
	if !regexp.MustCompile("^[a-zA-Z0-9]{16,128}$").MatchString(key) {
		return fmt.Errorf("bad key")
	}
	client := &Client{
		Name: name,
		Key:  key,
	}
	if err := ds.Get(c, ds.NewKey(c, "Client", name, 0, nil), client); err == nil {
		return fmt.Errorf("client already exists")
	}
	if _, err := ds.Put(c, ds.NewKey(c, "Client", name, 0, nil), client); err != nil {
		return err
	}
	fmt.Fprintf(w, "added client")
	return nil
}

func handleDash(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
	data := &dataDash{}
	bugGroups := map[int]*uiBugGroup{
		BugStatusNew:      &uiBugGroup{Name: "New bugs"},
		BugStatusClaimed:  &uiBugGroup{Name: "Claimed bugs"},
		BugStatusReported: &uiBugGroup{Name: "Reported bugs"},
		BugStatusUnclear:  &uiBugGroup{Name: "Unclear bugs"},
		BugStatusFixed:    &uiBugGroup{Name: "Fixed bugs"},
	}
	data.BugGroups = append(data.BugGroups,
		bugGroups[BugStatusNew],
		bugGroups[BugStatusClaimed],
		bugGroups[BugStatusReported],
		bugGroups[BugStatusUnclear],
		bugGroups[BugStatusFixed],
	)

	all := r.FormValue("all") != ""
	if all {
		bugGroups[BugStatusClosed] = &uiBugGroup{Name: "Closed bugs"}
		bugGroups[BugStatusDeleted] = &uiBugGroup{Name: "Deleted bugs"}
		data.BugGroups = append(data.BugGroups, bugGroups[BugStatusClosed], bugGroups[BugStatusDeleted])
	}

	var bugs []*Bug
	var keys []*ds.Key
	var err error
	query := ds.NewQuery("Bug").Project("Title", "Status", "Comment")
	if !all {
		query = query.Filter("Status <", BugStatusClosed)
	}
	if keys, err = query.GetAll(c, &bugs); err != nil {
		return fmt.Errorf("failed to fetch bugs: %v", err)
	}
	bugMap := make(map[int64]*uiBug)
	managers := make(map[int64]map[string]bool)
	for i, bug := range bugs {
		id := keys[i].IntID()
		ui := &uiBug{
			ID:      id,
			Title:   bug.Title,
			Status:  statusToString(bug.Status),
			Comment: bug.Comment,
		}
		bugMap[id] = ui
		managers[id] = make(map[string]bool)
		bugGroups[bug.Status].Bugs = append(bugGroups[bug.Status].Bugs, ui)
	}

	var groups []*Group
	if _, err := ds.NewQuery("Group").GetAll(c, &groups); err != nil {
		return fmt.Errorf("failed to fetch crash groups: %v", err)
	}
	for _, group := range groups {
		ui := bugMap[group.Bug]
		if ui == nil {
			if !all {
				continue
			}
			return fmt.Errorf("failed to find bug for crash %v (%v)", group.Title, group.Seq)
		}
		ui.NumCrashes += group.NumCrashes
		if group.HasCRepro {
			ui.Repro = "C repro"
		} else if group.HasRepro && ui.Repro != "C repro" {
			ui.Repro = "repro"
		}
		if ui.FirstTime.IsZero() || ui.FirstTime.After(group.FirstTime) {
			ui.FirstTime = group.FirstTime
		}
		if ui.LastTime.IsZero() || ui.LastTime.Before(group.LastTime) {
			ui.LastTime = group.LastTime
		}
		for _, mgr := range group.Managers {
			managers[group.Bug][mgr] = true
		}
	}

	for id, mgrs := range managers {
		bug := bugMap[id]
		var arr []string
		for k := range mgrs {
			arr = append(arr, k)
		}
		sort.Strings(arr)
		bug.Managers = strings.Join(arr, ", ")
	}

	for _, group := range data.BugGroups {
		sort.Sort(uiBugArray(group.Bugs))
	}

	cached, err := getCached(c)
	if err != nil {
		return err
	}
	data.Header = headerFromCached(cached)

	return templates.ExecuteTemplate(w, "dash.html", data)
}

func handleBug(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse bug id: %v", err)
	}
	action := r.FormValue("action")
	if action != "" && !user.IsAdmin(c) {
		return fmt.Errorf("can't touch this")
	}

	msg := ""
	bug := new(Bug)
	switch action {
	case "Update":
		ver, err := strconv.ParseInt(r.FormValue("ver"), 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse bug version: %v", err)
		}
		title := limitLength(r.FormValue("title"), maxTitleLen)
		reportLink := limitLength(r.FormValue("report_link"), maxLinkLen)
		cve := limitLength(r.FormValue("cve"), maxTextLen)
		comment := limitLength(r.FormValue("comment"), maxCommentLen)
		status, err := stringToStatus(r.FormValue("status"))
		if err != nil {
			return err
		}
		if title == "" {
			return fmt.Errorf("title can't be empty")
		}
		switch status {
		case BugStatusReported, BugStatusFixed:
			if reportLink == "" {
				return fmt.Errorf("enter report link")
			}
		case BugStatusClaimed, BugStatusUnclear:
			if comment == "" {
				return fmt.Errorf("enter comment as to why it's unclear/who claimed it")
			}
		}

		flushCached := false
		if err := ds.RunInTransaction(c, func(c appengine.Context) error {
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			if bug.Version != ver {
				return fmt.Errorf("bug has changed by somebody else")
			}
			if status == BugStatusFixed && len(bug.Patches) == 0 {
				return fmt.Errorf("add a patch for fixed bugs")
			}
			flushCached = bug.Status != status || bug.Title != title
			bug.Title = title
			bug.Status = status
			bug.ReportLink = reportLink
			bug.CVE = cve
			bug.Comment = comment
			bug.Version++
			if _, err := ds.Put(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			return nil
		}, nil); err != nil {
			return err
		}
		if flushCached {
			dropCached(c)
		}
		msg = "bug is updated"
	case "Close", "Delete", "Reopen":
		ver, err := strconv.ParseInt(r.FormValue("ver"), 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse bug version: %v", err)
		}
		if err := ds.RunInTransaction(c, func(c appengine.Context) error {
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			if bug.Version != ver {
				return fmt.Errorf("bug has changed by somebody else")
			}
			switch action {
			case "Close":
				bug.Status = BugStatusClosed
				msg = "bug is closed"
			case "Delete":
				bug.Status = BugStatusDeleted
				msg = "bug is deleted"
			case "Reopen":
				bug.Status = BugStatusNew
				msg = "bug is reopened"
			}
			bug.Version++
			if _, err := ds.Put(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			return nil
		}, nil); err != nil {
			return err
		}
		dropCached(c)
	case "Merge":
		ver, err := strconv.ParseInt(r.FormValue("ver"), 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse bug version: %v", err)
		}
		otherID, err := strconv.ParseInt(r.FormValue("bug_id"), 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse bug id: %v", err)
		}
		if err := ds.RunInTransaction(c, func(c appengine.Context) error {
			srcBug := new(Bug)
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), srcBug); err != nil {
				return err
			}
			if srcBug.Version != ver {
				return fmt.Errorf("bug has changed by somebody else")
			}
			dstBug := new(Bug)
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", otherID, nil), dstBug); err != nil {
				return err
			}
			if dstBug.Status >= BugStatusClosed {
				return fmt.Errorf("target bug is already closed")
			}
			mergeStrings := func(s1, s2 string) string {
				if s1 == "" {
					return s2
				} else if s2 == "" {
					return s1
				} else {
					return s1 + ", " + s2
				}
			}
			dstBug.Version++
			dstBug.ReportLink = mergeStrings(dstBug.ReportLink, srcBug.ReportLink)
			dstBug.Comment = mergeStrings(dstBug.Comment, srcBug.Comment)
			dstBug.CVE = mergeStrings(dstBug.CVE, srcBug.CVE)
			var groupKeys []*ds.Key
			var groups []*Group
			for _, hash := range srcBug.Groups {
				groupKeys = append(groupKeys, ds.NewKey(c, "Group", hash, 0, nil))
				groups = append(groups, new(Group))
			}
			if err := ds.GetMulti(c, groupKeys, groups); err != nil {
				return fmt.Errorf("failed to fetch crash groups: %v", err)
			}
			for _, group := range groups {
				group.Bug = otherID
				if _, err := ds.Put(c, group.Key(c), group); err != nil {
					return err
				}
			}
			dstBug.Groups = append(dstBug.Groups, srcBug.Groups...)
		nextPatch:
			for _, patch := range srcBug.Patches {
				for _, patch1 := range dstBug.Patches {
					if patch1.Title == patch.Title {
						continue nextPatch
					}
				}
				dstBug.Patches = append(dstBug.Patches, patch)
			}
			if _, err := ds.Put(c, ds.NewKey(c, "Bug", "", otherID, nil), dstBug); err != nil {
				return err
			}
			if err := ds.Delete(c, ds.NewKey(c, "Bug", "", id, nil)); err != nil {
				return err
			}
			id = otherID
			bug = dstBug
			return nil
		}, &ds.TransactionOptions{XG: true}); err != nil {
			return err
		}
		dropCached(c)
		http.Redirect(w, r, fmt.Sprintf("bug?id=%v", otherID), http.StatusMovedPermanently)
		return nil
	case "Unmerge":
		hash := r.FormValue("hash")
		if err := ds.RunInTransaction(c, func(c appengine.Context) error {
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			group := new(Group)
			if err := ds.Get(c, ds.NewKey(c, "Group", hash, 0, nil), group); err != nil {
				return err
			}
			found := false
			for i, hash1 := range bug.Groups {
				if hash == hash1 {
					found = true
					copy(bug.Groups[i:], bug.Groups[i+1:])
					bug.Groups = bug.Groups[:len(bug.Groups)-1]
					break
				}
			}
			if !found {
				return fmt.Errorf("group is not found")
			}
			if _, err := ds.Put(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}

			newBug := &Bug{
				Title:  group.DisplayTitle(),
				Status: BugStatusNew,
				Groups: []string{group.hash()},
			}
			bugKey, err := ds.Put(c, ds.NewIncompleteKey(c, "Bug", nil), newBug)
			if err != nil {
				return err
			}
			group.Bug = bugKey.IntID()
			if _, err := ds.Put(c, group.Key(c), group); err != nil {
				return err
			}
			msg = fmt.Sprintf("group '%v' is unmerged into separate bug", group.Title)
			return nil
		}, &ds.TransactionOptions{XG: true}); err != nil {
			return err
		}
		dropCached(c)
	case "Add patch":
		title, diff, err := parsePatch(r.FormValue("patch"))
		if err != nil {
			return fmt.Errorf("failed to parse patch: %v", err)
		}
		if err := ds.RunInTransaction(c, func(c appengine.Context) error {
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			for _, patch := range bug.Patches {
				if patch.Title == title {
					return fmt.Errorf("patch is already attached: %v", title)
				}
			}
			diffID, err := putText(c, "PatchDiff", []byte(diff))
			if err != nil {
				return err
			}
			bug.Patches = append(bug.Patches, Patch{
				Title: title,
				Diff:  diffID,
				Time:  time.Now(),
			})
			if _, err := ds.Put(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return fmt.Errorf("failed to save bug: %v", err)
			}
			return nil
		}, &ds.TransactionOptions{XG: true}); err != nil {
			return err
		}
		msg = fmt.Sprintf("patch '%v' added", title)
	case "Delete patch":
		title := r.FormValue("title")
		if err := ds.RunInTransaction(c, func(c appengine.Context) error {
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return err
			}
			found := false
			for i, patch := range bug.Patches {
				if patch.Title == title {
					found = true
					copy(bug.Patches[i:], bug.Patches[i+1:])
					bug.Patches = bug.Patches[:len(bug.Patches)-1]
					break
				}
			}
			if !found {
				return fmt.Errorf("no such patch")
			}
			if _, err := ds.Put(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
				return fmt.Errorf("failed to save bug: %v", err)
			}
			return nil
		}, &ds.TransactionOptions{XG: true}); err != nil {
			return err
		}
		msg = fmt.Sprintf("patch '%v' deleted", title)
	case "":
		if err := ds.Get(c, ds.NewKey(c, "Bug", "", id, nil), bug); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown action '%v'", r.FormValue("action"))
	}

	data := &dataBug{}
	data.ID = id
	data.Version = bug.Version
	data.Title = bug.Title
	data.ReportLink = bug.ReportLink
	data.CVE = bug.CVE
	data.Comment = bug.Comment
	data.Status = statusToString(bug.Status)
	data.Closed = bug.Status >= BugStatusClosed
	data.Patches = bug.Patches
	data.Message = msg

	cached, err := getCached(c)
	if err != nil {
		return err
	}
	data.Header = headerFromCached(cached)
	for _, bug1 := range cached.Bugs {
		if bug1.ID == id {
			continue
		}
		data.AllBugs = append(data.AllBugs, &uiBug{
			ID:    bug1.ID,
			Title: bug1.Title,
		})
	}
	sort.Sort(uiBugTitleSorter(data.AllBugs))

	managers := make(map[string]bool)

	var groups []*Group
	if _, err := ds.NewQuery("Group").Filter("Bug=", id).GetAll(c, &groups); err != nil {
		return fmt.Errorf("failed to fetch crash groups: %v", err)
	}
	for _, group := range groups {
		data.NumCrashes += group.NumCrashes
		if data.FirstTime.IsZero() || data.FirstTime.After(group.FirstTime) {
			data.FirstTime = group.FirstTime
		}
		if data.LastTime.IsZero() || data.LastTime.Before(group.LastTime) {
			data.LastTime = group.LastTime
		}
		for _, mgr := range group.Managers {
			managers[mgr] = true
		}
		data.Groups = append(data.Groups, &uiGroup{group.DisplayTitle(), group.hash()})

		var crashes []*Crash
		if _, err := ds.NewQuery("Crash").Ancestor(group.Key(c)).GetAll(c, &crashes); err != nil {
			return fmt.Errorf("failed to fetch crashes: %v", err)
		}
		for _, crash := range crashes {
			data.Crashes.List = append(data.Crashes.List, &uiCrash{
				Title:   group.DisplayTitle(),
				Manager: crash.Manager,
				Tag:     crash.Tag,
				Time:    crash.Time,
				Log:     crash.Log,
				Report:  crash.Report,
			})
		}

		var repros []*Repro
		if _, err := ds.NewQuery("Repro").Ancestor(group.Key(c)).GetAll(c, &repros); err != nil {
			return fmt.Errorf("failed to fetch repros: %v", err)
		}
		for _, repro := range repros {
			data.Repros = append(data.Repros, &uiRepro{
				Title:   group.DisplayTitle(),
				Manager: repro.Manager,
				Tag:     repro.Tag,
				Time:    repro.Time,
				Report:  repro.Report,
				Opts:    repro.Opts,
				Prog:    repro.Prog,
				CProg:   repro.CProg,
			})
		}
	}

	sort.Sort(uiCrashArray(data.Crashes.List))
	sort.Sort(uiReproArray(data.Repros))

	if len(data.Groups) == 1 {
		data.Groups = nil
	}

	var arr []string
	for k := range managers {
		arr = append(arr, k)
	}
	sort.Strings(arr)
	data.Managers = strings.Join(arr, ", ")

	return templates.ExecuteTemplate(w, "bug.html", data)
}

func handleText(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse text id: %v", err)
	}
	data, err := getText(c, id)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
	return nil
}

func handleSearch(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
	cached, err := getCached(c)
	if err != nil {
		return err
	}
	data := &dataSearch{
		Header: headerFromCached(cached),
	}
	data.Header.Query = r.FormValue("query")
	query := []byte(data.Header.Query)

	bugTitles := make(map[int64]string)
	for _, b := range cached.Bugs {
		bugTitles[b.ID] = b.Title
	}
	resMap := make(map[int64]*uiCrashGroup)

	var groups []*Group
	if _, err := ds.NewQuery("Group").GetAll(c, &groups); err != nil {
		return fmt.Errorf("failed to fetch crash groups: %v", err)
	}
	for _, group := range groups {
		var crashes []*Crash
		if _, err := ds.NewQuery("Crash").Ancestor(group.Key(c)).GetAll(c, &crashes); err != nil {
			return fmt.Errorf("failed to fetch crashes: %v", err)
		}
		for _, crash := range crashes {
			if crash.Report == 0 {
				continue
			}
			report, err := getText(c, crash.Report)
			if err != nil {
				return err
			}
			if !bytes.Contains(report, query) {
				continue
			}
			cg := resMap[group.Bug]
			if cg == nil {
				cg = &uiCrashGroup{
					Title: bugTitles[group.Bug],
					Link:  fmt.Sprintf("/bug?id=%v", group.Bug),
				}
				resMap[group.Bug] = cg
			}
			cg.List = append(cg.List, &uiCrash{
				Title:   group.DisplayTitle(),
				Manager: crash.Manager,
				Tag:     crash.Tag,
				Time:    crash.Time,
				Log:     crash.Log,
				Report:  crash.Report,
			})
		}
	}
	for _, res := range resMap {
		sort.Sort(uiCrashArray(res.List))
		data.Results = append(data.Results, res)
	}
	sort.Sort(uiCrashGroupArray(data.Results))

	return templates.ExecuteTemplate(w, "search.html", data)
}

type dataHeader struct {
	Found   int64
	Fixed   int64
	Crashed int64
	Query   string
}

func headerFromCached(cached *Cached) *dataHeader {
	return &dataHeader{
		Found:   cached.Found,
		Fixed:   cached.Fixed,
		Crashed: cached.Crashed,
	}
}

type dataSearch struct {
	Header  *dataHeader
	Results []*uiCrashGroup
}

type dataDash struct {
	Header    *dataHeader
	BugGroups []*uiBugGroup
}

type dataBug struct {
	Header *dataHeader
	uiBug
	Crashes uiCrashGroup
	Repros  []*uiRepro
	Message string
	AllBugs []*uiBug
}

type uiCrashGroup struct {
	Title string
	Link  string
	List  []*uiCrash
}

type uiBugGroup struct {
	Name string
	Bugs []*uiBug
}

type uiGroup struct {
	Title string
	Hash  string
}

type uiBug struct {
	ID         int64
	Version    int64
	Title      string
	Status     string
	Closed     bool
	NumCrashes int64
	Repro      string
	FirstTime  time.Time
	LastTime   time.Time
	Managers   string
	ReportLink string
	Comment    string
	CVE        string
	Groups     []*uiGroup
	Patches    []Patch
}

type uiCrash struct {
	Title   string
	Manager string
	Tag     string
	Time    time.Time
	Log     int64
	Report  int64
}

type uiRepro struct {
	Title   string
	Manager string
	Tag     string
	Time    time.Time
	Report  int64
	Opts    string
	Prog    int64
	CProg   int64
}

type uiBugArray []*uiBug

func (a uiBugArray) Len() int {
	return len(a)
}

func (a uiBugArray) Less(i, j int) bool {
	return a[i].LastTime.After(a[j].LastTime)
}

func (a uiBugArray) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type uiBugTitleSorter []*uiBug

func (a uiBugTitleSorter) Len() int {
	return len(a)
}

func (a uiBugTitleSorter) Less(i, j int) bool {
	return a[i].Title < a[j].Title
}

func (a uiBugTitleSorter) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type uiCrashArray []*uiCrash

func (a uiCrashArray) Len() int {
	return len(a)
}

func (a uiCrashArray) Less(i, j int) bool {
	return a[i].Time.After(a[j].Time)
}

func (a uiCrashArray) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type uiCrashGroupArray []*uiCrashGroup

func (a uiCrashGroupArray) Len() int {
	return len(a)
}

func (a uiCrashGroupArray) Less(i, j int) bool {
	return a[i].Title < a[j].Title
}

func (a uiCrashGroupArray) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type uiReproArray []*uiRepro

func (a uiReproArray) Len() int {
	return len(a)
}

func (a uiReproArray) Less(i, j int) bool {
	return a[i].Time.After(a[j].Time)
}

func (a uiReproArray) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type dataPatches struct {
	Message string
	Patches []*Patch
}

var tmplFuncs = template.FuncMap{
	"formatTime": formatTime,
}

func formatTime(t time.Time) string {
	return t.Format("Jan 02 15:04")
}

var templates = template.Must(template.New("").Funcs(tmplFuncs).ParseGlob("*.html"))
