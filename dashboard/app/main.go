// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/html/urlutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/memcache"
	"google.golang.org/appengine/v2/user"
	proto "google.golang.org/genproto/googleapis/appengine/logging/v1"
	ltype "google.golang.org/genproto/googleapis/logging/type"
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
	http.Handle("/x/repro.log", handlerWrapper(handleTextX(textReproLog)))
	http.Handle("/x/fsck.log", handlerWrapper(handleTextX(textFsckLog)))
	http.Handle("/x/patch.diff", handlerWrapper(handleTextX(textPatch)))
	http.Handle("/x/bisect.txt", handlerWrapper(handleTextX(textLog)))
	http.Handle("/x/error.txt", handlerWrapper(handleTextX(textError)))
	http.Handle("/x/minfo.txt", handlerWrapper(handleTextX(textMachineInfo)))
	for ns, nsConfig := range getConfig(context.Background()).Namespaces {
		http.Handle("/"+ns, handlerWrapper(handleMain))
		http.Handle("/"+ns+"/fixed", handlerWrapper(handleFixed))
		http.Handle("/"+ns+"/invalid", handlerWrapper(handleInvalid))
		http.Handle("/"+ns+"/graph/bugs", handlerWrapper(handleKernelHealthGraph))
		http.Handle("/"+ns+"/graph/lifetimes", handlerWrapper(handleGraphLifetimes))
		http.Handle("/"+ns+"/graph/fuzzing", handlerWrapper(handleGraphFuzzing))
		http.Handle("/"+ns+"/graph/crashes", handlerWrapper(handleGraphCrashes))
		http.Handle("/"+ns+"/graph/found-bugs", handlerWrapper(handleFoundBugsGraph))
		http.Handle("/"+ns+"/graph/coverage", handlerWrapper(handleCoverageGraph))
		http.Handle("/"+ns+"/coverage/file", handlerWrapper(handleFileCoverage))
		http.Handle("/"+ns+"/coverage", handlerWrapper(handleCoverageHeatmap))
		http.Handle("/"+ns+"/graph/coverage_heatmap", handleMovedPermanently("/"+ns+"/coverage"))
		if nsConfig.Subsystems.Service != nil {
			http.Handle("/"+ns+"/graph/coverage_subsystems_heatmap",
				handleMovedPermanently("/"+ns+"/coverage/subsystems"))
			http.Handle("/"+ns+"/coverage/subsystems", handlerWrapper(handleSubsystemsCoverageHeatmap))
		}
		http.Handle("/"+ns+"/repos", handlerWrapper(handleRepos))
		http.Handle("/"+ns+"/bug-summaries", handlerWrapper(handleBugSummaries))
		http.Handle("/"+ns+"/subsystems", handlerWrapper(handleSubsystemsList))
		http.Handle("/"+ns+"/backports", handlerWrapper(handleBackports))
		http.Handle("/"+ns+"/s/", handlerWrapper(handleSubsystemPage))
		http.Handle("/"+ns+"/manager/", handlerWrapper(handleManagerPage))
	}
	http.HandleFunc("/cron/cache_update", cacheUpdate)
	http.HandleFunc("/cron/minute_cache_update", handleMinuteCacheUpdate)
	http.HandleFunc("/cron/deprecate_assets", handleDeprecateAssets)
	http.HandleFunc("/cron/refresh_subsystems", handleRefreshSubsystems)
	http.HandleFunc("/cron/subsystem_reports", handleSubsystemReports)
	http.HandleFunc("/cron/update_coverdb_subsystems", handleUpdateCoverDBSubsystems)
}

func handleMovedPermanently(dest string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest, http.StatusMovedPermanently)
	}
}

type uiMainPage struct {
	Header         *uiHeader
	Now            time.Time
	Decommissioned bool
	Managers       *uiManagerList
	BugFilter      *uiBugFilter
	Groups         []*uiBugGroup
}

type uiBugFilter struct {
	Filter  *userBugFilter
	DropURL func(string, string) string
}

func makeUIBugFilter(c context.Context, filter *userBugFilter) *uiBugFilter {
	url := getCurrentURL(c)
	return &uiBugFilter{
		Filter: filter,
		DropURL: func(name, value string) string {
			return urlutil.DropParam(url, name, value)
		},
	}
}

type uiManagerList struct {
	RepoLink string
	List     []*uiManager
}

func makeManagerList(managers []*uiManager, ns string) *uiManagerList {
	return &uiManagerList{
		RepoLink: fmt.Sprintf("/%s/repos", ns),
		List:     managers,
	}
}

type uiTerminalPage struct {
	Header    *uiHeader
	Now       time.Time
	Bugs      *uiBugGroup
	Stats     *uiBugStats
	BugFilter *uiBugFilter
}

type uiBugStats struct {
	Total          int
	AutoObsoleted  int
	ReproObsoleted int
	UserObsoleted  int
}

func (stats *uiBugStats) Record(bug *Bug, bugReporting *BugReporting) {
	stats.Total++
	switch bug.Status {
	case BugStatusInvalid:
		if bugReporting.Auto {
			stats.AutoObsoleted++
		} else {
			stats.UserObsoleted++
		}
		if bug.StatusReason == dashapi.InvalidatedByRevokedRepro {
			stats.ReproObsoleted++
		}
	}
}

type uiReposPage struct {
	Header *uiHeader
	Repos  []*uiRepo
}

type uiRepo struct {
	URL    string
	Branch string
	Alias  string
}

func (r uiRepo) String() string {
	return r.URL + " " + r.Branch
}

func (r uiRepo) Equals(other *uiRepo) bool {
	return r.String() == other.String()
}

type uiSubsystemPage struct {
	Header   *uiHeader
	Info     *uiSubsystem
	Children []*uiSubsystem
	Parents  []*uiSubsystem
	Groups   []*uiBugGroup
}

type uiSubsystemsPage struct {
	Header       *uiHeader
	List         []*uiSubsystem
	Unclassified *uiSubsystem
	SomeHidden   bool
	ShowAllURL   string
}

type uiSubsystem struct {
	Name        string
	Lists       string
	Maintainers string
	Open        uiSubsystemStats
	Fixed       uiSubsystemStats
}

type uiSubsystemStats struct {
	Count int
	Link  string
}

type uiAdminPage struct {
	Header              *uiHeader
	Log                 []byte
	Managers            *uiManagerList
	RecentJobs          *uiJobList
	PendingJobs         *uiJobList
	RunningJobs         *uiJobList
	TypeJobs            *uiJobList
	FixBisectionsLink   string
	CauseBisectionsLink string
	JobOverviewLink     string
	MemcacheStats       *memcache.Statistics
	Stopped             bool
	StopLink            string
	MoreStopClicks      int
}

type uiManagerPage struct {
	Header        *uiHeader
	Manager       *uiManager
	Message       string
	ShowReproForm bool
	Builds        []*uiBuild
}

type uiManager struct {
	Now                   time.Time
	Namespace             string
	Name                  string
	Link                  string // link to the syz-manager
	PageLink              string // link to the manager page
	CoverLink             string
	CurrentBuild          *uiBuild
	FailedBuildBugLink    string
	FailedSyzBuildBugLink string
	LastActive            time.Time
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
	KernelRepo          string
	KernelBranch        string
	KernelAlias         string
	KernelCommit        string
	KernelCommitLink    string
	KernelCommitTitle   string
	KernelCommitDate    time.Time
	KernelConfigLink    string
	Assets              []*uiAsset
}

type uiBugDiscussion struct {
	Subject  string
	Link     string
	Total    int
	External int
	Last     time.Time
}

type uiReproAttempt struct {
	Time    time.Time
	Manager string
	LogLink string
}

type uiBugPage struct {
	Header          *uiHeader
	Now             time.Time
	Sections        []*uiCollapsible
	Crashes         *uiCrashTable
	LabelGroups     []*uiBugLabelGroup
	DebugSubsystems string
	Bug             *uiBugDetails
}

type uiBugDetails struct {
	*uiBug
	DupOf           *uiBug
	Dups            *uiBugGroup
	Similar         *uiBugGroup
	BisectCauseJob  *uiJob
	BisectFixJob    *uiJob
	FixCandidateJob *uiJob
	SampleReport    template.HTML
	Crashes         []*uiCrash
	TestPatchJobs   *uiJobList
	fixBisections   *bugJobs
	causeBisections *bugJobs
}

type uiBugLabelGroup struct {
	Name   string
	Labels []*uiBugLabel
}

const (
	sectionBugList        = "bug_list"
	sectionJobList        = "job_list"
	sectionDiscussionList = "discussion_list"
	sectionTestResults    = "test_results"
	sectionReproAttempts  = "repro_attempts"
)

type uiCollapsible struct {
	Title string
	Show  bool   // By default it's collapsed.
	Type  string // Template system understands it.
	Value interface{}
}

func makeCollapsibleBugJobs(title string, jobs []*uiJob) *uiCollapsible {
	return &uiCollapsible{
		Title: fmt.Sprintf("%s (%d)", title, len(jobs)),
		Type:  sectionJobList,
		Value: &uiJobList{
			PerBug: true,
			Jobs:   jobs,
		},
	}
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
	DispLastAct   bool
	DispDiscuss   bool
}

type uiJobList struct {
	Title  string
	PerBug bool
	Jobs   []*uiJob
}

type uiCommit struct {
	Hash   string
	Repo   string
	Branch string
	Title  string
	Link   string
	Author string
	CC     []string
	Date   time.Time
}

type uiBug struct {
	Namespace      string
	Title          string
	ImpactScore    int
	NumCrashes     int64
	NumCrashesBad  bool
	BisectCause    BisectStatus
	BisectFix      BisectStatus
	FirstTime      time.Time
	LastTime       time.Time
	ReportedTime   time.Time
	FixTime        time.Time
	ClosedTime     time.Time
	ReproLevel     dashapi.ReproLevel
	ReportingIndex int
	Status         string
	Link           string
	ExternalLink   string
	CreditEmail    string
	Commits        []*uiCommit
	PatchedOn      []string
	MissingOn      []string
	NumManagers    int
	LastActivity   time.Time
	Labels         []*uiBugLabel
	Discussions    DiscussionSummary
	ID             string
}

type uiBugLabel struct {
	Name string
	Link string
}

type uiCrash struct {
	Title           string
	Manager         string
	Time            time.Time
	Maintainers     string
	LogLink         string
	LogHasStrace    bool
	ReportLink      string
	ReproSyzLink    string
	ReproCLink      string
	ReproIsRevoked  bool
	ReproLogLink    string
	MachineInfoLink string
	Assets          []*uiAsset
	*uiBuild
}

type uiAsset struct {
	Title       string
	DownloadURL string
	FsckLogURL  string
	FsIsClean   bool
}

type uiCrashTable struct {
	Crashes []*uiCrash
	Caption string
}

type uiJob struct {
	*dashapi.JobInfo
	Crash             *uiCrash
	InvalidateJobLink string
	RestartJobLink    string
	FixCandidate      bool
}

type uiBackportGroup struct {
	From       *uiRepo
	To         *uiRepo
	Namespaces []string
	List       []*uiBackport
}

type uiBackportBug struct {
	Bug   *uiBug
	Crash *uiCrash
}

type uiBackport struct {
	Commit *uiCommit
	Bugs   map[string][]uiBackportBug // namespace -> list of related bugs in it
}

type uiBackportsPage struct {
	Header           *uiHeader
	Groups           []*uiBackportGroup
	DisplayNamespace func(string) string
}

type userBugFilter struct {
	Manager     string // show bugs that happened on the manager
	OnlyManager string // show bugs that happened ONLY on the manager
	Labels      []string
	NoSubsystem bool
}

func MakeBugFilter(r *http.Request) (*userBugFilter, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return &userBugFilter{
		NoSubsystem: r.FormValue("no_subsystem") != "",
		Manager:     r.FormValue("manager"),
		OnlyManager: r.FormValue("only_manager"),
		Labels:      r.Form["label"],
	}, nil
}

func (filter *userBugFilter) MatchManagerName(name string) bool {
	target := filter.ManagerName()
	return target == "" || target == name
}

func (filter *userBugFilter) ManagerName() string {
	if filter != nil && filter.OnlyManager != "" {
		return filter.OnlyManager
	}
	if filter != nil && filter.Manager != "" {
		return filter.Manager
	}
	return ""
}

func (filter *userBugFilter) MatchBug(bug *Bug) bool {
	if filter == nil {
		return true
	}
	if filter.OnlyManager != "" && (len(bug.HappenedOn) != 1 || bug.HappenedOn[0] != filter.OnlyManager) {
		return false
	}
	if filter.Manager != "" && !stringInList(bug.HappenedOn, filter.Manager) {
		return false
	}
	if filter.NoSubsystem && len(bug.LabelValues(SubsystemLabel)) > 0 {
		return false
	}
	for _, rawLabel := range filter.Labels {
		label, value := splitLabel(rawLabel)
		if !bug.HasLabel(label, value) {
			return false
		}
	}
	return true
}

func (filter *userBugFilter) Hash() string {
	return hash.String([]byte(fmt.Sprintf("%#v", filter)))
}

func splitLabel(rawLabel string) (BugLabelType, string) {
	label, value, _ := strings.Cut(rawLabel, ":")
	return BugLabelType(label), value
}

func (filter *userBugFilter) Any() bool {
	if filter == nil {
		return false
	}
	return len(filter.Labels) > 0 || filter.OnlyManager != "" || filter.Manager != "" || filter.NoSubsystem
}

// handleMain serves main page.
func handleMain(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	accessLevel := accessLevel(c, r)
	filter, err := MakeBugFilter(r)
	if err != nil {
		return fmt.Errorf("%w: failed to parse URL parameters", ErrClientBadRequest)
	}
	managers, err := CachedUIManagers(c, accessLevel, hdr.Namespace, filter)
	if err != nil {
		return err
	}
	groups, err := fetchNamespaceBugs(c, accessLevel, hdr.Namespace, filter)
	if err != nil {
		return err
	}
	for _, group := range groups {
		if getNsConfig(c, hdr.Namespace).DisplayDiscussions {
			group.DispDiscuss = true
		} else {
			group.DispLastAct = true
		}
	}
	data := &uiMainPage{
		Header:         hdr,
		Decommissioned: getNsConfig(c, hdr.Namespace).Decommissioned,
		Now:            timeNow(c),
		Groups:         groups,
		Managers:       makeManagerList(managers, hdr.Namespace),
		BugFilter:      makeUIBugFilter(c, filter),
	}

	if r.FormValue("json") == "1" {
		w.Header().Set("Content-Type", "application/json")
		return writeJSONVersionOf(w, data)
	}

	return serveTemplate(w, "main.html", data)
}

func handleFixed(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleTerminalBugList(c, w, r, &TerminalBug{
		Status:      BugStatusFixed,
		Subpage:     "/fixed",
		ShowPatch:   true,
		ShowPatched: true,
	})
}

func handleInvalid(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleTerminalBugList(c, w, r, &TerminalBug{
		Status:    BugStatusInvalid,
		Subpage:   "/invalid",
		ShowPatch: false,
		ShowStats: true,
	})
}

func handleManagerPage(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	managers, err := CachedUIManagers(c, accessLevel(c, r), hdr.Namespace, nil)
	if err != nil {
		return err
	}
	var manager *uiManager
	if pos := strings.Index(r.URL.Path, "/manager/"); pos != -1 {
		manager = findManager(managers, r.URL.Path[pos+len("/manager/"):])
	}
	if manager == nil {
		return fmt.Errorf("%w: manager is unknown", ErrClientBadRequest)
	}
	builds, err := loadBuilds(c, hdr.Namespace, manager.Name, BuildNormal)
	if err != nil {
		return fmt.Errorf("failed to query builds: %w", err)
	}
	managerPage := &uiManagerPage{Manager: manager, Header: hdr}
	accessLevel := accessLevel(c, r)
	if accessLevel >= AccessUser {
		managerPage.ShowReproForm = true
		if repro := r.FormValue("send-repro"); repro != "" {
			err := saveReproTask(c, hdr.Namespace, manager.Name, []byte(repro))
			if err != nil {
				return fmt.Errorf("failed to request reproduction: %w", err)
			}
			managerPage.Message = "Repro request was saved!"
		}
	}

	for _, build := range builds {
		managerPage.Builds = append(managerPage.Builds, makeUIBuild(c, build, false))
	}
	return serveTemplate(w, "manager.html", managerPage)
}

func findManager(managers []*uiManager, name string) *uiManager {
	for _, mgr := range managers {
		if mgr.Name == name {
			return mgr
		}
	}
	return nil
}

func handleSubsystemPage(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	service := getNsConfig(c, hdr.Namespace).Subsystems.Service
	if service == nil {
		return fmt.Errorf("%w: the namespace does not have subsystems", ErrClientBadRequest)
	}
	var subsystem *subsystem.Subsystem
	if pos := strings.Index(r.URL.Path, "/s/"); pos != -1 {
		name := r.URL.Path[pos+3:]
		if newName := getNsConfig(c, hdr.Namespace).Subsystems.Redirect[name]; newName != "" {
			http.Redirect(w, r, r.URL.Path[:pos+3]+newName, http.StatusMovedPermanently)
			return nil
		}
		subsystem = service.ByName(name)
	}
	if subsystem == nil {
		return fmt.Errorf("%w: the subsystem is not found in the path %v", ErrClientBadRequest, r.URL.Path)
	}
	groups, err := fetchNamespaceBugs(c, accessLevel(c, r),
		hdr.Namespace, &userBugFilter{
			Labels: []string{
				BugLabel{
					Label: SubsystemLabel,
					Value: subsystem.Name,
				}.String(),
			},
		})
	if err != nil {
		return err
	}
	for _, group := range groups {
		group.DispDiscuss = getNsConfig(c, hdr.Namespace).DisplayDiscussions
	}
	cached, err := CacheGet(c, r, hdr.Namespace)
	if err != nil {
		return err
	}
	children := []*uiSubsystem{}
	for _, item := range service.Children(subsystem) {
		uiChild := createUISubsystem(hdr.Namespace, item, cached)
		if uiChild.Open.Count+uiChild.Fixed.Count == 0 {
			continue
		}
		children = append(children, uiChild)
	}
	parents := []*uiSubsystem{}
	for _, item := range subsystem.Parents {
		parents = append(parents, createUISubsystem(hdr.Namespace, item, cached))
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	return serveTemplate(w, "subsystem_page.html", &uiSubsystemPage{
		Header:   hdr,
		Info:     createUISubsystem(hdr.Namespace, subsystem, cached),
		Children: children,
		Parents:  parents,
		Groups:   groups,
	})
}

func handleBackports(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	json := r.FormValue("json") == "1"
	backports, err := loadAllBackports(c, json)
	if err != nil {
		return err
	}
	var groups []*uiBackportGroup
	accessLevel := accessLevel(c, r)
	for _, backport := range backports {
		outgoing := stringInList(backport.FromNs, hdr.Namespace)
		ui := &uiBackport{
			Commit: backport.Commit,
			Bugs:   map[string][]uiBackportBug{},
		}
		incoming := false
		for _, bugInfo := range backport.Bugs {
			bug := bugInfo.bug
			if accessLevel < bug.sanitizeAccess(c, accessLevel) {
				continue
			}
			if !outgoing && bug.Namespace != hdr.Namespace {
				// If it's an incoming backport, don't include other namespaces.
				continue
			}
			if bug.Namespace == hdr.Namespace {
				incoming = true
			}
			ui.Bugs[bug.Namespace] = append(ui.Bugs[bug.Namespace], uiBackportBug{
				Bug:   bugInfo.Bug,
				Crash: bugInfo.Crash,
			})
		}
		if len(ui.Bugs) == 0 {
			continue
		}

		// Display either backports to/from repos of the namespace
		// or the backports that affect bugs from the current namespace.
		if !outgoing && !incoming {
			continue
		}
		var group *uiBackportGroup
		for _, existing := range groups {
			if backport.From.Equals(existing.From) &&
				backport.To.Equals(existing.To) {
				group = existing
				break
			}
		}
		if group == nil {
			group = &uiBackportGroup{
				From: backport.From,
				To:   backport.To,
			}
			groups = append(groups, group)
		}
		group.List = append(group.List, ui)
	}
	for _, group := range groups {
		var nsList []string
		for _, backport := range group.List {
			for ns := range backport.Bugs {
				nsList = append(nsList, ns)
			}
		}
		nsList = unique(nsList)
		sort.Strings(nsList)
		group.Namespaces = nsList
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].From.String()+groups[i].To.String() <
			groups[j].From.String()+groups[j].To.String()
	})
	page := &uiBackportsPage{
		Header: hdr,
		Groups: groups,
		DisplayNamespace: func(ns string) string {
			return getNsConfig(c, ns).DisplayTitle
		},
	}
	if json {
		w.Header().Set("Content-Type", "application/json")
		return writeJSONVersionOf(w, page)
	}
	return serveTemplate(w, "backports.html", page)
}

type rawBackportBug struct {
	Bug   *uiBug
	Crash *uiCrash
	bug   *Bug
}

type rawBackport struct {
	Commit *uiCommit
	From   *uiRepo
	FromNs []string // namespaces that correspond to From
	To     *uiRepo
	Bugs   []rawBackportBug
}

func loadAllBackports(c context.Context, loadCrashes bool) ([]*rawBackport, error) {
	list, err := relevantBackportJobs(c)
	if err != nil {
		return nil, err
	}
	if loadCrashes {
		if err := fullBackportInfo(c, list); err != nil {
			return nil, err
		}
	}
	var ret []*rawBackport
	perCommit := map[string]*rawBackport{}
	for _, info := range list {
		job := info.job
		jobCommit := job.Commits[0]
		to := &uiRepo{URL: job.MergeBaseRepo, Branch: job.MergeBaseBranch}
		from := &uiRepo{URL: job.KernelRepo, Branch: job.KernelBranch}
		commit := &uiCommit{
			Hash:   jobCommit.Hash,
			Title:  jobCommit.Title,
			Link:   vcs.CommitLink(from.URL, jobCommit.Hash),
			Repo:   from.URL,
			Branch: from.Branch,
		}

		hash := from.String() + to.String() + commit.Hash
		backport := perCommit[hash]
		if backport == nil {
			backport = &rawBackport{
				From:   from,
				FromNs: namespacesForRepo(c, from.URL, from.Branch),
				To:     to,
				Commit: commit}
			ret = append(ret, backport)
			perCommit[hash] = backport
		}
		bug := rawBackportBug{
			Bug: createUIBug(c, info.bug, nil, nil),
			bug: info.bug,
		}
		if info.crashBuild != nil {
			bug.Crash = makeUICrash(c, info.crash, info.crashBuild)
		}
		backport.Bugs = append(backport.Bugs, bug)
	}
	return ret, nil
}

func namespacesForRepo(c context.Context, url, branch string) []string {
	var ret []string
	for ns, cfg := range getConfig(c).Namespaces {
		has := false
		for _, repo := range cfg.Repos {
			if repo.NoPoll {
				continue
			}
			if repo.URL == url && repo.Branch == branch {
				has = true
				break
			}
		}
		if has {
			ret = append(ret, ns)
		}
	}
	return ret
}

func handleRepos(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	repos, err := loadRepos(c, hdr.Namespace)
	if err != nil {
		return err
	}
	return serveTemplate(w, "repos.html", &uiReposPage{
		Header: hdr,
		Repos:  repos,
	})
}

type TerminalBug struct {
	Status      int
	Subpage     string
	ShowPatch   bool
	ShowPatched bool
	ShowStats   bool
	Filter      *userBugFilter
}

func handleTerminalBugList(c context.Context, w http.ResponseWriter, r *http.Request, typ *TerminalBug) error {
	accessLevel := accessLevel(c, r)
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	hdr.Subpage = typ.Subpage
	typ.Filter, err = MakeBugFilter(r)
	if err != nil {
		return fmt.Errorf("%w: failed to parse URL parameters", ErrClientBadRequest)
	}
	extraBugs := []*Bug{}
	if typ.Status == BugStatusFixed {
		// Mix in bugs that have pending fixes.
		extraBugs, err = fetchFixPendingBugs(c, hdr.Namespace, typ.Filter.ManagerName())
		if err != nil {
			return err
		}
	}
	bugs, stats, err := fetchTerminalBugs(c, accessLevel, hdr.Namespace, typ, extraBugs)
	if err != nil {
		return err
	}
	if !typ.ShowStats {
		stats = nil
	}
	data := &uiTerminalPage{
		Header:    hdr,
		Now:       timeNow(c),
		Bugs:      bugs,
		Stats:     stats,
		BugFilter: makeUIBugFilter(c, typ.Filter),
	}

	if r.FormValue("json") == "1" {
		w.Header().Set("Content-Type", "application/json")
		return writeJSONVersionOf(w, data)
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
			return fmt.Errorf("failed to flush memcache: %w", err)
		}
	case "invalidate_bisection":
		return handleInvalidateBisection(c, w, r)
	case "emergency_stop":
		if err := recordEmergencyStop(c); err != nil {
			return fmt.Errorf("failed to record an emergency stop: %w", err)
		}
	default:
		return fmt.Errorf("%w: unknown action %q", ErrClientBadRequest, action)
	}
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	var (
		memcacheStats *memcache.Statistics
		managers      []*uiManager
		errorLog      []byte
		recentJobs    []*uiJob
		pendingJobs   []*uiJob
		runningJobs   []*uiJob
		typeJobs      []*uiJob
	)
	g, _ := errgroup.WithContext(context.Background())
	g.Go(func() error {
		var err error
		memcacheStats, err = memcache.Stats(c)
		return err
	})
	g.Go(func() error {
		var err error
		managers, err = loadManagers(c, accessLevel, "", nil)
		return err
	})
	g.Go(func() error {
		var err error
		errorLog, err = fetchErrorLogs(c)
		return err
	})
	if r.FormValue("job_type") != "" {
		value, err := strconv.Atoi(r.FormValue("job_type"))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrClientBadRequest, err)
		}
		g.Go(func() error {
			var err error
			typeJobs, err = loadJobsOfType(c, JobType(value))
			return err
		})
	} else {
		g.Go(func() error {
			var err error
			recentJobs, err = loadRecentJobs(c)
			return err
		})
		g.Go(func() error {
			var err error
			pendingJobs, err = loadPendingJobs(c)
			return err
		})
		g.Go(func() error {
			var err error
			runningJobs, err = loadRunningJobs(c)
			return err
		})
	}
	alreadyStopped := false
	g.Go(func() error {
		var err error
		alreadyStopped, err = emergentlyStopped(c)
		return err
	})
	err = g.Wait()
	if err != nil {
		return err
	}
	data := &uiAdminPage{
		Header:         hdr,
		Log:            errorLog,
		Managers:       makeManagerList(managers, hdr.Namespace),
		MemcacheStats:  memcacheStats,
		Stopped:        alreadyStopped,
		MoreStopClicks: 2,
		StopLink:       urlutil.SetParam("/admin", "stop_clicked", "1"),
	}
	if r.FormValue("stop_clicked") != "" {
		data.MoreStopClicks = 1
		data.StopLink = urlutil.SetParam("/admin", "action", "emergency_stop")
	}
	if r.FormValue("job_type") != "" {
		data.TypeJobs = &uiJobList{Title: "Last jobs:", Jobs: typeJobs}
		data.JobOverviewLink = "/admin"
	} else {
		data.RecentJobs = &uiJobList{Title: "Recent jobs:", Jobs: recentJobs}
		data.RunningJobs = &uiJobList{Title: "Running jobs:", Jobs: runningJobs}
		data.PendingJobs = &uiJobList{Title: "Pending jobs:", Jobs: pendingJobs}
		data.FixBisectionsLink = urlutil.SetParam("/admin", "job_type", fmt.Sprintf("%d", JobBisectFix))
		data.CauseBisectionsLink = urlutil.SetParam("/admin", "job_type", fmt.Sprintf("%d", JobBisectCause))
	}
	return serveTemplate(w, "admin.html", data)
}

// handleBug serves page about a single bug (which is passed in id argument).
// nolint: funlen, gocyclo
func handleBug(c context.Context, w http.ResponseWriter, r *http.Request) error {
	bug, err := findBugByID(c, r)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientNotFound, err)
	}
	accessLevel := accessLevel(c, r)
	if err := checkAccessLevel(c, r, bug.sanitizeAccess(c, accessLevel)); err != nil {
		return err
	}
	if r.FormValue("debug_subsystems") != "" && accessLevel == AccessAdmin {
		return debugBugSubsystems(c, w, bug)
	}
	hdr, err := commonHeader(c, r, w, bug.Namespace)
	if err != nil {
		return err
	}
	bugDetails, err := loadBugDetails(c, bug, accessLevel)
	if err != nil {
		return err
	}
	sections := []*uiCollapsible{}
	if bugDetails.DupOf != nil {
		sections = append(sections, &uiCollapsible{
			Title: "Duplicate of",
			Show:  true,
			Type:  sectionBugList,
			Value: &uiBugGroup{
				Now:  timeNow(c),
				Bugs: []*uiBug{bugDetails.DupOf},
			},
		})
	}
	crashesTable := &uiCrashTable{
		Crashes: bugDetails.Crashes,
		Caption: fmt.Sprintf("Crashes (%d)", bugDetails.NumCrashes),
	}
	if dups := bugDetails.Dups; len(dups.Bugs) > 0 {
		sections = append(sections, &uiCollapsible{
			Title: fmt.Sprintf("Duplicate bugs (%d)", len(dups.Bugs)),
			Type:  sectionBugList,
			Value: dups,
		})
	}
	discussions, err := getBugDiscussionsUI(c, bug)
	if err != nil {
		return err
	}
	if len(discussions) > 0 {
		sections = append(sections, &uiCollapsible{
			Title: fmt.Sprintf("Discussions (%d)", len(discussions)),
			Show:  true,
			Type:  sectionDiscussionList,
			Value: discussions,
		})
	}
	treeTestJobs, err := treeTestJobs(c, bug)
	if err != nil {
		return err
	}
	if len(treeTestJobs) > 0 {
		sections = append(sections, &uiCollapsible{
			Title: fmt.Sprintf("Bug presence (%d)", len(treeTestJobs)),
			Show:  true,
			Type:  sectionTestResults,
			Value: treeTestJobs,
		})
	}
	if similar := bugDetails.Similar; len(similar.Bugs) > 0 {
		sections = append(sections, &uiCollapsible{
			Title: fmt.Sprintf("Similar bugs (%d)", len(similar.Bugs)),
			Show:  getNsConfig(c, hdr.Namespace).AccessLevel != AccessPublic,
			Type:  sectionBugList,
			Value: similar,
		})
	}
	testPatchJobs, err := loadTestPatchJobs(c, bug)
	if err != nil {
		return err
	}
	if len(testPatchJobs) > 0 {
		sections = append(sections, &uiCollapsible{
			Title: fmt.Sprintf("Last patch testing requests (%d)", len(testPatchJobs)),
			Type:  sectionJobList,
			Value: &uiJobList{
				PerBug: true,
				Jobs:   testPatchJobs,
			},
		})
	}
	if accessLevel == AccessAdmin && len(bug.ReproAttempts) > 0 {
		reproAttempts := getReproAttempts(bug)
		sections = append(sections, &uiCollapsible{
			Title: fmt.Sprintf("Failed repro attempts (%d)", len(reproAttempts)),
			Type:  sectionReproAttempts,
			Value: reproAttempts,
		})
	}
	data := &uiBugPage{
		Header:      hdr,
		Now:         timeNow(c),
		Sections:    sections,
		LabelGroups: getLabelGroups(c, bug),
		Crashes:     crashesTable,
		Bug:         bugDetails,
	}
	if accessLevel == AccessAdmin && !bug.hasUserSubsystems() {
		data.DebugSubsystems = urlutil.SetParam(data.Bug.Link, "debug_subsystems", "1")
	}
	// bug.BisectFix is set to BisectNot in three cases :
	// - no fix bisections have been performed on the bug
	// - fix bisection was performed but resulted in a crash on HEAD
	// - there have been infrastructure problems during the job execution
	fixBisections := bugDetails.fixBisections
	// nolint: dupl
	if len(fixBisections.all()) > 1 || len(fixBisections.all()) > 0 && bugDetails.BisectFixJob == nil {
		uiList, err := fixBisections.uiAll(c)
		if err != nil {
			return err
		}
		if len(uiList) != 0 {
			data.Sections = append(data.Sections, makeCollapsibleBugJobs(
				"Fix bisection attempts", uiList))
		}
	}
	// Similarly, a cause bisection can be repeated if there were infrastructure problems.
	causeBisections := bugDetails.causeBisections
	// nolint: dupl
	if len(causeBisections.all()) > 1 || len(causeBisections.all()) > 0 && bugDetails.BisectCauseJob == nil {
		uiList, err := causeBisections.uiAll(c)
		if err != nil {
			return err
		}
		if len(uiList) != 0 {
			data.Sections = append(data.Sections, makeCollapsibleBugJobs(
				"Cause bisection attempts", uiList))
		}
	}
	if r.FormValue("json") == "1" {
		w.Header().Set("Content-Type", "application/json")
		return writeJSONVersionOf(w, data)
	}

	return serveTemplate(w, "bug.html", data)
}

func loadBugDetails(c context.Context, bug *Bug, accessLevel AccessLevel) (*uiBugDetails, error) {
	managers, err := CachedManagerList(c, bug.Namespace)
	if err != nil {
		return nil, err
	}
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	ret := &uiBugDetails{
		uiBug: createUIBug(c, bug, state, managers),
	}
	if bug.DupOf != "" {
		dup := new(Bug)
		if err := db.Get(c, db.NewKey(c, "Bug", bug.DupOf, 0, nil), dup); err != nil {
			return nil, err
		}
		if accessLevel >= dup.sanitizeAccess(c, accessLevel) {
			ret.DupOf = createUIBug(c, dup, state, managers)
		}
	}
	ret.Crashes, ret.SampleReport, err = loadCrashesForBug(c, bug)
	if err != nil {
		return nil, err
	}
	ret.Dups, err = loadDupsForBug(c, bug, state, managers, accessLevel)
	if err != nil {
		return nil, err
	}
	ret.Similar, err = loadSimilarBugsUI(c, bug, state, accessLevel)
	if err != nil {
		return nil, err
	}
	ret.causeBisections, err = queryBugJobs(c, bug, JobBisectCause)
	if err != nil {
		return nil, fmt.Errorf("failed to load cause bisections: %w", err)
	}
	if bug.BisectCause > BisectPending {
		ret.BisectCauseJob, err = ret.causeBisections.uiBestBisection(c)
		if err != nil {
			return nil, err
		}
	}
	ret.fixBisections, err = queryBugJobs(c, bug, JobBisectFix)
	if err != nil {
		return nil, fmt.Errorf("failed to load cause bisections: %w", err)
	}
	if bug.BisectFix > BisectPending {
		ret.BisectFixJob, err = ret.fixBisections.uiBestBisection(c)
		if err != nil {
			return nil, err
		}
	}
	if bug.FixCandidateJob != "" {
		ret.FixCandidateJob, err = ret.fixBisections.uiBestFixCandidate(c)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func getReproAttempts(bug *Bug) []*uiReproAttempt {
	var ret []*uiReproAttempt
	for _, item := range bug.ReproAttempts {
		ret = append(ret, &uiReproAttempt{
			Time:    item.Time,
			Manager: item.Manager,
			LogLink: textLink(textReproLog, item.Log),
		})
	}
	return ret
}

type labelGroupInfo struct {
	Label BugLabelType
	Name  string
}

var labelGroupOrder = []labelGroupInfo{
	{
		Label: OriginLabel,
		Name:  "Bug presence",
	},
	{
		Label: SubsystemLabel,
		Name:  "Subsystems",
	},
	{
		Label: EmptyLabel, // all the rest
		Name:  "Labels",
	},
}

func getLabelGroups(c context.Context, bug *Bug) []*uiBugLabelGroup {
	var ret []*uiBugLabelGroup
	seenLabel := map[string]bool{}
	for _, info := range labelGroupOrder {
		obj := &uiBugLabelGroup{
			Name: info.Name,
		}
		for _, entry := range bug.Labels {
			if seenLabel[entry.String()] {
				continue
			}
			if entry.Label == info.Label || info.Label == EmptyLabel {
				seenLabel[entry.String()] = true
				obj.Labels = append(obj.Labels, makeBugLabelUI(c, bug, entry))
			}
		}
		if len(obj.Labels) == 0 {
			continue
		}
		ret = append(ret, obj)
	}
	return ret
}

func debugBugSubsystems(c context.Context, w http.ResponseWriter, bug *Bug) error {
	service := getNsConfig(c, bug.Namespace).Subsystems.Service
	if service == nil {
		w.Write([]byte("Subsystem service was not found."))
		return nil
	}
	_, err := inferSubsystems(c, bug, bug.key(c), &debugtracer.GenericTracer{
		TraceWriter: w,
	})
	if err != nil {
		fmt.Fprintf(w, "%s", err)
	}
	return nil
}

func makeBugLabelUI(c context.Context, bug *Bug, entry BugLabel) *uiBugLabel {
	url := getCurrentURL(c)
	filterValue := entry.String()

	// If we're on a main/terminal/subsystem page, let's stay there.
	link := url
	if !strings.HasPrefix(url, "/"+bug.Namespace) {
		link = fmt.Sprintf("/%s", bug.Namespace)
	}
	link = urlutil.TransformParam(link, "label", func(oldLabels []string) []string {
		return mergeLabelSet(oldLabels, entry.String())
	})
	ret := &uiBugLabel{
		Name: filterValue,
		Link: link,
	}
	// Patch depending on the specific label type.
	switch entry.Label {
	case SubsystemLabel:
		// Use just the subsystem name.
		ret.Name = entry.Value
		// Prefer link to the per-subsystem page.
		if !strings.HasPrefix(url, "/"+bug.Namespace) || strings.Contains(url, "/s/") {
			ret.Link = fmt.Sprintf("/%s/s/%s", bug.Namespace, entry.Value)
		}
	}
	return ret
}

func mergeLabelSet(oldLabels []string, newLabel string) []string {
	// Leave only one label for each type.
	labelsMap := map[BugLabelType]string{}
	for _, rawLabel := range append(oldLabels, newLabel) {
		label, value := splitLabel(rawLabel)
		labelsMap[label] = value
	}
	var ret []string
	for label, value := range labelsMap {
		ret = append(ret, BugLabel{
			Label: label,
			Value: value,
		}.String())
	}
	return ret
}

func getBugDiscussionsUI(c context.Context, bug *Bug) ([]*uiBugDiscussion, error) {
	// TODO: also include dup bug discussions.
	// TODO: limit the number of DiscussionReminder type entries, e.g. all with
	// external replies + one latest.
	var list []*uiBugDiscussion
	discussions, err := discussionsForBug(c, bug.key(c))
	if err != nil {
		return nil, err
	}
	for _, d := range discussions {
		list = append(list, &uiBugDiscussion{
			Subject:  d.Subject,
			Link:     d.link(),
			Total:    d.Summary.AllMessages,
			External: d.Summary.ExternalMessages,
			Last:     d.Summary.LastMessage,
		})
	}
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].Last.After(list[j].Last)
	})
	return list, nil
}

func handleBugSummaries(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	stage := r.FormValue("stage")
	if stage == "" {
		return fmt.Errorf("stage must be specified")
	}
	list, err := getBugSummaries(c, hdr.Namespace, stage)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(list)
}

func writeJSONVersionOf(writer http.ResponseWriter, page interface{}) error {
	data, err := GetJSONDescrFor(page)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
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

func handleSubsystemsList(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	cached, err := CacheGet(c, r, hdr.Namespace)
	if err != nil {
		return err
	}
	service := getNsConfig(c, hdr.Namespace).Subsystems.Service
	if service == nil {
		return fmt.Errorf("%w: the namespace does not have subsystems", ErrClientBadRequest)
	}
	nonEmpty := r.FormValue("all") != "true"
	list := []*uiSubsystem{}
	someHidden := false
	for _, item := range service.List() {
		record := createUISubsystem(hdr.Namespace, item, cached)
		if nonEmpty && (record.Open.Count+record.Fixed.Count) == 0 {
			someHidden = true
			continue
		}
		list = append(list, record)
	}
	unclassified := &uiSubsystem{
		Name: "",
		Open: uiSubsystemStats{
			Count: cached.NoSubsystem.Open,
			Link:  urlutil.SetParam("/"+hdr.Namespace, "no_subsystem", "true"),
		},
		Fixed: uiSubsystemStats{
			Count: cached.NoSubsystem.Fixed,
			Link:  urlutil.SetParam("/"+hdr.Namespace+"/fixed", "no_subsystem", "true"),
		},
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return serveTemplate(w, "subsystems.html", &uiSubsystemsPage{
		Header:       hdr,
		List:         list,
		Unclassified: unclassified,
		SomeHidden:   someHidden,
		ShowAllURL:   urlutil.SetParam(getCurrentURL(c), "all", "true"),
	})
}

func createUISubsystem(ns string, item *subsystem.Subsystem, cached *Cached) *uiSubsystem {
	stats := cached.Subsystems[item.Name]
	return &uiSubsystem{
		Name:        item.Name,
		Lists:       strings.Join(item.Lists, ", "),
		Maintainers: strings.Join(item.Maintainers, ", "),
		Open: uiSubsystemStats{
			Count: stats.Open,
			Link:  "/" + ns + "/s/" + item.Name,
		},
		Fixed: uiSubsystemStats{
			Count: stats.Fixed,
			Link: urlutil.SetParam("/"+ns+"/fixed", "label", BugLabel{
				Label: SubsystemLabel,
				Value: item.Name,
			}.String()),
		},
	}
}

// handleText serves plain text blobs (crash logs, reports, reproducers, etc).
func handleTextImpl(c context.Context, w http.ResponseWriter, r *http.Request, tag string) error {
	var id int64
	if x := r.FormValue("x"); x != "" {
		xid, err := strconv.ParseUint(x, 16, 64)
		if err != nil || xid == 0 {
			return fmt.Errorf("%w: failed to parse text id: %w", ErrClientBadRequest, err)
		}
		id = int64(xid)
	} else {
		// Old link support, don't remove.
		xid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || xid == 0 {
			return fmt.Errorf("%w: failed to parse text id: %w", ErrClientBadRequest, err)
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
			err = fmt.Errorf("%w: %w", ErrClientNotFound, err)
		}
		return err
	}
	if err := checkAccessLevel(c, r, getNsConfig(c, ns).AccessLevel); err != nil {
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
			fmt.Fprintf(w, "%v %v/bug?id=%v\n", prefix, appURL(c), bug.keyHash(c))
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
	case textMachineInfo:
		return "minfo.txt"
	case textReproLog:
		return "repro.log"
	case textFsckLog:
		return "fsck.log"
	default:
		panic(fmt.Sprintf("unknown tag %v", tag))
	}
}

func fetchFixPendingBugs(c context.Context, ns, manager string) ([]*Bug, error) {
	filter := func(query *db.Query) *db.Query {
		query = query.Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("Commits>", "")
		if manager != "" {
			query = query.Filter("HappenedOn=", manager)
		}
		return query
	}
	rawBugs, _, err := loadAllBugs(c, filter)
	if err != nil {
		return nil, err
	}
	return rawBugs, nil
}

func fetchNamespaceBugs(c context.Context, accessLevel AccessLevel, ns string,
	filter *userBugFilter) ([]*uiBugGroup, error) {
	if !filter.Any() && getNsConfig(c, ns).CacheUIPages {
		// If there's no filter, try to fetch data from cache.
		cached, err := CachedBugGroups(c, ns, accessLevel)
		if err != nil {
			log.Errorf(c, "failed to fetch from bug groups cache: %v", err)
		} else if cached != nil {
			return cached, nil
		}
	}
	bugs, err := loadVisibleBugs(c, ns, filter)
	if err != nil {
		return nil, err
	}
	managers, err := CachedManagerList(c, ns)
	if err != nil {
		return nil, err
	}
	return prepareBugGroups(c, bugs, managers, accessLevel, ns)
}

func prepareBugGroups(c context.Context, bugs []*Bug, managers []string,
	accessLevel AccessLevel, ns string) ([]*uiBugGroup, error) {
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	groups := make(map[int][]*uiBug)
	bugMap := make(map[string]*uiBug)
	var dups []*Bug
	for _, bug := range bugs {
		if accessLevel < bug.sanitizeAccess(c, accessLevel) {
			continue
		}
		if bug.Status == BugStatusDup {
			dups = append(dups, bug)
			continue
		}
		uiBug := createUIBug(c, bug, state, managers)
		if len(uiBug.Commits) != 0 {
			// Don't show "fix pending" bugs on the main page.
			continue
		}
		bugMap[bug.keyHash(c)] = uiBug
		id := uiBug.ReportingIndex
		groups[id] = append(groups[id], uiBug)
	}
	for _, dup := range dups {
		bug := bugMap[dup.DupOf]
		if bug == nil {
			continue // this can be an invalid bug which we filtered above
		}
		mergeUIBug(c, bug, dup)
	}
	cfg := getNsConfig(c, ns)
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
		caption, fragment := "", ""
		switch index {
		case len(cfg.Reporting) - 1:
			caption = "open"
			fragment = "open"
		default:
			reporting := &cfg.Reporting[index]
			caption = reporting.DisplayTitle
			fragment = reporting.Name
		}
		uiGroups = append(uiGroups, &uiBugGroup{
			Now:       timeNow(c),
			Caption:   caption,
			Fragment:  fragment,
			Namespace: ns,
			ShowIndex: index,
			Bugs:      bugs,
		})
	}
	sort.Slice(uiGroups, func(i, j int) bool {
		return uiGroups[i].ShowIndex > uiGroups[j].ShowIndex
	})
	return uiGroups, nil
}

func loadVisibleBugs(c context.Context, ns string, bugFilter *userBugFilter) ([]*Bug, error) {
	// Load open and dup bugs in in 2 separate queries.
	// Ideally we load them in one query with a suitable filter,
	// but unfortunately status values don't allow one query (<BugStatusFixed || >BugStatusInvalid).
	// Ideally we also have separate status for "dup of a closed bug" as we don't need to fetch them.
	// Potentially changing "dup" to "dup of a closed bug" can be done in background.
	// But 2 queries is still much faster than fetching all bugs and we can do this in parallel.
	errc := make(chan error)
	var dups []*Bug
	go func() {
		// Don't apply bugFilter to dups -- they need to be joined unconditionally.
		filter := func(query *db.Query) *db.Query {
			return query.Filter("Namespace=", ns).
				Filter("Status=", BugStatusDup)
		}
		var err error
		dups, _, err = loadAllBugs(c, filter)
		errc <- err
	}()
	filter := func(query *db.Query) *db.Query {
		return applyBugFilter(
			query.Filter("Namespace=", ns).
				Filter("Status<", BugStatusFixed),
			bugFilter,
		)
	}
	bugs, _, err := loadAllBugs(c, filter)
	if err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	var filteredBugs []*Bug
	for _, bug := range bugs {
		if bugFilter.MatchBug(bug) {
			filteredBugs = append(filteredBugs, bug)
		}
	}
	return append(filteredBugs, dups...), nil
}

func fetchTerminalBugs(c context.Context, accessLevel AccessLevel,
	ns string, typ *TerminalBug, extraBugs []*Bug) (*uiBugGroup, *uiBugStats, error) {
	bugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return applyBugFilter(
			query.Filter("Namespace=", ns).Filter("Status=", typ.Status),
			typ.Filter,
		)
	})
	if err != nil {
		return nil, nil, err
	}
	bugs = append(bugs, extraBugs...)
	state, err := loadReportingState(c)
	if err != nil {
		return nil, nil, err
	}
	managers, err := CachedManagerList(c, ns)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(bugs, func(i, j int) bool {
		iFixed := bugs[i].Status == BugStatusFixed
		jFixed := bugs[j].Status == BugStatusFixed
		if iFixed != jFixed {
			// Not-yet-fully-patched bugs come first.
			return jFixed
		}
		return bugs[i].Closed.After(bugs[j].Closed)
	})
	stats := &uiBugStats{}
	res := &uiBugGroup{
		Now:         timeNow(c),
		ShowPatch:   typ.ShowPatch,
		ShowPatched: typ.ShowPatched,
		Namespace:   ns,
	}
	for _, bug := range bugs {
		if accessLevel < bug.sanitizeAccess(c, accessLevel) {
			continue
		}
		if !typ.Filter.MatchBug(bug) {
			continue
		}
		uiBug := createUIBug(c, bug, state, managers)
		res.Bugs = append(res.Bugs, uiBug)
		stats.Record(bug, &bug.Reporting[uiBug.ReportingIndex])
	}
	return res, stats, nil
}

func applyBugFilter(query *db.Query, filter *userBugFilter) *db.Query {
	if filter == nil {
		return query
	}
	manager := filter.ManagerName()
	if len(filter.Labels) > 0 {
		// Take just the first one.
		label, value := splitLabel(filter.Labels[0])
		query = query.Filter("Labels.Label=", string(label))
		query = query.Filter("Labels.Value=", value)
	} else if manager != "" {
		query = query.Filter("HappenedOn=", manager)
	}
	return query
}

func loadDupsForBug(c context.Context, bug *Bug, state *ReportingState,
	managers []string, accessLevel AccessLevel) (
	*uiBugGroup, error) {
	bugHash := bug.keyHash(c)
	var dups []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Status=", BugStatusDup).
		Filter("DupOf=", bugHash).
		GetAll(c, &dups)
	if err != nil {
		return nil, err
	}
	var results []*uiBug
	for _, dup := range dups {
		if accessLevel < dup.sanitizeAccess(c, accessLevel) {
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

func loadSimilarBugsUI(c context.Context, bug *Bug, state *ReportingState,
	accessLevel AccessLevel) (*uiBugGroup, error) {
	managers := make(map[string][]string)
	similarBugs, err := loadSimilarBugs(c, bug)
	if err != nil {
		return nil, err
	}
	var results []*uiBug
	for _, similar := range similarBugs {
		if accessLevel < similar.sanitizeAccess(c, accessLevel) {
			continue
		}
		if managers[similar.Namespace] == nil {
			mgrs, err := CachedManagerList(c, similar.Namespace)
			if err != nil {
				return nil, err
			}
			managers[similar.Namespace] = mgrs
		}
		results = append(results, createUIBug(c, similar, state, managers[similar.Namespace]))
	}
	group := &uiBugGroup{
		Now:           timeNow(c),
		ShowNamespace: true,
		ShowPatched:   true,
		ShowStatus:    true,
		Bugs:          results,
	}
	return group, nil
}

func closedBugStatus(bug *Bug, bugReporting *BugReporting) string {
	status := ""
	switch bug.Status {
	case BugStatusInvalid:
		switch bug.StatusReason {
		case dashapi.InvalidatedByNoActivity:
			fallthrough
		case dashapi.InvalidatedByRevokedRepro:
			status = "obsoleted due to no activity"
		default:
			status = "closed as invalid"
		}
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
	return fmt.Sprintf("%v on %v", status, html.FormatTime(bug.Closed))
}

func createUIBug(c context.Context, bug *Bug, state *ReportingState, managers []string) *uiBug {
	reportingIdx, status, link := 0, "", ""
	var reported time.Time
	var err error
	if bug.Status == BugStatusOpen && state != nil {
		_, _, reportingIdx, status, link, err = needReport(c, "", state, bug)
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
				status = closedBugStatus(bug, bugReporting)
				break
			}
		}
	}
	creditEmail := ""
	if bug.Reporting[reportingIdx].ID != "" {
		// If the bug was never reported to the public, sanitizeReporting() would clear IDs
		// for non-authorized users. In such case, don't show CreditEmail at all.
		creditEmail, err = email.AddAddrContext(ownEmail(c), bug.Reporting[reportingIdx].ID)
		if err != nil {
			log.Errorf(c, "failed to generate credit email: %v", err)
		}
	}
	uiBug := &uiBug{
		Namespace:      bug.Namespace,
		Title:          bug.displayTitle(),
		ImpactScore:    report.TitlesToImpact(bug.Title, bug.AltTitles...),
		BisectCause:    bug.BisectCause,
		BisectFix:      bug.BisectFix,
		NumCrashes:     bug.NumCrashes,
		FirstTime:      bug.FirstTime,
		LastTime:       bug.LastTime,
		ReportedTime:   reported,
		ClosedTime:     bug.Closed,
		FixTime:        bug.FixTime,
		ReproLevel:     bug.ReproLevel,
		ReportingIndex: reportingIdx,
		Status:         status,
		Link:           bugExtLink(c, bug),
		ExternalLink:   link,
		CreditEmail:    creditEmail,
		NumManagers:    len(managers),
		LastActivity:   bug.LastActivity,
		Discussions:    bug.discussionSummary(),
		ID:             bug.keyHash(c),
	}
	for _, entry := range bug.Labels {
		uiBug.Labels = append(uiBug.Labels, makeBugLabelUI(c, bug, entry))
	}
	updateBugBadness(c, uiBug)
	if len(bug.Commits) != 0 {
		for i, com := range bug.Commits {
			mainNsRepo, mainNsBranch := getNsConfig(c, bug.Namespace).mainRepoBranch()
			info := bug.getCommitInfo(i)
			uiBug.Commits = append(uiBug.Commits, &uiCommit{
				Hash:   info.Hash,
				Title:  com,
				Link:   vcs.CommitLink(mainNsRepo, info.Hash),
				Repo:   mainNsRepo,
				Branch: mainNsBranch,
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
	bug.BisectCause = mergeBisectStatus(bug.BisectCause, dup.BisectCause)
	bug.BisectFix = mergeBisectStatus(bug.BisectFix, dup.BisectFix)
	if bug.LastTime.Before(dup.LastTime) {
		bug.LastTime = dup.LastTime
	}
	bug.ReproLevel = max(bug.ReproLevel, dup.ReproLevel)
	updateBugBadness(c, bug)
}

func mergeBisectStatus(a, b BisectStatus) BisectStatus {
	// The statuses are stored in the datastore, so we can't reorder them.
	// But if one of bisections is Yes, then we want to show Yes.
	bisectPriority := [bisectStatusLast]int{0, 1, 2, 6, 5, 4, 3}
	if bisectPriority[a] >= bisectPriority[b] {
		return a
	}
	return b
}

func updateBugBadness(c context.Context, bug *uiBug) {
	bug.NumCrashesBad = bug.NumCrashes >= 10000 && timeNow(c).Sub(bug.LastTime) < 24*time.Hour
}

func loadCrashesForBug(c context.Context, bug *Bug) ([]*uiCrash, template.HTML, error) {
	bugKey := bug.key(c)
	// We can have more than maxCrashes crashes, if we have lots of reproducers.
	crashes, _, err := queryCrashesForBug(c, bugKey, 2*maxCrashes()+200)
	if err != nil || len(crashes) == 0 {
		return nil, "", err
	}
	builds := make(map[string]*Build)
	var results []*uiCrash
	for _, crash := range crashes {
		build := builds[crash.BuildID]
		if build == nil {
			build, err = loadBuild(c, bug.Namespace, crash.BuildID)
			if err != nil {
				return nil, "", err
			}
			builds[crash.BuildID] = build
		}
		results = append(results, makeUICrash(c, crash, build))
	}
	sampleReport, _, err := getText(c, textCrashReport, crashes[0].Report)
	if err != nil {
		return nil, "", err
	}
	sampleBuild := builds[crashes[0].BuildID]
	linkifiedReport := linkifyReport(sampleReport, sampleBuild.KernelRepo, sampleBuild.KernelCommit)
	return results, linkifiedReport, nil
}

func linkifyReport(report []byte, repo, commit string) template.HTML {
	escaped := template.HTMLEscapeString(string(report))
	return template.HTML(sourceFileRe.ReplaceAllStringFunc(escaped, func(match string) string {
		sub := sourceFileRe.FindStringSubmatch(match)
		line, _ := strconv.Atoi(sub[3])
		url := vcs.FileLink(repo, commit, sub[2], line)
		return fmt.Sprintf("%v<a href='%v'>%v:%v</a>%v", sub[1], url, sub[2], sub[3], sub[4])
	}))
}

var sourceFileRe = regexp.MustCompile("( |\t|\n)([a-zA-Z0-9/_.-]+\\.(?:h|c|cc|cpp|s|S|go|rs)):([0-9]+)( |!|\\)|\t|\n)")

func makeUIAssets(c context.Context, build *Build, crash *Crash, forReport bool) []*uiAsset {
	var uiAssets []*uiAsset
	for _, asset := range createAssetList(c, build, crash, forReport) {
		uiAssets = append(uiAssets, &uiAsset{
			Title:       asset.Title,
			DownloadURL: asset.DownloadURL,
			FsckLogURL:  asset.FsckLogURL,
			FsIsClean:   asset.FsIsClean,
		})
	}
	return uiAssets
}

func makeUICrash(c context.Context, crash *Crash, build *Build) *uiCrash {
	ui := &uiCrash{
		Title:           crash.Title,
		Manager:         crash.Manager,
		Time:            crash.Time,
		Maintainers:     strings.Join(crash.Maintainers, ", "),
		LogLink:         textLink(textCrashLog, crash.Log),
		LogHasStrace:    dashapi.CrashFlags(crash.Flags)&dashapi.CrashUnderStrace > 0,
		ReportLink:      textLink(textCrashReport, crash.Report),
		ReproSyzLink:    textLink(textReproSyz, crash.ReproSyz),
		ReproCLink:      textLink(textReproC, crash.ReproC),
		ReproLogLink:    textLink(textReproLog, crash.ReproLog),
		ReproIsRevoked:  crash.ReproIsRevoked,
		MachineInfoLink: textLink(textMachineInfo, crash.MachineInfo),
		Assets:          makeUIAssets(c, build, crash, true),
	}
	if build != nil {
		ui.uiBuild = makeUIBuild(c, build, true)
	}
	return ui
}

func makeUIBuild(c context.Context, build *Build, forReport bool) *uiBuild {
	return &uiBuild{
		Time:                build.Time,
		SyzkallerCommit:     build.SyzkallerCommit,
		SyzkallerCommitLink: vcs.LogLink(vcs.SyzkallerRepo, build.SyzkallerCommit),
		SyzkallerCommitDate: build.SyzkallerCommitDate,
		KernelRepo:          build.KernelRepo,
		KernelBranch:        build.KernelBranch,
		KernelAlias:         kernelRepoInfo(c, build).Alias,
		KernelCommit:        build.KernelCommit,
		KernelCommitLink:    vcs.LogLink(build.KernelRepo, build.KernelCommit),
		KernelCommitTitle:   build.KernelCommitTitle,
		KernelCommitDate:    build.KernelCommitDate,
		KernelConfigLink:    textLink(textKernelConfig, build.KernelConfig),
		Assets:              makeUIAssets(c, build, nil, forReport),
	}
}

func loadRepos(c context.Context, ns string) ([]*uiRepo, error) {
	managers, _, err := loadNsManagerList(c, ns, nil)
	if err != nil {
		return nil, err
	}
	var buildKeys []*db.Key
	for _, mgr := range managers {
		if mgr.CurrentBuild != "" {
			buildKeys = append(buildKeys, buildKey(c, mgr.Namespace, mgr.CurrentBuild))
		}
	}
	builds := make([]*Build, len(buildKeys))
	err = db.GetMulti(c, buildKeys, builds)
	if err != nil {
		return nil, err
	}
	ret := []*uiRepo{}
	dedupRepos := map[string]bool{}
	for _, build := range builds {
		if build == nil {
			continue
		}
		repo := &uiRepo{
			URL:    build.KernelRepo,
			Branch: build.KernelBranch,
		}
		hash := repo.String()
		if dedupRepos[hash] {
			continue
		}
		dedupRepos[hash] = true
		ret = append(ret, repo)
	}
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].URL != ret[j].URL {
			return ret[i].URL < ret[j].URL
		}
		return ret[i].Branch < ret[j].Branch
	})
	return ret, nil
}

func loadManagers(c context.Context, accessLevel AccessLevel, ns string, filter *userBugFilter) ([]*uiManager, error) {
	now := timeNow(c)
	date := timeDate(now)
	managers, managerKeys, err := loadNsManagerList(c, ns, filter)
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
	stats := make([]*ManagerStats, len(statsKeys))
	coverAssets := map[string]Asset{}
	g, _ := errgroup.WithContext(context.Background())
	g.Go(func() error {
		return db.GetMulti(c, buildKeys, builds)
	})
	g.Go(func() error {
		return db.GetMulti(c, statsKeys, stats)
	})
	g.Go(func() error {
		// Get the last coverage report asset for the last week.
		const maxDuration = time.Hour * 24 * 7
		var err error
		coverAssets, err = queryLatestManagerAssets(c, ns, dashapi.HTMLCoverageReport, maxDuration)
		return err
	})
	err = g.Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to query manager-related info: %w", err)
	}
	uiBuilds := make(map[string]*uiBuild)
	for _, build := range builds {
		uiBuilds[build.Namespace+"|"+build.ID] = makeUIBuild(c, build, true)
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
		uptime := mgr.CurrentUpTime
		if now.Sub(mgr.LastAlive) > 6*time.Hour {
			uptime = 0
		}
		// TODO: also display how fresh the coverage report is (to display it on
		// the main page -- this will reduce confusion).
		coverURL := ""
		if asset, ok := coverAssets[mgr.Name]; ok {
			coverURL = asset.DownloadURL
		} else if getConfig(c).CoverPath != "" {
			coverURL = getConfig(c).CoverPath + mgr.Name + ".html"
		}
		ui := &uiManager{
			Now:                   timeNow(c),
			Namespace:             mgr.Namespace,
			Name:                  mgr.Name,
			Link:                  link,
			PageLink:              mgr.Namespace + "/manager/" + mgr.Name,
			CoverLink:             coverURL,
			CurrentBuild:          uiBuilds[mgr.Namespace+"|"+mgr.CurrentBuild],
			FailedBuildBugLink:    bugLink(mgr.FailedBuildBug),
			FailedSyzBuildBugLink: bugLink(mgr.FailedSyzBuildBug),
			LastActive:            mgr.LastAlive,
			CurrentUpTime:         uptime,
			MaxCorpus:             stats.MaxCorpus,
			MaxCover:              stats.MaxCover,
			TotalFuzzingTime:      stats.TotalFuzzingTime,
			TotalCrashes:          stats.TotalCrashes,
			TotalExecs:            stats.TotalExecs,
			TotalExecsBad:         stats.TotalExecs == 0,
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

func loadNsManagerList(c context.Context, ns string, filter *userBugFilter) ([]*Manager, []*db.Key, error) {
	managers, keys, err := loadAllManagers(c, ns)
	if err != nil {
		return nil, nil, err
	}
	var filtered []*Manager
	var filteredKeys []*db.Key
	for i, mgr := range managers {
		cfg := getNsConfig(c, mgr.Namespace)
		if ns == "" && cfg.Decommissioned {
			continue
		}
		if !filter.MatchManagerName(mgr.Name) {
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
	return getUIJobs(c, keys, jobs), nil
}

func loadPendingJobs(c context.Context) ([]*uiJob, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Started=", time.Time{}).
		Limit(50).
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	return getUIJobs(c, keys, jobs), nil
}

func loadRunningJobs(c context.Context) ([]*uiJob, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("IsRunning=", true).
		Limit(50).
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	return getUIJobs(c, keys, jobs), nil
}

func loadJobsOfType(c context.Context, t JobType) ([]*uiJob, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Type=", t).
		Order("-Finished").
		Limit(50).
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	return getUIJobs(c, keys, jobs), nil
}

func getUIJobs(c context.Context, keys []*db.Key, jobs []*Job) []*uiJob {
	var results []*uiJob
	for i, job := range jobs {
		results = append(results, makeUIJob(c, job, keys[i], nil, nil, nil))
	}
	return results
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
	const maxAutomaticJobs = 10
	autoJobsLeft := maxAutomaticJobs
	var results []*uiJob
	for i, job := range jobs {
		if job.User == "" {
			if autoJobsLeft == 0 {
				continue
			}
			autoJobsLeft--
		}
		if job.TreeOrigin && !job.Finished.IsZero() {
			continue
		}
		var build *Build
		if job.BuildID != "" {
			if build, err = loadBuild(c, bug.Namespace, job.BuildID); err != nil {
				return nil, err
			}
		}
		results = append(results, makeUIJob(c, job, keys[i], nil, nil, build))
	}
	return results, nil
}

func makeUIJob(c context.Context, job *Job, jobKey *db.Key, bug *Bug, crash *Crash, build *Build) *uiJob {
	ui := &uiJob{
		JobInfo:           makeJobInfo(c, job, jobKey, bug, build, crash),
		InvalidateJobLink: invalidateJobLink(c, job, jobKey, false),
		RestartJobLink:    invalidateJobLink(c, job, jobKey, true),
		FixCandidate:      job.IsCrossTree(),
	}
	if crash != nil {
		ui.Crash = makeUICrash(c, crash, build)
	}
	return ui
}

func invalidateJobLink(c context.Context, job *Job, jobKey *db.Key, restart bool) string {
	if !user.IsAdmin(c) {
		return ""
	}
	if job.InvalidatedBy != "" || job.Finished.IsZero() {
		return ""
	}
	if job.Type != JobBisectCause && job.Type != JobBisectFix {
		return ""
	}
	params := url.Values{}
	params.Add("action", "invalidate_bisection")
	params.Add("key", jobKey.Encode())
	if restart {
		params.Add("restart", "1")
	}
	return "/admin?" + params.Encode()
}

func formatLogLine(line string) string {
	const maxLineLen = 1000

	line = strings.ReplaceAll(line, "\n", " ")
	line = strings.ReplaceAll(line, "\r", "")
	if len(line) > maxLineLen {
		line = line[:maxLineLen]
		line += "..."
	}
	return line + "\n"
}

func fetchErrorLogs(c context.Context) ([]byte, error) {
	if !appengine.IsAppEngine() {
		return nil, nil
	}

	const (
		maxLines = 100
	)
	projID := os.Getenv("GOOGLE_CLOUD_PROJECT")

	adminClient, err := logadmin.NewClient(c, projID)
	if err != nil {
		return nil, fmt.Errorf("failed to create the logging client: %w", err)
	}
	defer adminClient.Close()

	lastWeek := time.Now().Add(-1 * 7 * 24 * time.Hour).Format(time.RFC3339)
	iter := adminClient.Entries(c,
		logadmin.Filter(
			// We filter our instances.delete errors as false positives. Delete event happens every second.
			// Also, ignore GKE logs since it streams all stderr output as severity=ERROR.
			fmt.Sprintf(`(NOT protoPayload.methodName:v1.compute.instances.delete)`+
				` AND (NOT resource.type="k8s_container") AND timestamp > "%s" AND severity>="ERROR"`,
				lastWeek)),
		logadmin.NewestFirst(),
	)

	var entries []*logging.Entry
	for len(entries) < maxLines {
		entry, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	var lines []string
	for _, entry := range entries {
		requestLog, isRequestLog := entry.Payload.(*proto.RequestLog)
		if isRequestLog {
			for _, logLine := range requestLog.Line {
				if logLine.GetSeverity() < ltype.LogSeverity_ERROR {
					continue
				}
				line := fmt.Sprintf("%v: %v %v %v \"%v\"",
					entry.Timestamp.Format(time.Stamp),
					requestLog.GetStatus(),
					requestLog.GetMethod(),
					requestLog.GetResource(),
					logLine.GetLogMessage())
				lines = append(lines, formatLogLine(line))
			}
		} else {
			line := fmt.Sprintf("%v: %v",
				entry.Timestamp.Format(time.Stamp),
				entry.Payload)
			lines = append(lines, formatLogLine(line))
		}
	}

	buf := new(bytes.Buffer)
	for i := len(lines) - 1; i >= 0; i-- {
		buf.WriteString(lines[i])
	}
	return buf.Bytes(), nil
}

func (j *bugJob) ui(c context.Context) (*uiJob, error) {
	err := j.load(c)
	if err != nil {
		return nil, err
	}
	return makeUIJob(c, j.job, j.key, j.bug, j.crash, j.build), nil
}

func (b *bugJobs) uiAll(c context.Context) ([]*uiJob, error) {
	var ret []*uiJob
	for _, j := range b.all() {
		obj, err := j.ui(c)
		if err != nil {
			return nil, err
		}
		ret = append(ret, obj)
	}
	return ret, nil
}

func (b *bugJobs) uiBestBisection(c context.Context) (*uiJob, error) {
	j := b.bestBisection()
	if j == nil {
		return nil, nil
	}
	return j.ui(c)
}

func (b *bugJobs) uiBestFixCandidate(c context.Context) (*uiJob, error) {
	j := b.bestFixCandidate()
	if j == nil {
		return nil, nil
	}
	return j.ui(c)
}

// bugExtLink should be preferred to bugLink since it provides a URL that's more consistent with
// links from email addresses.
func bugExtLink(c context.Context, bug *Bug) string {
	_, bugReporting, _, _, _ := currentReporting(c, bug)
	if bugReporting == nil || bugReporting.ID == "" {
		return bugLink(bug.keyHash(c))
	}
	return "/bug?extid=" + bugReporting.ID
}

// bugLink should only be used when it's too inconvenient to actually load the bug from the DB.
func bugLink(id string) string {
	if id == "" {
		return ""
	}
	return "/bug?id=" + id
}
