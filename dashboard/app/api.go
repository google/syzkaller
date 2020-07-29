// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/hash"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	db "google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

func initAPIHandlers() {
	http.Handle("/api", handleJSON(handleAPI))
}

var apiHandlers = map[string]APIHandler{
	"log_error":             apiLogError,
	"job_poll":              apiJobPoll,
	"job_done":              apiJobDone,
	"reporting_poll_bugs":   apiReportingPollBugs,
	"reporting_poll_notifs": apiReportingPollNotifications,
	"reporting_poll_closed": apiReportingPollClosed,
	"reporting_update":      apiReportingUpdate,
}

var apiNamespaceHandlers = map[string]APINamespaceHandler{
	"upload_build":        apiUploadBuild,
	"builder_poll":        apiBuilderPoll,
	"report_build_error":  apiReportBuildError,
	"report_crash":        apiReportCrash,
	"report_failed_repro": apiReportFailedRepro,
	"need_repro":          apiNeedRepro,
	"manager_stats":       apiManagerStats,
	"commit_poll":         apiCommitPoll,
	"upload_commits":      apiUploadCommits,
	"bug_list":            apiBugList,
	"load_bug":            apiLoadBug,
}

type JSONHandler func(c context.Context, r *http.Request) (interface{}, error)
type APIHandler func(c context.Context, r *http.Request, payload []byte) (interface{}, error)
type APINamespaceHandler func(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error)

const (
	maxReproPerBug   = 10
	reproRetryPeriod = 24 * time.Hour // try 1 repro per day until we have at least syz repro
)

// Overridable for testing.
var timeNow = func(c context.Context) time.Time {
	return time.Now()
}

func timeSince(c context.Context, t time.Time) time.Duration {
	return timeNow(c).Sub(t)
}

func handleJSON(fn JSONHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		reply, err := fn(c, r)
		if err != nil {
			// ErrAccess is logged earlier.
			if err != ErrAccess {
				log.Errorf(c, "%v", err)
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			if err := json.NewEncoder(gz).Encode(reply); err != nil {
				log.Errorf(c, "failed to encode reply: %v", err)
			}
			gz.Close()
		} else {
			if err := json.NewEncoder(w).Encode(reply); err != nil {
				log.Errorf(c, "failed to encode reply: %v", err)
			}
		}
	})
}

func handleAPI(c context.Context, r *http.Request) (reply interface{}, err error) {
	client := r.PostFormValue("client")
	method := r.PostFormValue("method")
	log.Infof(c, "api %q from %q", method, client)
	ns, err := checkClient(c, client, r.PostFormValue("key"))
	if err != nil {
		if client != "" {
			log.Errorf(c, "%v", err)
		} else {
			// Don't log as error if somebody just invokes /api.
			log.Infof(c, "%v", err)
		}
		return nil, err
	}
	var payload []byte
	if str := r.PostFormValue("payload"); str != "" {
		gr, err := gzip.NewReader(strings.NewReader(str))
		if err != nil {
			return nil, fmt.Errorf("failed to ungzip payload: %v", err)
		}
		payload, err = ioutil.ReadAll(gr)
		if err != nil {
			return nil, fmt.Errorf("failed to ungzip payload: %v", err)
		}
		if err := gr.Close(); err != nil {
			return nil, fmt.Errorf("failed to ungzip payload: %v", err)
		}
	}
	handler := apiHandlers[method]
	if handler != nil {
		return handler(c, r, payload)
	}
	nsHandler := apiNamespaceHandlers[method]
	if nsHandler == nil {
		return nil, fmt.Errorf("unknown api method %q", method)
	}
	if ns == "" {
		return nil, fmt.Errorf("method %q must be called within a namespace", method)
	}
	return nsHandler(c, ns, r, payload)
}

func checkClient(c context.Context, name0, key0 string) (string, error) {
	for name, key := range config.Clients {
		if name == name0 {
			if key != key0 {
				return "", ErrAccess
			}
			return "", nil
		}
	}
	for ns, cfg := range config.Namespaces {
		for name, key := range cfg.Clients {
			if name == name0 {
				if key != key0 {
					return "", ErrAccess
				}
				return ns, nil
			}
		}
	}
	return "", ErrAccess
}

func apiLogError(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.LogEntry)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	log.Errorf(c, "%v: %v", req.Name, req.Text)
	return nil, nil
}

func apiBuilderPoll(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.BuilderPollReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	bugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).
			Filter("Status<", BugStatusFixed)
	})
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool)
loop:
	for _, bug := range bugs {
		// TODO(dvyukov): include this condition into the query if possible.
		if len(bug.Commits) == 0 {
			continue
		}
		for _, mgr := range bug.PatchedOn {
			if mgr == req.Manager {
				continue loop
			}
		}
		for _, com := range bug.Commits {
			m[com] = true
		}
	}
	commits := make([]string, 0, len(m))
	for com := range m {
		commits = append(commits, com)
	}
	sort.Strings(commits)
	resp := &dashapi.BuilderPollResp{
		PendingCommits: commits,
		ReportEmail:    reportEmail(c, ns),
	}
	return resp, nil
}

func reportEmail(c context.Context, ns string) string {
	for _, reporting := range config.Namespaces[ns].Reporting {
		if _, ok := reporting.Config.(*EmailConfig); ok {
			return ownEmail(c)
		}
	}
	return ""
}

func apiCommitPoll(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	resp := &dashapi.CommitPollResp{
		ReportEmail: reportEmail(c, ns),
	}
	for _, repo := range config.Namespaces[ns].Repos {
		resp.Repos = append(resp.Repos, dashapi.Repo{
			URL:    repo.URL,
			Branch: repo.Branch,
		})
	}
	var bugs []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("NeedCommitInfo=", true).
		Project("Commits").
		Limit(100).
		GetAll(c, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %v", err)
	}
	commits := make(map[string]bool)
	for _, bug := range bugs {
		for _, com := range bug.Commits {
			commits[com] = true
		}
	}
	for com := range commits {
		resp.Commits = append(resp.Commits, com)
	}
	return resp, nil
}

func apiUploadCommits(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.CommitPollResultReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	// This adds fixing commits to bugs.
	err := addCommitsToBugs(c, ns, "", nil, req.Commits)
	if err != nil {
		return nil, err
	}
	// Now add commit info to commits.
	for _, com := range req.Commits {
		if com.Hash == "" {
			continue
		}
		if err := addCommitInfo(c, ns, com); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func addCommitInfo(c context.Context, ns string, com dashapi.Commit) error {
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Commits=", com.Title).
		GetAll(c, &bugs)
	if err != nil {
		return fmt.Errorf("failed to query bugs: %v", err)
	}
	for i, bug := range bugs {
		if err := addCommitInfoToBug(c, bug, keys[i], com); err != nil {
			return err
		}
	}
	return nil
}

func addCommitInfoToBug(c context.Context, bug *Bug, bugKey *db.Key, com dashapi.Commit) error {
	if needUpdate, err := addCommitInfoToBugImpl(c, bug, com); err != nil {
		return err
	} else if !needUpdate {
		return nil
	}
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug %v: %v", bugKey.StringID(), err)
		}
		if needUpdate, err := addCommitInfoToBugImpl(c, bug, com); err != nil {
			return err
		} else if !needUpdate {
			return nil
		}
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	return db.RunInTransaction(c, tx, nil)
}

func addCommitInfoToBugImpl(c context.Context, bug *Bug, com dashapi.Commit) (bool, error) {
	ci := -1
	for i, title := range bug.Commits {
		if title == com.Title {
			ci = i
			break
		}
	}
	if ci < 0 {
		return false, nil
	}
	for len(bug.CommitInfo) < len(bug.Commits) {
		bug.CommitInfo = append(bug.CommitInfo, Commit{})
	}
	hash0 := bug.CommitInfo[ci].Hash
	date0 := bug.CommitInfo[ci].Date
	author0 := bug.CommitInfo[ci].Author
	needCommitInfo0 := bug.NeedCommitInfo

	bug.CommitInfo[ci].Hash = com.Hash
	bug.CommitInfo[ci].Date = com.Date
	bug.CommitInfo[ci].Author = com.Author
	bug.NeedCommitInfo = false
	for i := range bug.CommitInfo {
		if bug.CommitInfo[i].Hash == "" {
			bug.NeedCommitInfo = true
			break
		}
	}
	changed := hash0 != bug.CommitInfo[ci].Hash ||
		date0 != bug.CommitInfo[ci].Date ||
		author0 != bug.CommitInfo[ci].Author ||
		needCommitInfo0 != bug.NeedCommitInfo
	return changed, nil
}

func apiJobPoll(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.JobPollReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if len(req.Managers) == 0 {
		return nil, fmt.Errorf("no managers")
	}
	return pollPendingJobs(c, req.Managers)
}

func apiJobDone(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.JobDoneReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	err := doneJob(c, req)
	return nil, err
}

func apiUploadBuild(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.Build)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	now := timeNow(c)
	_, isNewBuild, err := uploadBuild(c, now, ns, req, BuildNormal)
	if err != nil {
		return nil, err
	}
	if isNewBuild {
		err := updateManager(c, ns, req.Manager, func(mgr *Manager, stats *ManagerStats) error {
			prevKernel, prevSyzkaller := "", ""
			if mgr.CurrentBuild != "" {
				prevBuild, err := loadBuild(c, ns, mgr.CurrentBuild)
				if err != nil {
					return err
				}
				prevKernel = prevBuild.KernelCommit
				prevSyzkaller = prevBuild.SyzkallerCommit
			}
			log.Infof(c, "new build on %v: kernel %v->%v syzkaller %v->%v",
				req.Manager, prevKernel, req.KernelCommit, prevSyzkaller, req.SyzkallerCommit)
			mgr.CurrentBuild = req.ID
			if req.KernelCommit != prevKernel {
				mgr.FailedBuildBug = ""
			}
			if req.SyzkallerCommit != prevSyzkaller {
				mgr.FailedSyzBuildBug = ""
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(req.Commits) != 0 || len(req.FixCommits) != 0 {
		for i := range req.FixCommits {
			// Reset hashes just to make sure,
			// the build does not necessary come from the master repo, so we must not remember hashes.
			req.FixCommits[i].Hash = ""
		}
		if err := addCommitsToBugs(c, ns, req.Manager, req.Commits, req.FixCommits); err != nil {
			// We've already uploaded the build successfully and manager can use it.
			// Moreover, addCommitsToBugs scans all bugs and can take long time.
			// So just log the error.
			log.Errorf(c, "failed to add commits to bugs: %v", err)
		}
	}
	return nil, nil
}

func uploadBuild(c context.Context, now time.Time, ns string, req *dashapi.Build, typ BuildType) (
	*Build, bool, error) {
	if build, err := loadBuild(c, ns, req.ID); err == nil {
		return build, false, nil
	}

	checkStrLen := func(str, name string, maxLen int) error {
		if str == "" {
			return fmt.Errorf("%v is empty", name)
		}
		if len(str) > maxLen {
			return fmt.Errorf("%v is too long (%v)", name, len(str))
		}
		return nil
	}
	if err := checkStrLen(req.Manager, "Build.Manager", MaxStringLen); err != nil {
		return nil, false, err
	}
	if err := checkStrLen(req.ID, "Build.ID", MaxStringLen); err != nil {
		return nil, false, err
	}
	if err := checkStrLen(req.KernelRepo, "Build.KernelRepo", MaxStringLen); err != nil {
		return nil, false, err
	}
	if len(req.KernelBranch) > MaxStringLen {
		return nil, false, fmt.Errorf("Build.KernelBranch is too long (%v)", len(req.KernelBranch))
	}
	if err := checkStrLen(req.SyzkallerCommit, "Build.SyzkallerCommit", MaxStringLen); err != nil {
		return nil, false, err
	}
	if len(req.CompilerID) > MaxStringLen {
		return nil, false, fmt.Errorf("Build.CompilerID is too long (%v)", len(req.CompilerID))
	}
	if len(req.KernelCommit) > MaxStringLen {
		return nil, false, fmt.Errorf("Build.KernelCommit is too long (%v)", len(req.KernelCommit))
	}
	configID, err := putText(c, ns, textKernelConfig, req.KernelConfig, true)
	if err != nil {
		return nil, false, err
	}
	build := &Build{
		Namespace:           ns,
		Manager:             req.Manager,
		ID:                  req.ID,
		Type:                typ,
		Time:                now,
		OS:                  req.OS,
		Arch:                req.Arch,
		VMArch:              req.VMArch,
		SyzkallerCommit:     req.SyzkallerCommit,
		SyzkallerCommitDate: req.SyzkallerCommitDate,
		CompilerID:          req.CompilerID,
		KernelRepo:          req.KernelRepo,
		KernelBranch:        req.KernelBranch,
		KernelCommit:        req.KernelCommit,
		KernelCommitTitle:   req.KernelCommitTitle,
		KernelCommitDate:    req.KernelCommitDate,
		KernelConfig:        configID,
	}
	if _, err := db.Put(c, buildKey(c, ns, req.ID), build); err != nil {
		return nil, false, err
	}
	return build, true, nil
}

func addCommitsToBugs(c context.Context, ns, manager string, titles []string, fixCommits []dashapi.Commit) error {
	presentCommits := make(map[string]bool)
	bugFixedBy := make(map[string][]string)
	for _, com := range titles {
		presentCommits[com] = true
	}
	for _, com := range fixCommits {
		presentCommits[com.Title] = true
		for _, bugID := range com.BugIDs {
			bugFixedBy[bugID] = append(bugFixedBy[bugID], com.Title)
		}
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return err
	}
	// Fetching all bugs in a namespace can be slow, and there is no way to filter only Open/Dup statuses.
	// So we run a separate query for each status, this both avoids fetching unnecessary data
	// and splits a long query into two (two smaller queries have lower chances of trigerring
	// timeouts than one huge).
	for _, status := range []int{BugStatusOpen, BugStatusDup} {
		err := addCommitsToBugsInStatus(c, status, ns, manager, managers, presentCommits, bugFixedBy)
		if err != nil {
			return err
		}
	}
	return nil
}

func addCommitsToBugsInStatus(c context.Context, status int, ns, manager string, managers []string,
	presentCommits map[string]bool, bugFixedBy map[string][]string) error {
	bugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).
			Filter("Status=", status)
	})
	if err != nil {
		return err
	}
	for _, bug := range bugs {
		var fixCommits []string
		for i := range bug.Reporting {
			fixCommits = append(fixCommits, bugFixedBy[bug.Reporting[i].ID]...)
		}
		sort.Strings(fixCommits)
		if err := addCommitsToBug(c, bug, manager, managers, fixCommits, presentCommits); err != nil {
			return err
		}
		if bug.Status == BugStatusDup {
			canon, err := canonicalBug(c, bug)
			if err != nil {
				return err
			}
			if canon.Status == BugStatusOpen && len(bug.Commits) == 0 {
				if err := addCommitsToBug(c, canon, manager, managers,
					fixCommits, presentCommits); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func addCommitsToBug(c context.Context, bug *Bug, manager string, managers []string,
	fixCommits []string, presentCommits map[string]bool) error {
	if !bugNeedsCommitUpdate(c, bug, manager, fixCommits, presentCommits, true) {
		return nil
	}
	now := timeNow(c)
	bugKey := bug.key(c)
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug %v: %v", bugKey.StringID(), err)
		}
		if !bugNeedsCommitUpdate(c, bug, manager, fixCommits, presentCommits, false) {
			return nil
		}
		if len(fixCommits) != 0 && !reflect.DeepEqual(bug.Commits, fixCommits) {
			bug.updateCommits(fixCommits, now)
		}
		if manager != "" {
			bug.PatchedOn = append(bug.PatchedOn, manager)
			if bug.Status == BugStatusOpen {
				fixed := true
				for _, mgr := range managers {
					if !stringInList(bug.PatchedOn, mgr) {
						fixed = false
						break
					}
				}
				if fixed {
					bug.Status = BugStatusFixed
					bug.Closed = now
				}
			}
		}
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	return db.RunInTransaction(c, tx, nil)
}

func bugNeedsCommitUpdate(c context.Context, bug *Bug, manager string, fixCommits []string,
	presentCommits map[string]bool, dolog bool) bool {
	if len(fixCommits) != 0 && !reflect.DeepEqual(bug.Commits, fixCommits) {
		if dolog {
			log.Infof(c, "bug %q is fixed with %q", bug.Title, fixCommits)
		}
		return true
	}
	if len(bug.Commits) == 0 || manager == "" || stringInList(bug.PatchedOn, manager) {
		return false
	}
	for _, com := range bug.Commits {
		if !presentCommits[com] {
			return false
		}
	}
	return true
}

func managerList(c context.Context, ns string) ([]string, error) {
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ns).
		Project("Manager").
		Distinct().
		GetAll(c, &builds)
	if err != nil {
		return nil, fmt.Errorf("failed to query builds: %v", err)
	}
	configManagers := config.Namespaces[ns].Managers
	var managers []string
	for _, build := range builds {
		if configManagers[build.Manager].Decommissioned {
			continue
		}
		managers = append(managers, build.Manager)
	}
	return managers, nil
}

func stringInList(list []string, str string) bool {
	for _, s := range list {
		if s == str {
			return true
		}
	}
	return false
}

func apiReportBuildError(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.BuildErrorReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	now := timeNow(c)
	build, _, err := uploadBuild(c, now, ns, &req.Build, BuildFailed)
	if err != nil {
		return nil, err
	}
	req.Crash.BuildID = req.Build.ID
	bug, err := reportCrash(c, build, &req.Crash)
	if err != nil {
		return nil, err
	}
	if err := updateManager(c, ns, req.Build.Manager, func(mgr *Manager, stats *ManagerStats) error {
		log.Infof(c, "failed build on %v: kernel=%v", req.Build.Manager, req.Build.KernelCommit)
		if req.Build.KernelCommit != "" {
			mgr.FailedBuildBug = bug.keyHash()
		} else {
			mgr.FailedSyzBuildBug = bug.keyHash()
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

const corruptedReportTitle = "corrupted report"

func apiReportCrash(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.Crash)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	build, err := loadBuild(c, ns, req.BuildID)
	if err != nil {
		return nil, err
	}
	if !config.Namespaces[ns].TransformCrash(build, req) {
		return new(dashapi.ReportCrashResp), nil
	}
	bug, err := reportCrash(c, build, req)
	if err != nil {
		return nil, err
	}
	resp := &dashapi.ReportCrashResp{
		NeedRepro: needRepro(c, bug),
	}
	return resp, nil
}

func reportCrash(c context.Context, build *Build, req *dashapi.Crash) (*Bug, error) {
	req.Title = limitLength(req.Title, maxTextLen)
	req.Maintainers = email.MergeEmailLists(req.Maintainers)
	if req.Corrupted {
		// The report is corrupted and the title is most likely invalid.
		// Such reports are usually unactionable and are discarded.
		// Collect them into a single bin.
		req.Title = corruptedReportTitle
	}

	ns := build.Namespace
	bug, bugKey, err := findBugForCrash(c, ns, req.Title)
	if err != nil {
		return nil, err
	}
	if active, err := isActiveBug(c, bug); err != nil {
		return nil, err
	} else if !active {
		bug, bugKey, err = createBugForCrash(c, ns, req)
		if err != nil {
			return nil, err
		}
	}

	now := timeNow(c)
	reproLevel := ReproLevelNone
	if len(req.ReproC) != 0 {
		reproLevel = ReproLevelC
	} else if len(req.ReproSyz) != 0 {
		reproLevel = ReproLevelSyz
	}
	save := reproLevel != ReproLevelNone ||
		bug.NumCrashes < maxCrashes ||
		now.Sub(bug.LastSavedCrash) > time.Hour ||
		bug.NumCrashes%20 == 0
	if save {
		if err := saveCrash(c, ns, req, bugKey, build); err != nil {
			return nil, err
		}
	} else {
		log.Infof(c, "not saving crash for %q", bug.Title)
	}

	tx := func(c context.Context) error {
		bug = new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %v", err)
		}
		bug.NumCrashes++
		bug.LastTime = now
		if save {
			bug.LastSavedCrash = now
		}
		if reproLevel != ReproLevelNone {
			bug.NumRepro++
			bug.LastReproTime = now
		}
		if bug.ReproLevel < reproLevel {
			bug.ReproLevel = reproLevel
		}
		if len(req.Report) != 0 {
			bug.HasReport = true
		}
		if !stringInList(bug.HappenedOn, build.Manager) {
			bug.HappenedOn = append(bug.HappenedOn, build.Manager)
		}
		if _, err = db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true}); err != nil {
		return nil, err
	}
	if save {
		purgeOldCrashes(c, bug, bugKey)
	}
	return bug, nil
}

func saveCrash(c context.Context, ns string, req *dashapi.Crash, bugKey *db.Key, build *Build) error {
	// Reporting priority of this crash.
	prio := int64(kernelRepoInfo(build).ReportingPriority) * 1e6
	if len(req.ReproC) != 0 {
		prio += 4e12
	} else if len(req.ReproSyz) != 0 {
		prio += 2e12
	}
	if build.Arch == "amd64" {
		prio += 1e3
	}
	crash := &Crash{
		Manager: build.Manager,
		BuildID: req.BuildID,
		Time:    timeNow(c),
		Maintainers: email.MergeEmailLists(req.Maintainers,
			GetEmails(req.Recipients, dashapi.To),
			GetEmails(req.Recipients, dashapi.Cc)),
		ReproOpts: req.ReproOpts,
		ReportLen: prio,
	}
	var err error
	if crash.Log, err = putText(c, ns, textCrashLog, req.Log, false); err != nil {
		return err
	}
	if crash.Report, err = putText(c, ns, textCrashReport, req.Report, false); err != nil {
		return err
	}
	if crash.ReproSyz, err = putText(c, ns, textReproSyz, req.ReproSyz, false); err != nil {
		return err
	}
	if crash.ReproC, err = putText(c, ns, textReproC, req.ReproC, false); err != nil {
		return err
	}
	crashKey := db.NewIncompleteKey(c, "Crash", bugKey)
	if _, err = db.Put(c, crashKey, crash); err != nil {
		return fmt.Errorf("failed to put crash: %v", err)
	}
	return nil
}

func purgeOldCrashes(c context.Context, bug *Bug, bugKey *db.Key) {
	const purgeEvery = 10
	if bug.NumCrashes <= 2*maxCrashes || (bug.NumCrashes-1)%purgeEvery != 0 {
		return
	}
	var crashes []*Crash
	keys, err := db.NewQuery("Crash").
		Ancestor(bugKey).
		Filter("Reported=", time.Time{}).
		GetAll(c, &crashes)
	if err != nil {
		log.Errorf(c, "failed to fetch purge crashes: %v", err)
		return
	}
	keyMap := make(map[*Crash]*db.Key)
	for i, crash := range crashes {
		keyMap[crash] = keys[i]
	}
	// Newest first.
	sort.Slice(crashes, func(i, j int) bool {
		return crashes[i].Time.After(crashes[j].Time)
	})
	var toDelete []*db.Key
	latestOnManager := make(map[string]bool)
	deleted, reproCount, noreproCount := 0, 0, 0
	for _, crash := range crashes {
		if !crash.Reported.IsZero() {
			log.Errorf(c, "purging reported crash?")
			continue
		}
		// Preserve latest crash on each manager.
		if !latestOnManager[crash.Manager] {
			latestOnManager[crash.Manager] = true
			continue
		}
		// Preserve maxCrashes latest crashes with repro and without repro.
		count := &noreproCount
		if crash.ReproSyz != 0 || crash.ReproC != 0 {
			count = &reproCount
		}
		if *count < maxCrashes {
			*count++
			continue
		}
		toDelete = append(toDelete, keyMap[crash])
		if crash.Log != 0 {
			toDelete = append(toDelete, db.NewKey(c, textCrashLog, "", crash.Log, nil))
		}
		if crash.Report != 0 {
			toDelete = append(toDelete, db.NewKey(c, textCrashReport, "", crash.Report, nil))
		}
		if crash.ReproSyz != 0 {
			toDelete = append(toDelete, db.NewKey(c, textReproSyz, "", crash.ReproSyz, nil))
		}
		if crash.ReproC != 0 {
			toDelete = append(toDelete, db.NewKey(c, textReproC, "", crash.ReproC, nil))
		}
		deleted++
		if deleted == 2*purgeEvery {
			break
		}
	}
	if len(toDelete) == 0 {
		return
	}
	if err := db.DeleteMulti(c, toDelete); err != nil {
		log.Errorf(c, "failed to delete old crashes: %v", err)
		return
	}
	log.Infof(c, "deleted %v crashes for bug %q", deleted, bug.Title)
}

func apiReportFailedRepro(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.CrashID)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	req.Title = limitLength(req.Title, maxTextLen)

	bug, bugKey, err := findBugForCrash(c, ns, req.Title)
	if err != nil {
		return nil, err
	}
	if bug == nil {
		return nil, fmt.Errorf("%v: can't find bug for crash %q", ns, req.Title)
	}
	now := timeNow(c)
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %v", err)
		}
		bug.NumRepro++
		bug.LastReproTime = now
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	err = db.RunInTransaction(c, tx, &db.TransactionOptions{
		XG:       true,
		Attempts: 30,
	})
	return nil, err
}

func apiNeedRepro(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.CrashID)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if req.Corrupted {
		resp := &dashapi.NeedReproResp{
			NeedRepro: false,
		}
		return resp, nil
	}
	req.Title = limitLength(req.Title, maxTextLen)

	bug, _, err := findBugForCrash(c, ns, req.Title)
	if err != nil {
		return nil, err
	}
	if bug == nil {
		return nil, fmt.Errorf("%v: can't find bug for crash %q", ns, req.Title)
	}
	resp := &dashapi.NeedReproResp{
		NeedRepro: needRepro(c, bug),
	}
	return resp, nil
}

func apiManagerStats(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.ManagerStatsReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	now := timeNow(c)
	err := updateManager(c, ns, req.Name, func(mgr *Manager, stats *ManagerStats) error {
		mgr.Link = req.Addr
		mgr.LastAlive = now
		mgr.CurrentUpTime = req.UpTime
		if cur := int64(req.Corpus); cur > stats.MaxCorpus {
			stats.MaxCorpus = cur
		}
		if cur := int64(req.PCs); cur > stats.MaxPCs {
			stats.MaxPCs = cur
		}
		if cur := int64(req.Cover); cur > stats.MaxCover {
			stats.MaxCover = cur
		}
		if cur := int64(req.CrashTypes); cur > stats.CrashTypes {
			stats.CrashTypes = cur
		}
		stats.TotalFuzzingTime += req.FuzzingTime
		stats.TotalCrashes += int64(req.Crashes)
		stats.SuppressedCrashes += int64(req.SuppressedCrashes)
		stats.TotalExecs += int64(req.Execs)
		return nil
	})
	return nil, err
}

func apiBugList(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		KeysOnly().
		GetAll(c, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %v", err)
	}
	resp := &dashapi.BugListResp{}
	for _, key := range keys {
		resp.List = append(resp.List, key.StringID())
	}
	return resp, nil
}

func apiLoadBug(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.LoadBugReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	bug := new(Bug)
	bugKey := db.NewKey(c, "Bug", req.ID, 0, nil)
	if err := db.Get(c, bugKey, bug); err != nil {
		return nil, fmt.Errorf("failed to get bug: %v", err)
	}
	if bug.Namespace != ns {
		return nil, fmt.Errorf("no such bug")
	}
	if bug.sanitizeAccess(AccessPublic) > AccessPublic {
		return nil, nil
	}
	crash, _, err := findCrashForBug(c, bug)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, ns, crash.BuildID)
	if err != nil {
		return nil, err
	}
	reproSyz, _, err := getText(c, textReproSyz, crash.ReproSyz)
	if err != nil {
		return nil, err
	}
	reproC, _, err := getText(c, textReproC, crash.ReproC)
	if err != nil {
		return nil, err
	}
	statuses := map[int]string{
		BugStatusOpen:    "open",
		BugStatusFixed:   "fixed",
		BugStatusInvalid: "invalid",
		BugStatusDup:     "dup",
	}
	resp := &dashapi.LoadBugResp{
		ID:              req.ID,
		Title:           bug.displayTitle(),
		Status:          statuses[bug.Status],
		SyzkallerCommit: build.SyzkallerCommit,
		ReproOpts:       crash.ReproOpts,
		ReproSyz:        reproSyz,
		ReproC:          reproC,
	}
	return resp, nil
}

func findBugForCrash(c context.Context, ns, title string) (*Bug, *db.Key, error) {
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Title=", title).
		Order("-Seq").
		Limit(1).
		GetAll(c, &bugs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query bugs: %v", err)
	}
	if len(bugs) == 0 {
		return nil, nil, nil
	}
	return bugs[0], keys[0], nil
}

func createBugForCrash(c context.Context, ns string, req *dashapi.Crash) (*Bug, *db.Key, error) {
	var bug *Bug
	var bugKey *db.Key
	now := timeNow(c)
	tx := func(c context.Context) error {
		for seq := int64(0); ; seq++ {
			bug = new(Bug)
			bugHash := bugKeyHash(ns, req.Title, seq)
			bugKey = db.NewKey(c, "Bug", bugHash, 0, nil)
			if err := db.Get(c, bugKey, bug); err != nil {
				if err != db.ErrNoSuchEntity {
					return fmt.Errorf("failed to get bug: %v", err)
				}
				bug = &Bug{
					Namespace:  ns,
					Seq:        seq,
					Title:      req.Title,
					Status:     BugStatusOpen,
					NumCrashes: 0,
					NumRepro:   0,
					ReproLevel: ReproLevelNone,
					HasReport:  false,
					FirstTime:  now,
					LastTime:   now,
				}
				createBugReporting(bug, config.Namespaces[ns])
				if bugKey, err = db.Put(c, bugKey, bug); err != nil {
					return fmt.Errorf("failed to put new bug: %v", err)
				}
				return nil
			}
			canon, err := canonicalBug(c, bug)
			if err != nil {
				return err
			}
			if canon.Status != BugStatusOpen {
				continue
			}
			return nil
		}
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{
		XG:       true,
		Attempts: 30,
	}); err != nil {
		return nil, nil, err
	}
	return bug, bugKey, nil
}

func createBugReporting(bug *Bug, cfg *Config) {
	for len(bug.Reporting) < len(cfg.Reporting) {
		rep := &cfg.Reporting[len(bug.Reporting)]
		bug.Reporting = append(bug.Reporting, BugReporting{
			Name: rep.Name,
			ID:   bugReportingHash(bug.keyHash(), rep.Name),
		})
	}
}

func isActiveBug(c context.Context, bug *Bug) (bool, error) {
	if bug == nil {
		return false, nil
	}
	canon, err := canonicalBug(c, bug)
	if err != nil {
		return false, err
	}
	return canon.Status == BugStatusOpen, nil
}

func needRepro(c context.Context, bug *Bug) bool {
	if !needReproForBug(c, bug) {
		return false
	}
	canon, err := canonicalBug(c, bug)
	if err != nil {
		log.Errorf(c, "failed to get canonical bug: %v", err)
		return false
	}
	return needReproForBug(c, canon)
}

func needReproForBug(c context.Context, bug *Bug) bool {
	return bug.ReproLevel < ReproLevelC &&
		len(bug.Commits) == 0 &&
		bug.Title != corruptedReportTitle &&
		config.Namespaces[bug.Namespace].NeedRepro(bug) &&
		(bug.NumRepro < maxReproPerBug ||
			bug.ReproLevel == ReproLevelNone &&
				timeSince(c, bug.LastReproTime) > reproRetryPeriod)
}

func putText(c context.Context, ns, tag string, data []byte, dedup bool) (int64, error) {
	if ns == "" {
		return 0, fmt.Errorf("putting text outside of namespace")
	}
	if len(data) == 0 {
		return 0, nil
	}
	const (
		maxTextLen       = 2 << 20
		maxCompressedLen = 1000 << 10 // datastore entity limit is 1MB
	)
	if len(data) > maxTextLen {
		data = data[:maxTextLen]
	}
	b := new(bytes.Buffer)
	for {
		z, _ := gzip.NewWriterLevel(b, gzip.BestCompression)
		z.Write(data)
		z.Close()
		if len(b.Bytes()) < maxCompressedLen {
			break
		}
		data = data[:len(data)/10*9]
		b.Reset()
	}
	var key *db.Key
	if dedup {
		h := hash.Hash([]byte(ns), b.Bytes())
		key = db.NewKey(c, tag, "", h.Truncate64(), nil)
	} else {
		key = db.NewIncompleteKey(c, tag, nil)
	}
	text := &Text{
		Namespace: ns,
		Text:      b.Bytes(),
	}
	key, err := db.Put(c, key, text)
	if err != nil {
		return 0, err
	}
	return key.IntID(), nil
}

func getText(c context.Context, tag string, id int64) ([]byte, string, error) {
	if id == 0 {
		return nil, "", nil
	}
	text := new(Text)
	if err := db.Get(c, db.NewKey(c, tag, "", id, nil), text); err != nil {
		return nil, "", fmt.Errorf("failed to read text %v: %v", tag, err)
	}
	d, err := gzip.NewReader(bytes.NewBuffer(text.Text))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read text %v: %v", tag, err)
	}
	data, err := ioutil.ReadAll(d)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read text %v: %v", tag, err)
	}
	return data, text.Namespace, nil
}

// limitLength essentially does return s[:max],
// but it ensures that we dot not split UTF-8 rune in half.
// Otherwise appengine python scripts will break badly.
func limitLength(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	for {
		s = s[:max]
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			return s
		}
		max--
	}
}

func GetEmails(r dashapi.Recipients, filter dashapi.RecipientType) []string {
	emails := []string{}
	for _, user := range r {
		if user.Type == filter {
			emails = append(emails, user.Address.Address)
		}
	}
	sort.Strings(emails)
	return emails
}
