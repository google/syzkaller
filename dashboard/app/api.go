// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

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
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

func init() {
	http.Handle("/api", handleJSON(handleAPI))
}

var apiHandlers = map[string]APIHandler{
	"log_error":             apiLogError,
	"job_poll":              apiJobPoll,
	"job_done":              apiJobDone,
	"reporting_poll_bugs":   apiReportingPollBugs,
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
}

type JSONHandler func(c context.Context, r *http.Request) (interface{}, error)
type APIHandler func(c context.Context, r *http.Request, payload []byte) (interface{}, error)
type APINamespaceHandler func(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error)

const maxReproPerBug = 10

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
			json.NewEncoder(gz).Encode(reply)
			gz.Close()
		} else {
			json.NewEncoder(w).Encode(reply)
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
	var bugs []*Bug
	_, err := datastore.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Status<", BugStatusFixed).
		GetAll(c, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %v", err)
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
	reportEmail := ""
	for _, reporting := range config.Namespaces[ns].Reporting {
		if _, ok := reporting.Config.(*EmailConfig); ok {
			reportEmail = ownEmail(c)
			break
		}
	}
	resp := &dashapi.BuilderPollResp{
		PendingCommits: commits,
		ReportEmail:    reportEmail,
	}
	return resp, nil
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
	isNewBuild, err := uploadBuild(c, now, ns, req, BuildNormal)
	if err != nil {
		return nil, err
	}
	if len(req.Commits) != 0 || len(req.FixCommits) != 0 {
		if err := addCommitsToBugs(c, ns, req.Manager, req.Commits, req.FixCommits); err != nil {
			return nil, err
		}
	}
	if isNewBuild {
		if err := updateManager(c, ns, req.Manager, func(mgr *Manager, stats *ManagerStats) {
			mgr.CurrentBuild = req.ID
			mgr.FailedBuildBug = ""
		}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func uploadBuild(c context.Context, now time.Time, ns string, req *dashapi.Build, typ BuildType) (bool, error) {
	if _, err := loadBuild(c, ns, req.ID); err == nil {
		return false, nil
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
		return false, err
	}
	if err := checkStrLen(req.ID, "Build.ID", MaxStringLen); err != nil {
		return false, err
	}
	if err := checkStrLen(req.KernelRepo, "Build.KernelRepo", MaxStringLen); err != nil {
		return false, err
	}
	if len(req.KernelBranch) > MaxStringLen {
		return false, fmt.Errorf("Build.KernelBranch is too long (%v)", len(req.KernelBranch))
	}
	if err := checkStrLen(req.SyzkallerCommit, "Build.SyzkallerCommit", MaxStringLen); err != nil {
		return false, err
	}
	if err := checkStrLen(req.CompilerID, "Build.CompilerID", MaxStringLen); err != nil {
		return false, err
	}
	if err := checkStrLen(req.KernelCommit, "Build.KernelCommit", MaxStringLen); err != nil {
		return false, err
	}
	configID, err := putText(c, ns, textKernelConfig, req.KernelConfig, true)
	if err != nil {
		return false, err
	}
	build := &Build{
		Namespace:         ns,
		Manager:           req.Manager,
		ID:                req.ID,
		Type:              typ,
		Time:              now,
		OS:                req.OS,
		Arch:              req.Arch,
		VMArch:            req.VMArch,
		SyzkallerCommit:   req.SyzkallerCommit,
		CompilerID:        req.CompilerID,
		KernelRepo:        req.KernelRepo,
		KernelBranch:      req.KernelBranch,
		KernelCommit:      req.KernelCommit,
		KernelCommitTitle: req.KernelCommitTitle,
		KernelCommitDate:  req.KernelCommitDate,
		KernelConfig:      configID,
	}
	if _, err := datastore.Put(c, buildKey(c, ns, req.ID), build); err != nil {
		return false, err
	}
	return true, nil
}

func addCommitsToBugs(c context.Context, ns, manager string,
	titles []string, fixCommits []dashapi.FixCommit) error {
	presentCommits := make(map[string]bool)
	bugFixedBy := make(map[string][]string)
	for _, com := range titles {
		presentCommits[com] = true
	}
	for _, com := range fixCommits {
		presentCommits[com.Title] = true
		bugFixedBy[com.BugID] = append(bugFixedBy[com.BugID], com.Title)
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return err
	}
	var bugs []*Bug
	keys, err := datastore.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Status<", BugStatusFixed).
		GetAll(c, &bugs)
	if err != nil {
		return fmt.Errorf("failed to query bugs: %v", err)
	}
	now := timeNow(c)
	for i, bug := range bugs {
		var fixCommits []string
		for i := range bug.Reporting {
			fixCommits = append(fixCommits, bugFixedBy[bug.Reporting[i].ID]...)
		}
		sort.Strings(fixCommits)
		if !bugNeedsCommitUpdate(c, bug, manager, fixCommits, presentCommits) {
			continue
		}
		tx := func(c context.Context) error {
			bug := new(Bug)
			if err := datastore.Get(c, keys[i], bug); err != nil {
				return fmt.Errorf("failed to get bug %v: %v", keys[i].StringID(), err)
			}
			if !bugNeedsCommitUpdate(nil, bug, manager, fixCommits, presentCommits) {
				return nil
			}
			if len(fixCommits) != 0 && !reflect.DeepEqual(bug.Commits, fixCommits) {
				bug.Commits = fixCommits
				bug.PatchedOn = nil
			}
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
			if _, err := datastore.Put(c, keys[i], bug); err != nil {
				return fmt.Errorf("failed to put bug: %v", err)
			}
			return nil
		}
		if err := datastore.RunInTransaction(c, tx, nil); err != nil {
			return err
		}
	}
	return nil
}

func managerList(c context.Context, ns string) ([]string, error) {
	var builds []*Build
	_, err := datastore.NewQuery("Build").
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

func bugNeedsCommitUpdate(c context.Context, bug *Bug, manager string, fixCommits []string,
	presentCommits map[string]bool) bool {
	if len(fixCommits) != 0 && !reflect.DeepEqual(bug.Commits, fixCommits) {
		if c != nil {
			log.Infof(c, "bug %q is fixed with %q", bug.Title, fixCommits)
		}
		return true
	}
	if len(bug.Commits) == 0 || stringInList(bug.PatchedOn, manager) {
		return false
	}
	for _, com := range bug.Commits {
		if !presentCommits[com] {
			return false
		}
	}
	return true
}

func stringInList(list []string, str string) bool {
	for _, s := range list {
		if s == str {
			return true
		}
	}
	return false
}

func stringsInList(list, str []string) bool {
	for _, s := range str {
		if !stringInList(list, s) {
			return false
		}
	}
	return true
}

func apiReportBuildError(c context.Context, ns string, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.BuildErrorReq)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	now := timeNow(c)
	if _, err := uploadBuild(c, now, ns, &req.Build, BuildFailed); err != nil {
		return nil, err
	}
	req.Crash.BuildID = req.Build.ID
	bug, err := reportCrash(c, ns, &req.Crash)
	if err != nil {
		return nil, err
	}
	if err := updateManager(c, ns, req.Build.Manager, func(mgr *Manager, stats *ManagerStats) {
		mgr.FailedBuildBug = bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
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
	bug, err := reportCrash(c, ns, req)
	if err != nil {
		return nil, err
	}
	resp := &dashapi.ReportCrashResp{
		NeedRepro: needRepro(c, bug),
	}
	return resp, nil
}

func reportCrash(c context.Context, ns string, req *dashapi.Crash) (*Bug, error) {
	req.Title = limitLength(req.Title, maxTextLen)
	req.Maintainers = email.MergeEmailLists(req.Maintainers)
	if req.Corrupted {
		// The report is corrupted and the title is most likely invalid.
		// Such reports are usually unactionable and are discarded.
		// Collect them into a single bin.
		req.Title = corruptedReportTitle
	}

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
	build, err := loadBuild(c, ns, req.BuildID)
	if err != nil {
		return nil, err
	}

	now := timeNow(c)
	reproLevel := ReproLevelNone
	if len(req.ReproC) != 0 {
		reproLevel = ReproLevelC
	} else if len(req.ReproSyz) != 0 {
		reproLevel = ReproLevelSyz
	}
	saveCrash := bug.NumCrashes < maxCrashes ||
		now.Sub(bug.LastTime) > time.Hour ||
		reproLevel != ReproLevelNone
	if saveCrash {
		// Reporting priority of this crash.
		// Currently it is computed only from repository ReportingPriority and Arch,
		// but can be extended to account for other factors as well.
		prio := kernelRepoInfo(build).ReportingPriority * 1e6
		if build.Arch == "amd64" {
			prio += 1e3
		}
		crash := &Crash{
			Manager:     build.Manager,
			BuildID:     req.BuildID,
			Time:        now,
			Maintainers: req.Maintainers,
			ReproOpts:   req.ReproOpts,
			ReportLen:   prio,
		}
		if crash.Log, err = putText(c, ns, textCrashLog, req.Log, false); err != nil {
			return nil, err
		}
		if crash.Report, err = putText(c, ns, textCrashReport, req.Report, false); err != nil {
			return nil, err
		}
		if crash.ReproSyz, err = putText(c, ns, textReproSyz, req.ReproSyz, false); err != nil {
			return nil, err
		}
		if crash.ReproC, err = putText(c, ns, textReproC, req.ReproC, false); err != nil {
			return nil, err
		}

		crashKey := datastore.NewIncompleteKey(c, "Crash", bugKey)
		if _, err = datastore.Put(c, crashKey, crash); err != nil {
			return nil, fmt.Errorf("failed to put crash: %v", err)
		}
	} else {
		log.Infof(c, "not saving crash for %q", bug.Title)
	}

	tx := func(c context.Context) error {
		bug = new(Bug)
		if err := datastore.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %v", err)
		}
		bug.NumCrashes++
		bug.LastTime = now
		if reproLevel != ReproLevelNone {
			bug.NumRepro++
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
		if _, err = datastore.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	if err := datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{XG: true}); err != nil {
		return nil, err
	}
	if saveCrash {
		purgeOldCrashes(c, bug, bugKey)
	}
	return bug, nil
}

func purgeOldCrashes(c context.Context, bug *Bug, bugKey *datastore.Key) {
	if bug.NumCrashes <= maxCrashes || bug.NumCrashes%10 != 0 {
		return
	}
	var crashes []*Crash
	keys, err := datastore.NewQuery("Crash").
		Ancestor(bugKey).
		Filter("ReproC=", 0).
		Filter("ReproSyz=", 0).
		Filter("Reported=", time.Time{}).
		GetAll(c, &crashes)
	if err != nil {
		log.Errorf(c, "failed to fetch purge crashes: %v", err)
		return
	}
	if len(keys) <= maxCrashes {
		return
	}
	keyMap := make(map[*Crash]*datastore.Key)
	for i, crash := range crashes {
		keyMap[crash] = keys[i]
	}
	// Newest first.
	sort.Slice(crashes, func(i, j int) bool {
		return crashes[i].Time.After(crashes[j].Time)
	})
	// Find latest crash on each manager.
	latestOnManager := make(map[string]*Crash)
	for _, crash := range crashes {
		if latestOnManager[crash.Manager] == nil {
			latestOnManager[crash.Manager] = crash
		}
	}
	// Oldest first but move latest crash on each manager to the end (preserve them).
	sort.Slice(crashes, func(i, j int) bool {
		latesti := latestOnManager[crashes[i].Manager] == crashes[i]
		latestj := latestOnManager[crashes[j].Manager] == crashes[j]
		if latesti != latestj {
			return latestj
		}
		return crashes[i].Time.Before(crashes[j].Time)
	})
	crashes = crashes[:len(crashes)-maxCrashes]
	var toDelete []*datastore.Key
	for _, crash := range crashes {
		if crash.ReproSyz != 0 || crash.ReproC != 0 || !crash.Reported.IsZero() {
			log.Errorf(c, "purging reproducer?")
			continue
		}
		toDelete = append(toDelete, keyMap[crash])
		if crash.Log != 0 {
			toDelete = append(toDelete, datastore.NewKey(c, textCrashLog, "", crash.Log, nil))
		}
		if crash.Report != 0 {
			toDelete = append(toDelete, datastore.NewKey(c, textCrashReport, "", crash.Report, nil))
		}
	}
	if err := datastore.DeleteMulti(c, toDelete); err != nil {
		log.Errorf(c, "failed to delete old crashes: %v", err)
		return
	}
	log.Infof(c, "deleted %v crashes for bug %q", len(crashes), bug.Title)
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
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := datastore.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %v", err)
		}
		bug.NumRepro++
		if _, err := datastore.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	err = datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{
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
	err := updateManager(c, ns, req.Name, func(mgr *Manager, stats *ManagerStats) {
		mgr.Link = req.Addr
		mgr.LastAlive = now
		mgr.CurrentUpTime = req.UpTime
		if cur := int64(req.Corpus); cur > stats.MaxCorpus {
			stats.MaxCorpus = cur
		}
		if cur := int64(req.Cover); cur > stats.MaxCover {
			stats.MaxCover = cur
		}
		stats.TotalFuzzingTime += req.FuzzingTime
		stats.TotalCrashes += int64(req.Crashes)
		stats.TotalExecs += int64(req.Execs)
	})
	return nil, err
}

func findBugForCrash(c context.Context, ns, title string) (*Bug, *datastore.Key, error) {
	var bugs []*Bug
	keys, err := datastore.NewQuery("Bug").
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

func createBugForCrash(c context.Context, ns string, req *dashapi.Crash) (*Bug, *datastore.Key, error) {
	var bug *Bug
	var bugKey *datastore.Key
	now := timeNow(c)
	tx := func(c context.Context) error {
		for seq := int64(0); ; seq++ {
			bug = new(Bug)
			bugHash := bugKeyHash(ns, req.Title, seq)
			bugKey = datastore.NewKey(c, "Bug", bugHash, 0, nil)
			if err := datastore.Get(c, bugKey, bug); err != nil {
				if err != datastore.ErrNoSuchEntity {
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
				for _, rep := range config.Namespaces[ns].Reporting {
					bug.Reporting = append(bug.Reporting, BugReporting{
						Name: rep.Name,
						ID:   bugReportingHash(bugHash, rep.Name),
					})
				}
				if bugKey, err = datastore.Put(c, bugKey, bug); err != nil {
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
	if err := datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{
		XG:       true,
		Attempts: 30,
	}); err != nil {
		return nil, nil, err
	}
	return bug, bugKey, nil
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
	if !needReproForBug(bug) {
		return false
	}
	canon, err := canonicalBug(c, bug)
	if err != nil {
		log.Errorf(c, "failed to get canonical bug: %v", err)
		return false
	}
	return needReproForBug(canon)
}

func needReproForBug(bug *Bug) bool {
	return bug.ReproLevel < ReproLevelC &&
		bug.NumRepro < maxReproPerBug &&
		len(bug.Commits) == 0 &&
		bug.Title != corruptedReportTitle
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
	var key *datastore.Key
	if dedup {
		h := hash.Hash([]byte(ns), b.Bytes())
		key = datastore.NewKey(c, tag, "", h.Truncate64(), nil)
	} else {
		key = datastore.NewIncompleteKey(c, tag, nil)
	}
	text := &Text{
		Namespace: ns,
		Text:      b.Bytes(),
	}
	key, err := datastore.Put(c, key, text)
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
	if err := datastore.Get(c, datastore.NewKey(c, tag, "", id, nil), text); err != nil {
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
