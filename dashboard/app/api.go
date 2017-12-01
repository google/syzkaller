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
	"log_error":        apiLogError,
	"job_poll":         apiJobPoll,
	"job_done":         apiJobDone,
	"reporting_poll":   apiReportingPoll,
	"reporting_update": apiReportingUpdate,
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
type APIHandler func(c context.Context, r *http.Request) (interface{}, error)
type APINamespaceHandler func(c context.Context, ns string, r *http.Request) (interface{}, error)

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
			log.Errorf(c, "%v", err)
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
	ns, err := checkClient(c, r.FormValue("client"), r.FormValue("key"))
	if err != nil {
		log.Warningf(c, "%v", err)
		return nil, fmt.Errorf("unauthorized request")
	}
	method := r.FormValue("method")
	handler := apiHandlers[method]
	if handler != nil {
		return handler(c, r)
	}
	nsHandler := apiNamespaceHandlers[method]
	if nsHandler == nil {
		return nil, fmt.Errorf("unknown api method %q", method)
	}
	if ns == "" {
		return nil, fmt.Errorf("method %q must be called within a namespace", method)
	}
	return nsHandler(c, ns, r)
}

func checkClient(c context.Context, name0, key0 string) (string, error) {
	for name, key := range config.Clients {
		if name == name0 {
			if key != key0 {
				return "", fmt.Errorf("wrong client %q key", name0)
			}
			return "", nil
		}
	}
	for ns, cfg := range config.Namespaces {
		for name, key := range cfg.Clients {
			if name == name0 {
				if key != key0 {
					return "", fmt.Errorf("wrong client %q key", name0)
				}
				return ns, nil
			}
		}
	}
	return "", fmt.Errorf("unauthorized api request from %q", name0)
}

func apiLogError(c context.Context, r *http.Request) (interface{}, error) {
	req := new(dashapi.LogEntry)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	log.Errorf(c, "%v: %v", req.Name, req.Text)
	return nil, nil
}

func apiBuilderPoll(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.BuilderPollReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
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
	resp := &dashapi.BuilderPollResp{
		PendingCommits: commits,
	}
	return resp, nil
}

func apiJobPoll(c context.Context, r *http.Request) (interface{}, error) {
	req := new(dashapi.JobPollReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if len(req.Managers) == 0 {
		return nil, fmt.Errorf("no managers")
	}
	return pollPendingJobs(c, req.Managers)
}

func apiJobDone(c context.Context, r *http.Request) (interface{}, error) {
	req := new(dashapi.JobDoneReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	err := doneJob(c, req)
	return nil, err
}

func apiUploadBuild(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.Build)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if err := uploadBuild(c, ns, req, BuildNormal); err != nil {
		return nil, err
	}
	if len(req.Commits) != 0 {
		if err := addCommitsToBugs(c, ns, req.Manager, req.Commits); err != nil {
			return nil, err
		}
	}
	if err := updateManager(c, ns, req.Manager, func(mgr *Manager, stats *ManagerStats) {
		mgr.CurrentBuild = req.ID
		mgr.FailedBuildBug = ""
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

func uploadBuild(c context.Context, ns string, req *dashapi.Build, typ BuildType) error {
	if _, err := loadBuild(c, ns, req.ID); err == nil {
		return nil
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
		return err
	}
	if err := checkStrLen(req.ID, "Build.ID", MaxStringLen); err != nil {
		return err
	}
	if err := checkStrLen(req.KernelRepo, "Build.KernelRepo", MaxStringLen); err != nil {
		return err
	}
	if err := checkStrLen(req.KernelBranch, "Build.KernelBranch", MaxStringLen); err != nil {
		return err
	}
	if err := checkStrLen(req.SyzkallerCommit, "Build.SyzkallerCommit", MaxStringLen); err != nil {
		return err
	}
	if err := checkStrLen(req.CompilerID, "Build.CompilerID", MaxStringLen); err != nil {
		return err
	}
	if err := checkStrLen(req.KernelCommit, "Build.KernelCommit", MaxStringLen); err != nil {
		return err
	}
	configID, err := putText(c, ns, "KernelConfig", req.KernelConfig, true)
	if err != nil {
		return err
	}
	build := &Build{
		Namespace:       ns,
		Manager:         req.Manager,
		ID:              req.ID,
		Type:            typ,
		Time:            timeNow(c),
		OS:              req.OS,
		Arch:            req.Arch,
		VMArch:          req.VMArch,
		SyzkallerCommit: req.SyzkallerCommit,
		CompilerID:      req.CompilerID,
		KernelRepo:      req.KernelRepo,
		KernelBranch:    req.KernelBranch,
		KernelCommit:    req.KernelCommit,
		KernelConfig:    configID,
	}
	if _, err := datastore.Put(c, buildKey(c, ns, req.ID), build); err != nil {
		return err
	}
	return nil
}

func addCommitsToBugs(c context.Context, ns, manager string, commits []string) error {
	commitMap := make(map[string]bool)
	for _, com := range commits {
		commitMap[com] = true
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
		if !fixedWith(bug, manager, commitMap) {
			continue
		}
		tx := func(c context.Context) error {
			bug := new(Bug)
			if err := datastore.Get(c, keys[i], bug); err != nil {
				return fmt.Errorf("failed to get bug %v: %v", keys[i].StringID(), err)
			}
			if !fixedWith(bug, manager, commitMap) {
				return nil
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
	decommissioned := config.Namespaces[ns].DecommissionedManagers
	var managers []string
	for _, build := range builds {
		if _, ok := decommissioned[build.Manager]; ok {
			continue
		}
		managers = append(managers, build.Manager)
	}
	return managers, nil
}

func fixedWith(bug *Bug, manager string, commits map[string]bool) bool {
	if stringInList(bug.PatchedOn, manager) {
		return false
	}
	for _, com := range bug.Commits {
		if !commits[com] {
			return false
		}
	}
	return len(bug.Commits) > 0
}

func stringInList(list []string, str string) bool {
	for _, s := range list {
		if s == str {
			return true
		}
	}
	return false
}

func apiReportBuildError(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.BuildErrorReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	if err := uploadBuild(c, ns, &req.Build, BuildFailed); err != nil {
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

func apiReportCrash(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.Crash)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
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

	now := timeNow(c)
	reproLevel := ReproLevelNone
	if len(req.ReproC) != 0 {
		reproLevel = ReproLevelC
	} else if len(req.ReproSyz) != 0 {
		reproLevel = ReproLevelSyz
	}
	saveCrash := bug.NumCrashes < 1000 ||
		now.Sub(bug.LastTime) > time.Hour ||
		reproLevel != ReproLevelNone
	if saveCrash {
		build, err := loadBuild(c, ns, req.BuildID)
		if err != nil {
			return nil, err
		}

		crash := &Crash{
			Manager:     build.Manager,
			BuildID:     req.BuildID,
			Time:        now,
			Maintainers: req.Maintainers,
			ReproOpts:   req.ReproOpts,
			// We used to report crash with the longest report len to work around
			// corrupted reports. Now that we explicitly detect corrupted reports,
			// disable this sorting. When all old bugs are closed, we need to remove
			// sorting by ReportLen from queryCrashesForBug.
			ReportLen: 1e9,
		}

		if crash.Log, err = putText(c, ns, "CrashLog", req.Log, false); err != nil {
			return nil, err
		}
		if crash.Report, err = putText(c, ns, "CrashReport", req.Report, false); err != nil {
			return nil, err
		}
		if crash.ReproSyz, err = putText(c, ns, "ReproSyz", req.ReproSyz, false); err != nil {
			return nil, err
		}
		if crash.ReproC, err = putText(c, ns, "ReproC", req.ReproC, false); err != nil {
			return nil, err
		}

		crashKey := datastore.NewIncompleteKey(c, "Crash", bugKey)
		if _, err = datastore.Put(c, crashKey, crash); err != nil {
			return nil, fmt.Errorf("failed to put crash: %v", err)
		}
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
	const batchSize = 10 // delete at most that many at once
	if bug.NumCrashes <= maxCrashes {
		return
	}
	var crashes []*Crash
	keys, err := datastore.NewQuery("Crash").
		Ancestor(bugKey).
		Filter("ReproC=", 0).
		Filter("ReproSyz=", 0).
		Order("ReportLen").
		Order("Time").
		Limit(maxCrashes+batchSize).
		GetAll(c, &crashes)
	if err != nil {
		log.Errorf(c, "failed to fetch purge crashes: %v", err)
		return
	}
	if len(keys) <= maxCrashes {
		return
	}
	keys = keys[:len(keys)-maxCrashes]
	crashes = crashes[:len(crashes)-maxCrashes]
	var texts []*datastore.Key
	for _, crash := range crashes {
		if crash.ReproSyz != 0 || crash.ReproC != 0 {
			log.Errorf(c, "purging reproducer?")
			continue
		}
		if crash.Log != 0 {
			texts = append(texts, datastore.NewKey(c, "CrashLog", "", crash.Log, nil))
		}
		if crash.Report != 0 {
			texts = append(texts, datastore.NewKey(c, "CrashReport", "", crash.Report, nil))
		}
	}
	if len(texts) != 0 {
		if err := datastore.DeleteMulti(c, texts); err != nil {
			log.Errorf(c, "failed to delete old crash texts: %v", err)
			return
		}
	}
	if err := datastore.DeleteMulti(c, keys); err != nil {
		log.Errorf(c, "failed to delete old crashes: %v", err)
		return
	}
	log.Infof(c, "deleted %v crashes", len(keys))
}

func apiReportFailedRepro(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.CrashID)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
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
	if err := datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{
		XG:       true,
		Attempts: 30,
	}); err != nil {
		return nil, err
	}
	return nil, nil
}

func apiNeedRepro(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.CrashID)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
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

func apiManagerStats(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.ManagerStatsReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	now := timeNow(c)
	if err := updateManager(c, ns, req.Name, func(mgr *Manager, stats *ManagerStats) {
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
	}); err != nil {
		return nil, err
	}
	return nil, nil
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
		bug.NumRepro < 5 &&
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

func getText(c context.Context, tag string, id int64) ([]byte, error) {
	if id == 0 {
		return nil, nil
	}
	text := new(Text)
	if err := datastore.Get(c, datastore.NewKey(c, tag, "", id, nil), text); err != nil {
		return nil, fmt.Errorf("failed to read text %v: %v", tag, err)
	}
	d, err := gzip.NewReader(bytes.NewBuffer(text.Text))
	if err != nil {
		return nil, fmt.Errorf("failed to read text %v: %v", tag, err)
	}
	data, err := ioutil.ReadAll(d)
	if err != nil {
		return nil, fmt.Errorf("failed to read text %v: %v", tag, err)
	}
	return data, nil
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
