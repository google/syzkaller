// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/uuid"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"
	"google.golang.org/appengine/v2/user"
)

func initAPIHandlers() {
	http.Handle("/api", handleJSON(handleAPI))
}

var apiHandlers = map[string]APIHandler{
	"log_error":             typedHandler(apiLogError),
	"job_poll":              typedHandler(apiJobPoll),
	"job_reset":             typedHandler(apiJobReset),
	"job_done":              typedHandler(apiJobDone),
	"reporting_poll_bugs":   typedHandler(apiReportingPollBugs),
	"reporting_poll_notifs": typedHandler(apiReportingPollNotifications),
	"reporting_poll_closed": typedHandler(apiReportingPollClosed),
	"reporting_update":      typedHandler(apiReportingUpdate),
	"new_test_job":          typedHandler(apiNewTestJob),
	"needed_assets":         typedHandler(apiNeededAssetsList),
	"load_full_bug":         typedHandler(apiLoadFullBug),
	"save_discussion":       typedHandler(apiSaveDiscussion),
	"create_upload_url":     typedHandler(apiCreateUploadURL),
	"send_email":            typedHandler(apiSendEmail),
	"ai_job_poll":           typedHandler(apiAIJobPoll),
	"ai_job_done":           typedHandler(apiAIJobDone),
	"ai_trajectory_log":     typedHandler(apiAITrajectoryLog),
	"save_coverage":         gcsPayloadHandler(apiSaveCoverage),
	"upload_build":          nsHandler(apiUploadBuild),
	"builder_poll":          nsHandler(apiBuilderPoll),
	"report_build_error":    nsHandler(apiReportBuildError),
	"report_crash":          nsHandler(apiReportCrash),
	"report_failed_repro":   nsHandler(apiReportFailedRepro),
	"need_repro":            nsHandler(apiNeedRepro),
	"manager_stats":         nsHandler(apiManagerStats),
	"commit_poll":           nsHandler(apiCommitPoll),
	"upload_commits":        nsHandler(apiUploadCommits),
	"bug_list":              nsHandler(apiBugList),
	"load_bug":              nsHandler(apiLoadBug),
	"update_report":         nsHandler(apiUpdateReport),
	"add_build_assets":      nsHandler(apiAddBuildAssets),
	"log_to_repro":          nsHandler(apiLogToReproduce),
}

type JSONHandler func(ctx context.Context, r *http.Request) (any, error)
type APIHandler func(ctx context.Context, payload io.Reader) (any, error)

const (
	maxReproPerBug   = 10
	reproRetryPeriod = 24 * time.Hour // try 1 repro per day until we have at least syz repro
	// Attempt a new repro every ~ 3 months, even if we have already found it for the bug. This should:
	// 1) Improve old repros over time (as we update descriptions / change syntax / repro algorithms).
	// 2) Constrain the impact of bugs in syzkaller's backward compatibility. Fewer old repros, fewer problems.
	reproStalePeriod = 100 * 24 * time.Hour
)

// Overridable for testing.
var timeNow = func(ctx context.Context) time.Time {
	return time.Now()
}

func timeSince(ctx context.Context, t time.Time) time.Duration {
	return timeNow(ctx).Sub(t)
}

var maxCrashes = func() int {
	const maxCrashesPerBug = 40
	return maxCrashesPerBug
}

func handleJSON(fn JSONHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		reply, err := fn(ctx, r)
		if err != nil {
			status := logErrorPrepareStatus(ctx, err)
			http.Error(w, err.Error(), status)
			return
		}

		wJS := newGzipResponseWriterCloser(w)
		defer wJS.Close()
		if err := json.NewEncoder(wJS).Encode(reply); err != nil {
			log.Errorf(ctx, "failed to encode reply: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := wJS.writeResult(r); err != nil {
			log.Errorf(ctx, "wJS.writeResult: %s", err.Error())
		}
	})
}

func handleAPI(ctx context.Context, r *http.Request) (any, error) {
	client := r.PostFormValue("client")
	method := r.PostFormValue("method")
	log.Infof(ctx, "api %q from %q", method, client)
	if client == "" {
		// Don't log as error if somebody just invokes /api.
		return nil, fmt.Errorf("client is empty: %w", ErrClientBadRequest)
	}
	auth := auth.MakeEndpoint(auth.GoogleTokenInfoEndpoint)
	subj, err := auth.DetermineAuthSubj(timeNow(ctx), r.Header["Authorization"])
	if err != nil {
		return nil, fmt.Errorf("failed to auth.DetermineAuthSubj(): %w", err)
	}
	password := r.PostFormValue("key")
	ns, err := checkClient(getConfig(ctx), client, password, subj)
	if err != nil {
		return nil, fmt.Errorf("checkClient('%s') error: %w", client, err)
	}
	var payloadReader io.Reader
	if str := r.PostFormValue("payload"); str != "" {
		gr, err := gzip.NewReader(strings.NewReader(str))
		if err != nil {
			return nil, fmt.Errorf("failed to ungzip payload: %w", err)
		}
		payloadReader = gr
		// Ignore Close() error because we may not read all data.
		defer gr.Close()
	}
	handler, exists := apiHandlers[method]
	if !exists {
		return nil, fmt.Errorf("unknown api method %q", method)
	}
	reply, err := handler(contextWithNamespace(ctx, ns), payloadReader)
	if err != nil {
		err = fmt.Errorf("method '%s' ns '%s' err: %w", method, ns, err)
	}
	return reply, err
}

var contextKeyNamespace = "context namespace available for any APIHandler"

func contextWithNamespace(ctx context.Context, ns string) context.Context {
	return context.WithValue(ctx, &contextKeyNamespace, ns)
}

func contextNamespace(ctx context.Context) string {
	return ctx.Value(&contextKeyNamespace).(string)
}

// gcsPayloadHandler json.Decode the gcsURL from payload and stream pointed content.
// This function streams ungzipped content in order to be aligned with other wrappers/handlers.
func gcsPayloadHandler(handler APIHandler) APIHandler {
	return func(ctx context.Context, payload io.Reader) (any, error) {
		var gcsURL string
		if err := json.NewDecoder(payload).Decode(&gcsURL); err != nil {
			return nil, fmt.Errorf("json.NewDecoder(payload).Decode(&gcsURL): %w", err)
		}
		gcsURL = strings.TrimPrefix(gcsURL, "gs://")
		clientGCS, err := gcs.NewClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("gcs.NewClient: %w", err)
		}
		defer clientGCS.Close()
		gcsPayloadReader, err := clientGCS.FileReader(gcsURL)
		if err != nil {
			return nil, fmt.Errorf("clientGCS.FileReader: %w", err)
		}
		gz, err := gzip.NewReader(gcsPayloadReader)
		if err != nil {
			return nil, fmt.Errorf("gzip.NewReader: %w", err)
		}
		// Close() generates error in case of the corrupted data.
		// In order to check the data checksum all the data should be read.
		// We don't guarantee all the data will be read - let's ignore.
		defer gz.Close()
		return handler(ctx, gz)
	}
}

func nsHandler[Req any](handler func(context.Context, string, *Req) (any, error)) APIHandler {
	return typedHandler(func(ctx context.Context, req *Req) (any, error) {
		ns := contextNamespace(ctx)
		if ns == "" {
			return nil, fmt.Errorf("must be called within a namespace")
		}
		return handler(ctx, ns, req)
	})
}

func typedHandler[Req any](handler func(context.Context, *Req) (any, error)) APIHandler {
	return func(ctx context.Context, payload io.Reader) (any, error) {
		req := new(Req)
		if payload != nil {
			if err := json.NewDecoder(payload).Decode(req); err != nil {
				return nil, fmt.Errorf("failed to unmarshal request %T: %w", req, err)
			}
		}
		res, err := handler(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("%w\nrequest: %+v", err, *req)
		}
		return res, nil
	}
}

func apiLogError(ctx context.Context, req *dashapi.LogEntry) (any, error) {
	log.Errorf(ctx, "%v: %v", req.Name, req.Text)
	return nil, nil
}

func apiBuilderPoll(ctx context.Context, ns string, req *dashapi.BuilderPollReq) (any, error) {
	bugs, _, err := loadAllBugs(ctx, func(query *db.Query) *db.Query {
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
		ReportEmail:    reportEmail(ctx, ns),
	}
	return resp, nil
}

func reportEmail(ctx context.Context, ns string) string {
	for _, reporting := range getNsConfig(ctx, ns).Reporting {
		if _, ok := reporting.Config.(*EmailConfig); ok {
			return ownEmail(ctx)
		}
	}
	return ""
}

func apiCommitPoll(ctx context.Context, ns string, req *any) (any, error) {
	resp := &dashapi.CommitPollResp{
		ReportEmail: reportEmail(ctx, ns),
	}
	for _, repo := range getNsConfig(ctx, ns).Repos {
		if repo.NoPoll {
			continue
		}
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
		GetAll(ctx, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %w", err)
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
	if getNsConfig(ctx, ns).RetestMissingBackports {
		const takeBackportTitles = 5
		backportCommits, err := pollBackportCommits(ctx, ns, takeBackportTitles)
		if err != nil {
			return nil, err
		}
		resp.Commits = append(resp.Commits, backportCommits...)
	}
	return resp, nil
}

func pollBackportCommits(ctx context.Context, ns string, count int) ([]string, error) {
	// Let's assume that there won't be too many pending backports.
	list, err := relevantBackportJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query backport: %w", err)
	}
	var backportTitles []string
	for _, info := range list {
		if info.bug.Namespace != ns {
			continue
		}
		backportTitles = append(backportTitles, info.job.Commits[0].Title)
	}
	randomizer := rand.New(rand.NewSource(timeNow(ctx).UnixNano()))
	randomizer.Shuffle(len(backportTitles), func(i, j int) {
		backportTitles[i], backportTitles[j] = backportTitles[j], backportTitles[i]
	})
	if len(backportTitles) > count {
		backportTitles = backportTitles[:count]
	}
	return backportTitles, nil
}

func apiUploadCommits(ctx context.Context, ns string, req *dashapi.CommitPollResultReq) (any, error) {
	// This adds fixing commits to bugs.
	err := addCommitsToBugs(ctx, ns, "", nil, req.Commits)
	if err != nil {
		return nil, err
	}
	// Now add commit info to commits.
	for _, com := range req.Commits {
		if com.Hash == "" {
			continue
		}
		if err := addCommitInfo(ctx, ns, com); err != nil {
			return nil, err
		}
	}
	if getNsConfig(ctx, ns).RetestMissingBackports {
		err = updateBackportCommits(ctx, ns, req.Commits)
		if err != nil {
			return nil, fmt.Errorf("failed to update backport commits: %w", err)
		}
	}
	return nil, nil
}

func addCommitInfo(ctx context.Context, ns string, com dashapi.Commit) error {
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Commits=", com.Title).
		GetAll(ctx, &bugs)
	if err != nil {
		return fmt.Errorf("failed to query bugs: %w", err)
	}
	for i, bug := range bugs {
		if err := addCommitInfoToBug(ctx, bug, keys[i], com); err != nil {
			return err
		}
	}
	return nil
}

func addCommitInfoToBug(ctx context.Context, bug *Bug, bugKey *db.Key, com dashapi.Commit) error {
	if needUpdate, err := addCommitInfoToBugImpl(ctx, bug, com); err != nil {
		return err
	} else if !needUpdate {
		return nil
	}
	tx := func(ctx context.Context) error {
		bug := new(Bug)
		if err := db.Get(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug %v: %w", bugKey.StringID(), err)
		}
		if needUpdate, err := addCommitInfoToBugImpl(ctx, bug, com); err != nil {
			return err
		} else if !needUpdate {
			return nil
		}
		if _, err := db.Put(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		return nil
	}
	return runInTransaction(ctx, tx, nil)
}

func addCommitInfoToBugImpl(ctx context.Context, bug *Bug, com dashapi.Commit) (bool, error) {
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

func apiJobPoll(ctx context.Context, req *dashapi.JobPollReq) (any, error) {
	if stop, err := emergentlyStopped(ctx); err != nil || stop {
		// The bot's operation was aborted. Don't accept new crash reports.
		return &dashapi.JobPollResp{}, err
	}
	if len(req.Managers) == 0 {
		return nil, fmt.Errorf("no managers")
	}
	return pollPendingJobs(ctx, req.Managers)
}

func apiJobDone(ctx context.Context, req *dashapi.JobDoneReq) (any, error) {
	err := doneJob(ctx, req)
	return nil, err
}

func apiJobReset(ctx context.Context, req *dashapi.JobResetReq) (any, error) {
	err := resetJobs(ctx, req)
	return nil, err
}

func apiUploadBuild(ctx context.Context, ns string, req *dashapi.Build) (any, error) {
	now := timeNow(ctx)
	_, isNewBuild, err := uploadBuild(ctx, now, ns, req, BuildNormal)
	if err != nil {
		return nil, err
	}
	if isNewBuild {
		err := updateManager(ctx, ns, req.Manager, func(mgr *Manager, stats *ManagerStats) error {
			prevKernel, prevSyzkaller := "", ""
			if mgr.CurrentBuild != "" {
				prevBuild, err := loadBuild(ctx, ns, mgr.CurrentBuild)
				if err != nil {
					return err
				}
				prevKernel = prevBuild.KernelCommit
				prevSyzkaller = prevBuild.SyzkallerCommit
			}
			log.Infof(ctx, "new build on %v: kernel %v->%v syzkaller %v->%v",
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
		if err := addCommitsToBugs(ctx, ns, req.Manager, req.Commits, req.FixCommits); err != nil {
			// We've already uploaded the build successfully and manager can use it.
			// Moreover, addCommitsToBugs scans all bugs and can take long time.
			// So just log the error.
			log.Errorf(ctx, "failed to add commits to bugs: %v", err)
		}
	}
	return nil, nil
}

func uploadBuild(ctx context.Context, now time.Time, ns string, req *dashapi.Build, typ BuildType) (
	*Build, bool, error) {
	newAssets := []Asset{}
	for i, toAdd := range req.Assets {
		newAsset, err := parseIncomingAsset(ctx, toAdd, ns)
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse asset #%d: %w", i, err)
		}
		newAssets = append(newAssets, newAsset)
	}
	if build, err := loadBuild(ctx, ns, req.ID); err == nil {
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
	configID, err := putText(ctx, ns, textKernelConfig, req.KernelConfig)
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
		Assets:              newAssets,
	}
	if _, err := db.Put(ctx, buildKey(ctx, ns, req.ID), build); err != nil {
		return nil, false, err
	}
	return build, true, nil
}

func addCommitsToBugs(ctx context.Context, ns, manager string, titles []string, fixCommits []dashapi.Commit) error {
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
	managers, err := managerList(ctx, ns)
	if err != nil {
		return err
	}
	// Fetching all bugs in a namespace can be slow, and there is no way to filter only Open/Dup statuses.
	// So we run a separate query for each status, this both avoids fetching unnecessary data
	// and splits a long query into two (two smaller queries have lower chances of trigerring
	// timeouts than one huge).
	for _, status := range []int{BugStatusOpen, BugStatusDup} {
		err := addCommitsToBugsInStatus(ctx, status, ns, manager, managers, presentCommits, bugFixedBy)
		if err != nil {
			return err
		}
	}
	return nil
}

func addCommitsToBugsInStatus(ctx context.Context, status int, ns, manager string, managers []string,
	presentCommits map[string]bool, bugFixedBy map[string][]string) error {
	bugs, _, err := loadAllBugs(ctx, func(query *db.Query) *db.Query {
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
		if err := addCommitsToBug(ctx, bug, manager, managers, fixCommits, presentCommits); err != nil {
			return err
		}
		if bug.Status == BugStatusDup {
			canon, err := canonicalBug(ctx, bug)
			if err != nil {
				return err
			}
			if canon.Status == BugStatusOpen && len(bug.Commits) == 0 {
				if err := addCommitsToBug(ctx, canon, manager, managers,
					fixCommits, presentCommits); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func addCommitsToBug(ctx context.Context, bug *Bug, manager string, managers, fixCommits []string,
	presentCommits map[string]bool) error {
	if !bugNeedsCommitUpdate(ctx, bug, manager, fixCommits, presentCommits, true) {
		return nil
	}
	now := timeNow(ctx)
	bugKey := bug.key(ctx)
	tx := func(ctx context.Context) error {
		bug := new(Bug)
		if err := db.Get(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug %v: %w", bugKey.StringID(), err)
		}
		if !bugNeedsCommitUpdate(ctx, bug, manager, fixCommits, presentCommits, false) {
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
		if _, err := db.Put(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		return nil
	}
	return runInTransaction(ctx, tx, nil)
}

func bugNeedsCommitUpdate(ctx context.Context, bug *Bug, manager string, fixCommits []string,
	presentCommits map[string]bool, dolog bool) bool {
	if len(fixCommits) != 0 && !reflect.DeepEqual(bug.Commits, fixCommits) {
		if dolog {
			log.Infof(ctx, "bug %q is fixed with %q", bug.Title, fixCommits)
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

// Note: if you do not need the latest data, prefer CachedManagersList().
func managerList(ctx context.Context, ns string) ([]string, error) {
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ns).
		Project("Manager").
		Distinct().
		GetAll(ctx, &builds)
	if err != nil {
		return nil, fmt.Errorf("failed to query builds: %w", err)
	}
	configManagers := getNsConfig(ctx, ns).Managers
	var managers []string
	for _, build := range builds {
		if configManagers[build.Manager].Decommissioned {
			continue
		}
		managers = append(managers, build.Manager)
	}
	return managers, nil
}

func apiReportBuildError(ctx context.Context, ns string, req *dashapi.BuildErrorReq) (any, error) {
	now := timeNow(ctx)
	build, _, err := uploadBuild(ctx, now, ns, &req.Build, BuildFailed)
	if err != nil {
		return nil, fmt.Errorf("failed to store build: %w", err)
	}
	req.Crash.BuildID = req.Build.ID
	bug, err := reportCrash(ctx, build, &req.Crash)
	if err != nil {
		return nil, fmt.Errorf("failed to store crash: %w", err)
	}
	if err := updateManager(ctx, ns, req.Build.Manager, func(mgr *Manager, stats *ManagerStats) error {
		log.Infof(ctx, "failed build on %v: kernel=%v", req.Build.Manager, req.Build.KernelCommit)
		if req.Build.KernelCommit != "" {
			mgr.FailedBuildBug = bug.keyHash(ctx)
		} else {
			mgr.FailedSyzBuildBug = bug.keyHash(ctx)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to update manager: %w", err)
	}
	return nil, nil
}

const (
	corruptedReportTitle  = "corrupted report"
	suppressedReportTitle = "suppressed report"
)

func apiReportCrash(ctx context.Context, ns string, req *dashapi.Crash) (any, error) {
	if stop, err := emergentlyStopped(ctx); err != nil || stop {
		// The bot's operation was aborted. Don't accept new crash reports.
		return &dashapi.ReportCrashResp{}, err
	}
	build, err := loadBuild(ctx, ns, req.BuildID)
	if err != nil {
		return nil, err
	}
	if !getNsConfig(ctx, ns).TransformCrash(build, req) {
		return new(dashapi.ReportCrashResp), nil
	}
	var bug2 *Bug
	if req.OriginalTitle != "" {
		bug2, err = findExistingBugForCrash(ctx, ns, []string{req.OriginalTitle})
		if err != nil {
			return nil, fmt.Errorf("original bug query failed: %w", err)
		}
	}
	bug, err := reportCrash(ctx, build, req)
	if err != nil {
		return nil, err
	}
	if bug2 != nil && bug2.Title != bug.Title && len(req.ReproLog) > 0 {
		// During bug reproduction, we have diverted to another bug.
		// Let's remember this.
		err = saveFailedReproLog(ctx, bug2, build, req.ReproLog)
		if err != nil {
			return nil, fmt.Errorf("failed to save failed repro log: %w", err)
		}
	}
	resp := &dashapi.ReportCrashResp{
		NeedRepro: needRepro(ctx, bug),
	}
	return resp, nil
}

// nolint: gocyclo
func reportCrash(ctx context.Context, build *Build, req *dashapi.Crash) (*Bug, error) {
	ns := build.Namespace
	assets, err := parseCrashAssets(ctx, req, ns)
	if err != nil {
		return nil, err
	}
	req.Title = canonicalizeCrashTitle(req.Title, req.Corrupted, req.Suppressed)
	if req.Corrupted || req.Suppressed {
		req.AltTitles = []string{req.Title}
	} else {
		for i, t := range req.AltTitles {
			req.AltTitles[i] = normalizeCrashTitle(t)
		}
		req.AltTitles = mergeStringList([]string{req.Title}, req.AltTitles) // dedup
	}
	req.Maintainers = email.MergeEmailLists(req.Maintainers)

	bug, err := findBugForCrash(ctx, ns, req.AltTitles)
	if err != nil {
		return nil, fmt.Errorf("failed to find bug for the crash: %w", err)
	}
	if bug == nil {
		bug, err = createBugForCrash(ctx, ns, req)
		if err != nil {
			return nil, fmt.Errorf("failed to create a bug: %w", err)
		}
	}

	bugKey := bug.key(ctx)
	now := timeNow(ctx)
	reproLevel := ReproLevelNone
	if len(req.ReproC) != 0 {
		reproLevel = ReproLevelC
	} else if len(req.ReproSyz) != 0 {
		reproLevel = ReproLevelSyz
	}
	save := reproLevel != ReproLevelNone ||
		bug.NumCrashes < int64(maxCrashes()) ||
		now.Sub(bug.LastSavedCrash) > time.Hour ||
		bug.NumCrashes%20 == 0 ||
		!stringInList(bug.MergedTitles, req.Title)
	if save {
		if err := saveCrash(ctx, ns, req, bug, bugKey, build, assets); err != nil {
			return nil, fmt.Errorf("failed to save the crash: %w", err)
		}
	} else {
		log.Infof(ctx, "not saving crash for %q", bug.Title)
	}

	subsystemService := getNsConfig(ctx, ns).Subsystems.Service

	newSubsystems := []*subsystem.Subsystem{}
	// Recalculate subsystems on the first saved crash and on the first saved repro,
	// unless a user has already manually specified them.
	calculateSubsystems := subsystemService != nil &&
		save &&
		!bug.hasUserSubsystems() &&
		(bug.NumCrashes == 0 ||
			bug.ReproLevel == ReproLevelNone && reproLevel != ReproLevelNone)
	if calculateSubsystems {
		newSubsystems, err = inferSubsystems(ctx, bug, bugKey, &debugtracer.NullTracer{})
		if err != nil {
			log.Errorf(ctx, "%q: failed to extract subsystems: %s", bug.Title, err)
			return nil, err
		}
	}

	tx := func(ctx context.Context) error {
		bug = new(Bug)
		if err := db.Get(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %w", err)
		}
		bug.LastTime = now
		if save {
			bug.LastSavedCrash = now
		}
		if reproLevel != ReproLevelNone {
			bug.NumRepro++
			bug.LastReproTime = now
		}
		bug.ReproLevel = max(bug.ReproLevel, reproLevel)
		bug.HeadReproLevel = max(bug.HeadReproLevel, reproLevel)
		if len(req.Report) != 0 {
			bug.HasReport = true
		}
		if calculateSubsystems {
			bug.SetAutoSubsystems(ctx, newSubsystems, now, subsystemService.Revision)
		}
		bug.increaseCrashStats(now)
		bug.HappenedOn = mergeString(bug.HappenedOn, build.Manager)
		// Migration of older entities (for new bugs Title is always in MergedTitles).
		bug.MergedTitles = mergeString(bug.MergedTitles, bug.Title)
		bug.MergedTitles = mergeString(bug.MergedTitles, req.Title)
		bug.AltTitles = mergeStringList(bug.AltTitles, req.AltTitles)
		if _, err = db.Put(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		return nil
	}
	if err := runInTransaction(ctx, tx, &db.TransactionOptions{
		XG: true,
		// Very valuable transaction.
		Attempts: 30,
	}); err != nil {
		return nil, fmt.Errorf("bug updating failed: %w", err)
	}
	if save {
		purgeOldCrashes(ctx, bug, bugKey)
	}
	return bug, nil
}

func parseCrashAssets(ctx context.Context, req *dashapi.Crash, ns string) ([]Asset, error) {
	assets := []Asset{}
	for i, toAdd := range req.Assets {
		newAsset, err := parseIncomingAsset(ctx, toAdd, ns)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset #%d: %w", i, err)
		}
		assets = append(assets, newAsset)
	}
	return assets, nil
}

func (crash *Crash) UpdateReportingPriority(ctx context.Context, build *Build, bug *Bug) {
	prio := int64(kernelRepoInfo(ctx, build).ReportingPriority) * 1e6
	if crash.ReproC > 0 && !crash.ReproIsRevoked {
		prio += 4e12
	} else if crash.ReproSyz > 0 && !crash.ReproIsRevoked {
		prio += 2e12
	}
	if crash.Title == bug.Title {
		prio += 1e8 // prefer reporting crash that matches bug title
	}
	managerPrio := 0
	if _, mgrConfig := activeManager(ctx, crash.Manager, bug.Namespace); mgrConfig != nil {
		managerPrio = mgrConfig.Priority
	}
	prio += int64((managerPrio - MinManagerPriority) * 1e5)
	if build.Arch == targets.AMD64 {
		prio += 1e3
	}
	crash.ReportLen = prio
}

func saveCrash(ctx context.Context, ns string, req *dashapi.Crash, bug *Bug, bugKey *db.Key,
	build *Build, assets []Asset) error {
	crash := &Crash{
		Title:   req.Title,
		Manager: build.Manager,
		BuildID: req.BuildID,
		Time:    timeNow(ctx),
		Maintainers: email.MergeEmailLists(req.Maintainers,
			GetEmails(req.Recipients, dashapi.To),
			GetEmails(req.Recipients, dashapi.Cc)),
		ReproOpts: req.ReproOpts,
		Flags:     int64(req.Flags),
		Assets:    assets,
		ReportElements: CrashReportElements{
			GuiltyFiles: req.GuiltyFiles,
		},
	}
	var err error
	if crash.Log, err = putText(ctx, ns, textCrashLog, req.Log); err != nil {
		return err
	}
	if crash.Report, err = putText(ctx, ns, textCrashReport, req.Report); err != nil {
		return err
	}
	if crash.ReproSyz, err = putText(ctx, ns, textReproSyz, req.ReproSyz); err != nil {
		return err
	}
	if crash.ReproC, err = putText(ctx, ns, textReproC, req.ReproC); err != nil {
		return err
	}
	if crash.MachineInfo, err = putText(ctx, ns, textMachineInfo, req.MachineInfo); err != nil {
		return err
	}
	if crash.ReproLog, err = putText(ctx, ns, textReproLog, req.ReproLog); err != nil {
		return err
	}
	crash.UpdateReportingPriority(ctx, build, bug)
	crashKey := db.NewIncompleteKey(ctx, "Crash", bugKey)
	if _, err = db.Put(ctx, crashKey, crash); err != nil {
		return fmt.Errorf("failed to put crash: %w", err)
	}
	return nil
}

func purgeOldCrashes(ctx context.Context, bug *Bug, bugKey *db.Key) {
	const purgeEvery = 10
	if bug.NumCrashes <= int64(2*maxCrashes()) || (bug.NumCrashes-1)%purgeEvery != 0 {
		return
	}
	var crashes []*Crash
	keys, err := db.NewQuery("Crash").
		Ancestor(bugKey).
		Filter("Reported=", time.Time{}).
		GetAll(ctx, &crashes)
	if err != nil {
		log.Errorf(ctx, "failed to fetch purge crashes: %v", err)
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
	uniqueTitle := make(map[string]bool)
	deleted, reproCount, noreproCount := 0, 0, 0
	for _, crash := range crashes {
		if !crash.Reported.IsZero() {
			log.Errorf(ctx, "purging reported crash?")
			continue
		}
		// Preserve latest crash on each manager.
		if !latestOnManager[crash.Manager] {
			latestOnManager[crash.Manager] = true
			continue
		}
		// Preserve at least one crash with each title.
		if !uniqueTitle[crash.Title] {
			uniqueTitle[crash.Title] = true
			continue
		}
		// Preserve maxCrashes latest crashes with repro and without repro.
		count := &noreproCount
		if crash.ReproSyz != 0 || crash.ReproC != 0 {
			count = &reproCount
		}
		if *count < maxCrashes() {
			*count++
			continue
		}
		toDelete = append(toDelete, keyMap[crash])
		if crash.Log != 0 {
			toDelete = append(toDelete, db.NewKey(ctx, textCrashLog, "", crash.Log, nil))
		}
		if crash.Report != 0 {
			toDelete = append(toDelete, db.NewKey(ctx, textCrashReport, "", crash.Report, nil))
		}
		if crash.ReproSyz != 0 {
			toDelete = append(toDelete, db.NewKey(ctx, textReproSyz, "", crash.ReproSyz, nil))
		}
		if crash.ReproC != 0 {
			toDelete = append(toDelete, db.NewKey(ctx, textReproC, "", crash.ReproC, nil))
		}
		deleted++
		if deleted == 2*purgeEvery {
			break
		}
	}
	if len(toDelete) == 0 {
		return
	}
	if err := db.DeleteMulti(ctx, toDelete); err != nil {
		log.Errorf(ctx, "failed to delete old crashes: %v", err)
		return
	}
	log.Infof(ctx, "deleted %v crashes for bug %q", deleted, bug.Title)
}

func apiReportFailedRepro(ctx context.Context, ns string, req *dashapi.CrashID) (any, error) {
	req.Title = canonicalizeCrashTitle(req.Title, req.Corrupted, req.Suppressed)
	bug, err := findExistingBugForCrash(ctx, ns, []string{req.Title})
	if err != nil {
		return nil, err
	}
	if bug == nil {
		return nil, fmt.Errorf("%v: can't find bug for crash %q", ns, req.Title)
	}
	build, err := loadBuild(ctx, ns, req.BuildID)
	if err != nil {
		return nil, err
	}
	return nil, saveFailedReproLog(ctx, bug, build, req.ReproLog)
}

func saveFailedReproLog(ctx context.Context, bug *Bug, build *Build, log []byte) error {
	now := timeNow(ctx)
	bugKey := bug.key(ctx)
	tx := func(ctx context.Context) error {
		bug := new(Bug)
		if err := db.Get(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %w", err)
		}
		bug.NumRepro++
		bug.LastReproTime = now
		if len(log) > 0 {
			err := saveReproAttempt(ctx, bug, build, log)
			if err != nil {
				return fmt.Errorf("failed to save repro log: %w", err)
			}
		}
		if _, err := db.Put(ctx, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		return nil
	}
	return runInTransaction(ctx, tx, &db.TransactionOptions{
		XG:       true,
		Attempts: 30,
	})
}

const maxReproLogs = 5

func saveReproAttempt(ctx context.Context, bug *Bug, build *Build, log []byte) error {
	var deleteKeys []*db.Key
	for len(bug.ReproAttempts)+1 > maxReproLogs {
		deleteKeys = append(deleteKeys,
			db.NewKey(ctx, textReproLog, "", bug.ReproAttempts[0].Log, nil))
		bug.ReproAttempts = bug.ReproAttempts[1:]
	}
	entry := BugReproAttempt{
		Time:    timeNow(ctx),
		Manager: build.Manager,
	}
	var err error
	if entry.Log, err = putText(ctx, bug.Namespace, textReproLog, log); err != nil {
		return err
	}
	if len(deleteKeys) > 0 {
		return db.DeleteMulti(ctx, deleteKeys)
	}
	bug.ReproAttempts = append(bug.ReproAttempts, entry)
	return nil
}

func apiNeedRepro(ctx context.Context, ns string, req *dashapi.CrashID) (any, error) {
	if req.Corrupted {
		resp := &dashapi.NeedReproResp{
			NeedRepro: false,
		}
		return resp, nil
	}
	req.Title = canonicalizeCrashTitle(req.Title, req.Corrupted, req.Suppressed)

	bug, err := findExistingBugForCrash(ctx, ns, []string{req.Title})
	if err != nil {
		return nil, err
	}
	if bug == nil {
		if req.MayBeMissing {
			// Manager does not send leak reports w/o repro to dashboard, we want to reproduce them.
			resp := &dashapi.NeedReproResp{
				NeedRepro: true,
			}
			return resp, nil
		}
		return nil, fmt.Errorf("%v: can't find bug for crash %q", ns, req.Title)
	}
	resp := &dashapi.NeedReproResp{
		NeedRepro: needRepro(ctx, bug),
	}
	return resp, nil
}

func canonicalizeCrashTitle(title string, corrupted, suppressed bool) string {
	if corrupted {
		// The report is corrupted and the title is most likely invalid.
		// Such reports are usually unactionable and are discarded.
		// Collect them into a single bin.
		return corruptedReportTitle
	}
	if suppressed {
		// Collect all of them into a single bucket so that it's possible to control and assess them,
		// e.g. if there are some spikes in suppressed reports.
		return suppressedReportTitle
	}
	return normalizeCrashTitle(title)
}

func normalizeCrashTitle(title string) string {
	return strings.TrimSpace(limitLength(title, maxTextLen))
}

func apiManagerStats(ctx context.Context, ns string, req *dashapi.ManagerStatsReq) (any, error) {
	now := timeNow(ctx)
	err := updateManager(ctx, ns, req.Name, func(mgr *Manager, stats *ManagerStats) error {
		mgr.Link = req.Addr
		mgr.LastAlive = now
		mgr.CurrentUpTime = req.UpTime
		stats.MaxCorpus = max(stats.MaxCorpus, int64(req.Corpus))
		stats.MaxPCs = max(stats.MaxPCs, int64(req.PCs))
		stats.MaxCover = max(stats.MaxCover, int64(req.Cover))
		stats.CrashTypes = max(stats.CrashTypes, int64(req.CrashTypes))
		stats.TotalFuzzingTime += req.FuzzingTime
		stats.TotalCrashes += int64(req.Crashes)
		stats.SuppressedCrashes += int64(req.SuppressedCrashes)
		stats.TotalExecs += int64(req.Execs)
		stats.TriagedCoverage = max(stats.TriagedCoverage, int64(req.TriagedCoverage))
		stats.TriagedPCs = max(stats.TriagedPCs, int64(req.TriagedPCs))
		return nil
	})
	return nil, err
}

func apiUpdateReport(ctx context.Context, ns string, req *dashapi.UpdateReportReq) (any, error) {
	bug := new(Bug)
	bugKey := db.NewKey(ctx, "Bug", req.BugID, 0, nil)
	if err := db.Get(ctx, bugKey, bug); err != nil {
		return nil, fmt.Errorf("failed to get bug: %w", err)
	}
	if bug.Namespace != ns {
		return nil, fmt.Errorf("no such bug")
	}
	tx := func(ctx context.Context) error {
		crash := new(Crash)
		crashKey := db.NewKey(ctx, "Crash", "", req.CrashID, bugKey)
		if err := db.Get(ctx, crashKey, crash); err != nil {
			return fmt.Errorf("failed to query the crash: %w", err)
		}
		if req.GuiltyFiles != nil {
			crash.ReportElements.GuiltyFiles = *req.GuiltyFiles
		}
		if _, err := db.Put(ctx, crashKey, crash); err != nil {
			return fmt.Errorf("failed to put reported crash: %w", err)
		}
		return nil
	}
	return nil, runInTransaction(ctx, tx, nil)
}

func apiBugList(ctx context.Context, ns string, req *any) (any, error) {
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		KeysOnly().
		GetAll(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %w", err)
	}
	resp := &dashapi.BugListResp{}
	for _, key := range keys {
		resp.List = append(resp.List, key.StringID())
	}
	return resp, nil
}

func apiLoadBug(ctx context.Context, ns string, req *dashapi.LoadBugReq) (any, error) {
	bug := new(Bug)
	bugKey := db.NewKey(ctx, "Bug", req.ID, 0, nil)
	if err := db.Get(ctx, bugKey, bug); err != nil {
		return nil, fmt.Errorf("failed to get bug: %w", err)
	}
	if bug.Namespace != ns {
		return nil, fmt.Errorf("no such bug")
	}
	return loadBugReport(ctx, bug)
}

func apiLoadFullBug(ctx context.Context, req *dashapi.LoadFullBugReq) (any, error) {
	bug, bugKey, err := findBugByReportingID(ctx, req.BugID)
	if err != nil {
		return nil, fmt.Errorf("failed to find the bug: %w", err)
	}
	bugReporting, _ := bugReportingByID(bug, req.BugID)
	if bugReporting == nil {
		return nil, fmt.Errorf("failed to find the bug reporting: %w", err)
	}
	return loadFullBugInfo(ctx, bug, bugKey, bugReporting)
}

func loadBugReport(ctx context.Context, bug *Bug) (*dashapi.BugReport, error) {
	crash, crashKey, err := findCrashForBug(ctx, bug)
	if err != nil {
		return nil, err
	}
	// Create report for the last reporting so that it's stable and ExtID does not change over time.
	bugReporting := &bug.Reporting[len(bug.Reporting)-1]
	reporting := getNsConfig(ctx, bug.Namespace).ReportingByName(bugReporting.Name)
	if reporting == nil {
		return nil, fmt.Errorf("reporting %v is missing in config", bugReporting.Name)
	}
	return createBugReport(ctx, bug, crash, crashKey, bugReporting, reporting)
}

func apiAddBuildAssets(ctx context.Context, ns string, req *dashapi.AddBuildAssetsReq) (any, error) {
	assets := []Asset{}
	for i, toAdd := range req.Assets {
		asset, err := parseIncomingAsset(ctx, toAdd, ns)
		if err != nil {
			return nil, fmt.Errorf("failed to parse asset #%d: %w", i, err)
		}
		assets = append(assets, asset)
	}
	_, err := appendBuildAssets(ctx, ns, req.BuildID, assets)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func parseIncomingAsset(ctx context.Context, newAsset dashapi.NewAsset, ns string) (Asset, error) {
	typeInfo := asset.GetTypeDescription(newAsset.Type)
	if typeInfo == nil {
		return Asset{}, fmt.Errorf("unknown asset type")
	}
	_, err := url.ParseRequestURI(newAsset.DownloadURL)
	if err != nil {
		return Asset{}, fmt.Errorf("invalid URL: %w", err)
	}
	fsckLog := int64(0)
	if len(newAsset.FsckLog) > 0 {
		fsckLog, err = putText(ctx, ns, textFsckLog, newAsset.FsckLog)
		if err != nil {
			return Asset{}, err
		}
	}
	return Asset{
		Type:        newAsset.Type,
		DownloadURL: newAsset.DownloadURL,
		CreateDate:  timeNow(ctx),
		FsckLog:     fsckLog,
		FsIsClean:   newAsset.FsIsClean,
	}, nil
}

func apiNeededAssetsList(ctx context.Context, req *any) (any, error) {
	return queryNeededAssets(ctx)
}

func findExistingBugForCrash(ctx context.Context, ns string, titles []string) (*Bug, error) {
	// First, try to find an existing bug that we already used to report this crash title.
	var bugs []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("MergedTitles=", titles[0]).
		GetAll(ctx, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %w", err)
	}
	// We can find bugs with different bug.Title and uncomparable bug.Seq's.
	// But there should be only one active bug for each crash title,
	// so if we sort by Seq, the first active bug is our target bug.
	sort.Slice(bugs, func(i, j int) bool {
		return bugs[i].Seq > bugs[j].Seq
	})
	for _, bug := range bugs {
		if active, err := isActiveBug(ctx, bug); err != nil {
			return nil, err
		} else if active {
			return bug, nil
		}
	}
	// This is required for incremental migration.
	// Older bugs don't have MergedTitles, so we need to check Title as well
	// (reportCrash will set MergedTitles later).
	for _, title := range titles {
		bug, err := highestSeqBug(ctx, ns, title)
		if err != nil {
			return nil, err
		}
		if bug != nil {
			if active, err := isActiveBug(ctx, bug); err != nil {
				return nil, err
			} else if active {
				return bug, nil
			}
		}
	}
	return nil, nil
}

func highestSeqBug(ctx context.Context, ns, title string) (*Bug, error) {
	var bugs []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Title=", title).
		Order("-Seq").
		Limit(1).
		GetAll(ctx, &bugs)
	if err != nil {
		return nil, fmt.Errorf("failed to query the last bug report: %w", err)
	}
	if len(bugs) == 0 {
		return nil, nil
	}
	return bugs[0], nil
}

func findBugForCrash(ctx context.Context, ns string, titles []string) (*Bug, error) {
	// First, try to find an existing bug that we already used to report this crash title.
	bug, err := findExistingBugForCrash(ctx, ns, titles)
	if bug != nil || err != nil {
		return bug, err
	}
	// If there is no active bug for this crash title, try to find an existing candidate based on AltTitles.
	var bugs []*Bug
	for _, title := range titles {
		var bugs1 []*Bug
		_, err := db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("AltTitles=", title).
			GetAll(ctx, &bugs1)
		if err != nil {
			return nil, fmt.Errorf("failed to query bugs: %w", err)
		}
		bugs = append(bugs, bugs1...)
	}
	// Sort to get determinism and skip inactive bugs.
	sort.Slice(bugs, func(i, j int) bool {
		if bugs[i].Title != bugs[j].Title {
			return bugs[i].Title < bugs[j].Title
		}
		return bugs[i].Seq > bugs[j].Seq
	})
	var best *Bug
	bestPrio := 0
	for i, bug := range bugs {
		if i != 0 && bugs[i-1].Title == bug.Title {
			continue // skip inactive bugs
		}
		if active, err := isActiveBug(ctx, bug); err != nil {
			return nil, err
		} else if !active {
			continue
		}
		// Generally we should have few candidates (one in most cases).
		// However, it's possible if e.g. we first get a data race between A<->B,
		// then a race between C<->D and now we handle a race between B<->D,
		// it can be merged into any of the previous ones.
		// The priority here is very basic. The only known case we want to handle is bug title renaming
		// where we have an active bug with title A, but then A is renamed to B and A is attached as alt title.
		// In such case we want to merge the new crash into the old one. However, it's also unlikely that
		// in this case we have any other candidates.
		// Overall selection algorithm can be arbitrary changed because the selection for existing crashes
		// is fixed with bug.MergedTitles (stable for existing bugs/crashes).
		prio := 0
		if stringInList(titles[1:], bug.Title) {
			prio = 2
		} else if stringInList(bug.AltTitles[1:], titles[0]) {
			prio = 1
		}
		if best == nil || prio > bestPrio {
			best, bestPrio = bug, prio
		}
	}
	return best, nil
}

func createBugForCrash(ctx context.Context, ns string, req *dashapi.Crash) (*Bug, error) {
	// Datastore limits the number of entities involved in a transaction to 25, so it's possible
	// to iterate over them all only up to some point.
	// To optimize the process, let's first obtain the maximum known seq for the title outside
	// of the transaction and then iterate a bit more in case of conflicts.
	startSeq := int64(0)
	prevBug, err := highestSeqBug(ctx, ns, req.Title)
	if err != nil {
		return nil, err
	} else if prevBug != nil {
		startSeq = prevBug.Seq + 1
	}

	var bug *Bug
	now := timeNow(ctx)
	tx := func(ctx context.Context) error {
		for seq := startSeq; ; seq++ {
			bug = new(Bug)
			bugHash := bugKeyHash(ctx, ns, req.Title, seq)
			bugKey := db.NewKey(ctx, "Bug", bugHash, 0, nil)
			if err := db.Get(ctx, bugKey, bug); err != nil {
				if err != db.ErrNoSuchEntity {
					return fmt.Errorf("failed to get bug: %w", err)
				}
				bug = &Bug{
					Namespace:      ns,
					Seq:            seq,
					Title:          req.Title,
					MergedTitles:   []string{req.Title},
					AltTitles:      req.AltTitles,
					Status:         BugStatusOpen,
					NumCrashes:     0,
					NumRepro:       0,
					ReproLevel:     ReproLevelNone,
					HasReport:      false,
					FirstTime:      now,
					LastTime:       now,
					SubsystemsTime: now,
				}
				err = bug.updateReportings(ctx, getNsConfig(ctx, ns), now)
				if err != nil {
					return err
				}
				if _, err = db.Put(ctx, bugKey, bug); err != nil {
					return fmt.Errorf("failed to put new bug: %w", err)
				}
				return nil
			}
			canon, err := canonicalBug(ctx, bug)
			if err != nil {
				return err
			}
			if canon.Status != BugStatusOpen {
				continue
			}
			return nil
		}
	}
	if err := runInTransaction(ctx, tx, &db.TransactionOptions{
		XG: true,
		// Very valuable transaction.
		Attempts: 30,
	}); err != nil {
		return nil, err
	}
	return bug, nil
}

func isActiveBug(ctx context.Context, bug *Bug) (bool, error) {
	if bug == nil {
		return false, nil
	}
	canon, err := canonicalBug(ctx, bug)
	if err != nil {
		return false, err
	}
	return canon.Status == BugStatusOpen, nil
}

func needRepro(ctx context.Context, bug *Bug) bool {
	if !needReproForBug(ctx, bug) {
		return false
	}
	canon, err := canonicalBug(ctx, bug)
	if err != nil {
		log.Errorf(ctx, "failed to get canonical bug: %v", err)
		return false
	}
	return needReproForBug(ctx, canon)
}

var syzErrorTitleRe = regexp.MustCompile(`^SYZFAIL:|^SYZFATAL:`)

func needReproForBug(ctx context.Context, bug *Bug) bool {
	// We already have fixing commits.
	if len(bug.Commits) > 0 {
		return false
	}
	if bug.Title == corruptedReportTitle ||
		bug.Title == suppressedReportTitle {
		return false
	}
	if !getNsConfig(ctx, bug.Namespace).NeedRepro(bug) {
		return false
	}
	bestReproLevel := ReproLevelC
	// For some bugs there's anyway no chance to find a C repro.
	if syzErrorTitleRe.MatchString(bug.Title) {
		bestReproLevel = ReproLevelSyz
	}
	if bug.HeadReproLevel < bestReproLevel {
		// We have not found a best-level repro yet, try until we do.
		return bug.NumRepro < maxReproPerBug || timeSince(ctx, bug.LastReproTime) >= reproRetryPeriod
	}
	// When the best repro is already found, still do a repro attempt once in a while.
	return timeSince(ctx, bug.LastReproTime) >= reproStalePeriod
}

var dedupTextFor = map[string]bool{
	textKernelConfig: true,
	textMachineInfo:  true,
}

func putText(ctx context.Context, ns, tag string, data []byte) (int64, error) {
	if ns == "" {
		return 0, fmt.Errorf("putting text outside of namespace")
	}
	if len(data) == 0 {
		return 0, nil
	}
	const (
		// Kernel crash log is capped at ~1MB, but vm.Diagnose can add more.
		// These text files usually compress very well.
		maxTextLen       = 10 << 20   // 10 MB
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
		// For crash logs, it's better to preserve the end of the log - that is,
		// where the panic message resides.
		// Other types of data are not really assumed to be larger than 1MB compressed.
		data = data[len(data)/10:]
		b.Reset()
	}
	var key *db.Key
	if dedupTextFor[tag] {
		h := hash.Hash([]byte(ns), b.Bytes())
		key = db.NewKey(ctx, tag, "", h.Truncate64(), nil)
	} else {
		key = db.NewIncompleteKey(ctx, tag, nil)
	}
	text := &Text{
		Namespace: ns,
		Text:      b.Bytes(),
	}
	key, err := db.Put(ctx, key, text)
	if err != nil {
		return 0, err
	}
	return key.IntID(), nil
}

func getText(ctx context.Context, tag string, id int64) ([]byte, string, error) {
	if id == 0 {
		return nil, "", nil
	}
	text := new(Text)
	if err := db.Get(ctx, db.NewKey(ctx, tag, "", id, nil), text); err != nil {
		return nil, "", fmt.Errorf("failed to read text %v: %w", tag, err)
	}
	d, err := gzip.NewReader(bytes.NewBuffer(text.Text))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read text %v: %w", tag, err)
	}
	data, err := io.ReadAll(d)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read text %v: %w", tag, err)
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

// Verifies that the given credentials are acceptable and returns the
// corresponding namespace.
func checkClient(conf *GlobalConfig, name0, secretPassword, oauthSubject string) (string, error) {
	checkAuth := func(ns, a string) (string, error) {
		if strings.HasPrefix(a, auth.OauthMagic) &&
			subtle.ConstantTimeCompare([]byte(a), []byte(oauthSubject)) == 1 {
			return ns, nil
		}
		if subtle.ConstantTimeCompare([]byte(a), []byte(secretPassword)) == 0 {
			return ns, ErrAccess
		}
		return ns, nil
	}
	for name, authenticator := range conf.Clients {
		if name == name0 {
			return checkAuth("", authenticator)
		}
	}
	for ns, cfg := range conf.Namespaces {
		for name, authenticator := range cfg.Clients {
			if name == name0 {
				return checkAuth(ns, authenticator)
			}
		}
	}
	return "", ErrAccess
}

func handleRefreshSubsystems(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	const updateBugsCount = 25
	for ns := range getConfig(c).Namespaces {
		err := reassignBugSubsystems(c, ns, updateBugsCount)
		if err != nil {
			log.Errorf(c, "failed to update subsystems for %s: %v", ns, err)
		}
	}
}

func apiSaveDiscussion(ctx context.Context, req *dashapi.SaveDiscussionReq) (any, error) {
	d := req.Discussion
	newBugIDs := []string{}
	for _, id := range d.BugIDs {
		_, _, err := findBugByReportingID(ctx, id)
		if err == nil {
			newBugIDs = append(newBugIDs, id)
		}
	}
	d.BugIDs = newBugIDs
	if len(d.BugIDs) == 0 {
		return nil, nil
	}
	return nil, mergeDiscussion(ctx, d)
}

func emergentlyStopped(ctx context.Context) (bool, error) {
	keys, err := db.NewQuery("EmergencyStop").
		Limit(1).
		KeysOnly().
		GetAll(ctx, nil)
	if err != nil {
		return false, err
	}
	return len(keys) > 0, nil
}

func recordEmergencyStop(ctx context.Context) error {
	key := db.NewKey(ctx, "EmergencyStop", "all", 0, nil)
	_, err := db.Put(ctx, key, &EmergencyStop{
		Time: timeNow(ctx),
		User: user.Current(ctx).Email,
	})
	return err
}

// Share crash logs for non-reproduced bugs with syz-managers.
// In future, this can also take care of repro exchange between instances
// in the place of syz-hub.
func apiLogToReproduce(ctx context.Context, ns string, req *dashapi.LogToReproReq) (any, error) {
	build, err := loadBuild(ctx, ns, req.BuildID)
	if err != nil {
		return nil, err
	}
	// First check if there have been any manual requests.
	log, err := takeReproTask(ctx, ns, build.Manager)
	if err != nil {
		return nil, err
	}
	if log != nil {
		return &dashapi.LogToReproResp{
			CrashLog: log,
			Type:     dashapi.ManualLog,
		}, nil
	}

	bugs, _, err := loadAllBugs(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).
			Filter("HappenedOn=", build.Manager).
			Filter("Status=", BugStatusOpen)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs: %w", err)
	}
	rand.New(rand.NewSource(timeNow(ctx).UnixNano())).Shuffle(len(bugs), func(i, j int) {
		bugs[i], bugs[j] = bugs[j], bugs[i]
	})
	// Let's limit the load on the DB.
	const bugsToConsider = 10
	checkedBugs := 0
	for _, bug := range bugs {
		if bug.ReproLevel != ReproLevelNone {
			continue
		}
		if len(bug.Commits) > 0 || len(bug.ReproAttempts) > 0 {
			// For now let's focus on all bugs where we have never ever
			// finished a bug reproduction process.
			continue
		}
		if !crashNeedsRepro(bug.Title) || !needReproForBug(ctx, bug) {
			continue
		}
		checkedBugs++
		if checkedBugs > bugsToConsider {
			break
		}
		resp, err := logToReproForBug(ctx, bug, build.Manager)
		if resp != nil || err != nil {
			return resp, err
		}
	}
	return nil, nil
}

func logToReproForBug(ctx context.Context, bug *Bug, manager string) (*dashapi.LogToReproResp, error) {
	const considerCrashes = 10
	crashes, _, err := queryCrashesForBug(ctx, bug.key(ctx), considerCrashes)
	if err != nil {
		return nil, err
	}
	for _, crash := range crashes {
		if crash.Manager != manager {
			continue
		}
		crashLog, _, err := getText(ctx, textCrashLog, crash.Log)
		if err != nil {
			return nil, fmt.Errorf("failed to query a crash log: %w", err)
		}
		return &dashapi.LogToReproResp{
			Title:    bug.Title,
			CrashLog: crashLog,
			Type:     dashapi.RetryReproLog,
		}, nil
	}
	return nil, nil
}

func saveReproTask(ctx context.Context, ns, manager string, repro []byte) error {
	log, err := putText(ctx, ns, textCrashLog, repro)
	if err != nil {
		return err
	}
	// We don't control the status of each attempt, so let's just try twice.
	const attempts = 2
	obj := &ReproTask{
		Namespace:    ns,
		Manager:      manager,
		Log:          log,
		AttemptsLeft: attempts,
	}
	key := db.NewIncompleteKey(ctx, "ReproTask", nil)
	_, err = db.Put(ctx, key, obj)
	return err
}

func takeReproTask(ctx context.Context, ns, manager string) ([]byte, error) {
	var tasks []*ReproTask
	keys, err := db.NewQuery("ReproTask").
		Filter("Namespace=", ns).
		Filter("Manager=", manager).
		Filter("AttemptsLeft>", 0).
		GetAll(ctx, &tasks)
	if err != nil || len(keys) == 0 {
		return nil, err
	}

	// Yes, it's possible that the entity will be modified simultaneously, and we
	// ideall need a transaction, but let's just ignore this possibility  -- in the
	// worst case we'd just try to reproduce it once more.
	key, task := keys[0], tasks[0]
	task.AttemptsLeft--
	task.LastAttempt = timeNow(ctx)
	if _, err := db.Put(ctx, key, task); err != nil {
		return nil, err
	}
	log, _, err := getText(ctx, textCrashLog, task.Log)
	return log, err
}

func apiCreateUploadURL(ctx context.Context, req *any) (any, error) {
	bucket := getConfig(ctx).UploadBucket
	if bucket == "" {
		return nil, errors.New("not configured")
	}
	return fmt.Sprintf("%s/%s.upload", bucket, uuid.New().String()), nil
}

func apiSendEmail(ctx context.Context, req *dashapi.SendEmailReq) (any, error) {
	var headers mail.Header
	if req.InReplyTo != "" {
		headers = mail.Header{"In-Reply-To": []string{req.InReplyTo}}
	}
	return nil, sendEmail(ctx, &aemail.Message{
		Sender:  req.Sender,
		Headers: headers,
		To:      req.To,
		Cc:      req.Cc,
		Subject: req.Subject,
		Body:    req.Body,
	})
}

// apiSaveCoverage reads jsonl data from payload and stores it to coveragedb.
// First payload jsonl line is a coveragedb.HistoryRecord (w/o session and time).
// Second+ records are coveragedb.JSONLWrapper.
func apiSaveCoverage(ctx context.Context, payload io.Reader) (any, error) {
	descr := new(coveragedb.HistoryRecord)
	jsonDec := json.NewDecoder(payload)
	if err := jsonDec.Decode(descr); err != nil {
		return 0, fmt.Errorf("json.NewDecoder(coveragedb.HistoryRecord).Decode: %w", err)
	}
	rowsCreated, err := coveragedb.SaveMergeResult(ctx, getCoverageDBClient(ctx), descr, jsonDec)
	if err != nil {
		log.Errorf(ctx, "error storing coverage for ns %s, date %s: %v",
			descr.Namespace, descr.DateTo.String(), err)
	} else {
		log.Infof(ctx, "updated coverage for ns %s, date %s to %d rows",
			descr.Namespace, descr.DateTo.String(), descr.TotalRows)
	}
	return &rowsCreated, err
}
