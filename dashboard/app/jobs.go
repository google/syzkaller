// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	db "google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// handleTestRequest added new job to db.
// Returns empty string if job added successfully, or reason why it wasn't added.
func handleTestRequest(c context.Context, bugID, user, extID, link, patch, repo, branch string,
	jobCC []string) string {
	log.Infof(c, "test request: bug=%q user=%q extID=%q patch=%v, repo=%q branch=%q",
		bugID, user, extID, len(patch), repo, branch)
	for _, blacklisted := range config.EmailBlacklist {
		if user == blacklisted {
			log.Errorf(c, "test request from blacklisted user: %v", user)
			return ""
		}
	}
	bug, bugKey, err := findBugByReportingID(c, bugID)
	if err != nil {
		log.Errorf(c, "can't find bug: %v", err)
		if link != "" {
			return "" // don't send duplicate error reply
		}
		myEmail, _ := email.AddAddrContext(ownEmail(c), "hash")
		return fmt.Sprintf("can't find the associated bug (do you have %v in To/CC?)", myEmail)
	}
	bugReporting, _ := bugReportingByID(bug, bugID)
	now := timeNow(c)
	reply, err := addTestJob(c, bug, bugKey, bugReporting, user, extID, link, patch, repo, branch, jobCC, now)
	if err != nil {
		log.Errorf(c, "test request failed: %v", err)
		if reply == "" {
			reply = internalError
		}
	}
	// Update bug CC and last activity time.
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return err
		}
		bug.LastActivity = now
		bugReporting = bugReportingByName(bug, bugReporting.Name)
		bugCC := strings.Split(bugReporting.CC, "|")
		merged := email.MergeEmailLists(bugCC, jobCC)
		bugReporting.CC = strings.Join(merged, "|")
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	if err := db.RunInTransaction(c, tx, nil); err != nil {
		// We've already stored the job, so just log the error.
		log.Errorf(c, "failed to update bug: %v", err)
	}
	if link != "" {
		reply = "" // don't send duplicate error reply
	}
	return reply
}

func addTestJob(c context.Context, bug *Bug, bugKey *db.Key, bugReporting *BugReporting,
	user, extID, link, patch, repo, branch string, jobCC []string, now time.Time) (string, error) {
	crash, crashKey, err := findCrashForBug(c, bug)
	if err != nil {
		return "", err
	}
	if reason := checkTestJob(c, bug, bugReporting, crash, repo, branch); reason != "" {
		return reason, nil
	}

	manager := crash.Manager
	for _, ns := range config.Namespaces {
		if mgr, ok := ns.Managers[manager]; ok {
			if mgr.RestrictedTestingRepo != "" && repo != mgr.RestrictedTestingRepo {
				return mgr.RestrictedTestingReason, nil
			}
			if mgr.Decommissioned {
				manager = mgr.DelegatedTo
			}
			break
		}
	}

	patchID, err := putText(c, bug.Namespace, textPatch, []byte(patch), false)
	if err != nil {
		return "", err
	}

	job := &Job{
		Type:         JobTestPatch,
		Created:      now,
		User:         user,
		CC:           jobCC,
		Reporting:    bugReporting.Name,
		ExtID:        extID,
		Link:         link,
		Namespace:    bug.Namespace,
		Manager:      manager,
		BugTitle:     bug.displayTitle(),
		CrashID:      crashKey.IntID(),
		KernelRepo:   repo,
		KernelBranch: branch,
		Patch:        patchID,
	}

	deletePatch := false
	tx := func(c context.Context) error {
		deletePatch = false
		// We can get 2 emails for the same request: one direct and one from a mailing list.
		// Filter out such duplicates (for dup we only need link update).
		var jobs []*Job
		keys, err := db.NewQuery("Job").
			Ancestor(bugKey).
			Filter("ExtID=", extID).
			GetAll(c, &jobs)
		if len(jobs) > 1 || err != nil {
			return fmt.Errorf("failed to query jobs: jobs=%v err=%v", len(jobs), err)
		}
		if len(jobs) != 0 {
			// The job is already present, update link.
			deletePatch = true
			existingJob, jobKey := jobs[0], keys[0]
			if existingJob.Link != "" || link == "" {
				return nil
			}
			existingJob.Link = link
			if _, err := db.Put(c, jobKey, existingJob); err != nil {
				return fmt.Errorf("failed to put job: %v", err)
			}
			return nil
		}
		// Create a new job.
		jobKey := db.NewIncompleteKey(c, "Job", bugKey)
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		return markCrashReported(c, job.CrashID, bugKey, now)
	}
	err = db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 30})
	if patchID != 0 && deletePatch || err != nil {
		if err := db.Delete(c, db.NewKey(c, textPatch, "", patchID, nil)); err != nil {
			log.Errorf(c, "failed to delete patch for dup job: %v", err)
		}
	}
	if err != nil {
		return "", fmt.Errorf("job tx failed: %v", err)
	}
	return "", nil
}

func checkTestJob(c context.Context, bug *Bug, bugReporting *BugReporting, crash *Crash,
	repo, branch string) string {
	switch {
	case crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it."
	case !vcs.CheckRepoAddress(repo):
		return fmt.Sprintf("%q does not look like a valid git repo address.", repo)
	case !vcs.CheckBranch(branch) && !vcs.CheckCommitHash(branch):
		return fmt.Sprintf("%q does not look like a valid git branch or commit.", branch)
	case crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it."
	case bug.Status == BugStatusFixed:
		return "This bug is already marked as fixed. No point in testing."
	case bug.Status == BugStatusInvalid:
		return "This bug is already marked as invalid. No point in testing."
	// TODO(dvyukov): for BugStatusDup check status of the canonical bug.
	case !bugReporting.Closed.IsZero():
		return "This bug is already upstreamed. Please test upstream."
	}
	return ""
}

// pollPendingJobs returns the next job to execute for the provided list of managers.
func pollPendingJobs(c context.Context, testMgrs, bisectMgrs []string) (*dashapi.JobPollResp, error) {
	testManagers := make(map[string]bool)
	for _, mgr := range testMgrs {
		testManagers[mgr] = true
	}
	bisectManagers := make(map[string]bool)
	for _, mgr := range bisectMgrs {
		bisectManagers[mgr] = true
	}
retry:
	job, jobKey, err := getNextJob(c, testManagers, bisectManagers)
	if job == nil || err != nil {
		return nil, err
	}
	resp, stale, err := createJobResp(c, job, jobKey)
	if err != nil {
		return nil, err
	}
	if stale {
		goto retry
	}
	return resp, nil
}

func getNextJob(c context.Context, testManagers, bisectManagers map[string]bool) (*Job, *db.Key, error) {
	job, jobKey, err := loadPendingJob(c, testManagers, bisectManagers)
	if job != nil || err != nil {
		return job, jobKey, err
	}
	if len(bisectManagers) == 0 {
		return nil, nil, nil
	}
	// We need both C and syz repros, but the crazy datastore query restrictions
	// do not allow to use ReproLevel>ReproLevelNone in the query.  So we do 2 separate queries.
	// C repros tend to be of higher reliability so maybe it's not bad.
	job, jobKey, err = createBisectJob(c, bisectManagers, ReproLevelC)
	if job != nil || err != nil {
		return job, jobKey, err
	}
	return createBisectJob(c, bisectManagers, ReproLevelSyz)
}

func createBisectJob(c context.Context, managers map[string]bool, reproLevel dashapi.ReproLevel) (
	*Job, *db.Key, error) {
	var bugs []*Bug
	// Note: we could also include len(Commits)==0 but datastore does not work this way.
	// So we would need an additional HasCommits field or something.
	keys, err := db.NewQuery("Bug").
		Filter("Status=", BugStatusOpen).
		Filter("FirstTime>", time.Time{}).
		Filter("ReproLevel=", reproLevel).
		Filter("BisectCause=", BisectNot).
		Order("-FirstTime").
		Limit(300). // we only need 1 job, but we skip some because the query is not precise
		GetAll(c, &bugs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query bugs: %v", err)
	}
	for bi, bug := range bugs {
		if !shouldBisectBug(bug, managers) {
			continue
		}
		crash, crashKey, err := bisectCrashForBug(c, keys[bi], managers)
		if err != nil {
			return nil, nil, err
		}
		if crash == nil {
			continue
		}
		return createBisectJobForBug(c, bug, crash, keys[bi], crashKey)
	}
	return nil, nil, nil
}

func shouldBisectBug(bug *Bug, managers map[string]bool) bool {
	if len(bug.Commits) != 0 {
		return false
	}
	for _, mgr := range bug.HappenedOn {
		if managers[mgr] {
			return true
		}
	}
	return false
}

func bisectCrashForBug(c context.Context, bugKey *db.Key, managers map[string]bool) (
	*Crash, *db.Key, error) {
	crashes, crashKeys, err := queryCrashesForBug(c, bugKey, maxCrashes)
	if err != nil {
		return nil, nil, err
	}
	for ci, crash := range crashes {
		if crash.ReproSyz == 0 || !managers[crash.Manager] {
			continue
		}
		return crash, crashKeys[ci], nil
	}
	return nil, nil, nil
}

func createBisectJobForBug(c context.Context, bug0 *Bug, crash *Crash, bugKey, crashKey *db.Key) (
	*Job, *db.Key, error) {
	build, err := loadBuild(c, bug0.Namespace, crash.BuildID)
	if err != nil {
		return nil, nil, err
	}
	now := timeNow(c)
	job := &Job{
		Type:         JobBisectCause,
		Created:      now,
		Namespace:    bug0.Namespace,
		Manager:      crash.Manager,
		KernelRepo:   build.KernelRepo,
		KernelBranch: build.KernelBranch,
		BugTitle:     bug0.displayTitle(),
		CrashID:      crashKey.IntID(),
	}
	var jobKey *db.Key
	tx := func(c context.Context) error {
		jobKey = nil
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug %v: %v", bugKey.StringID(), err)
		}
		if bug.BisectCause != BisectNot {
			// Race, we could do a more complex retry, but we just rely on the next poll.
			job = nil
			return nil
		}
		bug.BisectCause = BisectPending
		// Create a new job.
		var err error
		jobKey = db.NewIncompleteKey(c, "Job", bugKey)
		if jobKey, err = db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return markCrashReported(c, job.CrashID, bugKey, now)
	}
	if err := db.RunInTransaction(c, tx, nil); err != nil {
		return nil, nil, fmt.Errorf("create bisect job tx failed: %v", err)
	}
	return job, jobKey, nil
}

func createJobResp(c context.Context, job *Job, jobKey *db.Key) (*dashapi.JobPollResp, bool, error) {
	jobID := extJobID(jobKey)
	patch, _, err := getText(c, textPatch, job.Patch)
	if err != nil {
		return nil, false, err
	}
	bugKey := jobKey.Parent()
	crashKey := db.NewKey(c, "Crash", "", job.CrashID, bugKey)
	crash := new(Crash)
	if err := db.Get(c, crashKey, crash); err != nil {
		return nil, false, fmt.Errorf("job %v: failed to get crash: %v", jobID, err)
	}

	build, err := loadBuild(c, job.Namespace, crash.BuildID)
	if err != nil {
		return nil, false, err
	}
	kernelConfig, _, err := getText(c, textKernelConfig, build.KernelConfig)
	if err != nil {
		return nil, false, err
	}

	reproC, _, err := getText(c, textReproC, crash.ReproC)
	if err != nil {
		return nil, false, err
	}
	reproSyz, _, err := getText(c, textReproSyz, crash.ReproSyz)
	if err != nil {
		return nil, false, err
	}

	now := timeNow(c)
	stale := false
	tx := func(c context.Context) error {
		stale = false
		job = new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get in tx: %v", jobID, err)
		}
		if !job.Finished.IsZero() {
			// This happens sometimes due to inconsistent db.
			stale = true
			return nil
		}
		job.Attempts++
		job.Started = now
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to put: %v", jobID, err)
		}
		return nil
	}
	if err := db.RunInTransaction(c, tx, nil); err != nil {
		return nil, false, err
	}
	if stale {
		return nil, true, nil
	}
	resp := &dashapi.JobPollResp{
		ID:                jobID,
		Manager:           job.Manager,
		KernelRepo:        job.KernelRepo,
		KernelBranch:      job.KernelBranch,
		KernelCommit:      build.KernelCommit,
		KernelCommitTitle: build.KernelCommitTitle,
		KernelCommitDate:  build.KernelCommitDate,
		KernelConfig:      kernelConfig,
		SyzkallerCommit:   build.SyzkallerCommit,
		Patch:             patch,
		ReproOpts:         crash.ReproOpts,
		ReproSyz:          reproSyz,
		ReproC:            reproC,
	}
	switch job.Type {
	case JobTestPatch:
		resp.Type = dashapi.JobTestPatch
	case JobBisectCause:
		resp.Type = dashapi.JobBisectCause
	case JobBisectFix:
		resp.Type = dashapi.JobBisectFix
	default:
		return nil, false, fmt.Errorf("bad job type %v", job.Type)
	}
	return resp, false, nil
}

// doneJob is called by syz-ci to mark completion of a job.
func doneJob(c context.Context, req *dashapi.JobDoneReq) error {
	jobID := req.ID
	jobKey, err := jobID2Key(c, req.ID)
	if err != nil {
		return err
	}
	now := timeNow(c)
	tx := func(c context.Context) error {
		job := new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get job: %v", jobID, err)
		}
		if !job.Finished.IsZero() {
			return fmt.Errorf("job %v: already finished", jobID)
		}
		ns := job.Namespace
		if req.Build.ID != "" {
			if _, isNewBuild, err := uploadBuild(c, now, ns, &req.Build, BuildJob); err != nil {
				return err
			} else if !isNewBuild {
				log.Errorf(c, "job %v: duplicate build %v", jobID, req.Build.ID)
			}
		}
		if job.Log, err = putText(c, ns, textLog, req.Log, false); err != nil {
			return err
		}
		if job.Error, err = putText(c, ns, textError, req.Error, false); err != nil {
			return err
		}
		if job.CrashLog, err = putText(c, ns, textCrashLog, req.CrashLog, false); err != nil {
			return err
		}
		if job.CrashReport, err = putText(c, ns, textCrashReport, req.CrashReport, false); err != nil {
			return err
		}
		for _, com := range req.Commits {
			job.Commits = append(job.Commits, Commit{
				Hash:       com.Hash,
				Title:      com.Title,
				Author:     com.Author,
				AuthorName: com.AuthorName,
				CC:         strings.Join(sanitizeCC(c, com.CC), "|"),
				Date:       com.Date,
			})
		}
		if job.Type == JobBisectCause || job.Type == JobBisectFix {
			// Update bug.BisectCause/Fix status and also remember current bug reporting to send results.
			bug := new(Bug)
			bugKey := jobKey.Parent()
			if err := db.Get(c, bugKey, bug); err != nil {
				return fmt.Errorf("job %v: failed to get bug: %v", jobID, err)
			}
			result := BisectYes
			if len(req.Error) != 0 {
				result = BisectError
			}
			if job.Type == JobBisectCause {
				bug.BisectCause = result
			} else {
				bug.BisectFix = result
			}
			if _, err := db.Put(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to put bug: %v", err)
			}
			_, bugReporting, _, _, _ := currentReporting(c, bug)
			if bugReporting == nil || bugReporting.Reported.IsZero() {
				// The bug is either already closed or not yet reported in the current reporting,
				// either way we don't need to report it. If it wasn't reported, it will be reported
				// with the bisection results.
				job.Reported = true
			} else {
				job.Reporting = bugReporting.Name
			}
		}
		if job.Error != 0 && job.Type != JobTestPatch {
			// Don't report errors for non-user-initiated jobs.
			job.Reported = true
		}
		job.BuildID = req.Build.ID
		job.CrashTitle = req.CrashTitle
		job.Finished = now
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		log.Infof(c, "DONE JOB %v: reported=%v reporting=%v", jobID, job.Reported, job.Reporting)
		return nil
	}
	return db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 30})
}

func pollCompletedJobs(c context.Context, typ string) ([]*dashapi.BugReport, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Finished>", time.Time{}).
		Filter("Reported=", false).
		GetAll(c, &jobs)
	if err != nil {
		return nil, fmt.Errorf("failed to query jobs: %v", err)
	}
	var reports []*dashapi.BugReport
	for i, job := range jobs {
		if job.Reporting == "" {
			log.Criticalf(c, "no reporting for job %v", extJobID(keys[i]))
			continue
		}
		reporting := config.Namespaces[job.Namespace].ReportingByName(job.Reporting)
		if reporting.Config.Type() != typ {
			continue
		}
		// TODO: this is temporal for gradual bisection rollout.
		// Notify only about successful bisection for now.
		if !appengine.IsDevAppServer() && job.Type != JobTestPatch && len(job.Commits) != 1 {
			continue
		}
		rep, err := createBugReportForJob(c, job, keys[i], reporting.Config)
		if err != nil {
			log.Errorf(c, "failed to create report for job: %v", err)
			continue
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

func createBugReportForJob(c context.Context, job *Job, jobKey *db.Key, config interface{}) (
	*dashapi.BugReport, error) {
	reportingConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	crashLog, _, err := getText(c, textCrashLog, job.CrashLog)
	if err != nil {
		return nil, err
	}
	if len(crashLog) > maxMailLogLen {
		crashLog = crashLog[len(crashLog)-maxMailLogLen:]
	}
	report, _, err := getText(c, textCrashReport, job.CrashReport)
	if err != nil {
		return nil, err
	}
	if len(report) > maxMailReportLen {
		report = report[:maxMailReportLen]
	}
	jobError, _, err := getText(c, textError, job.Error)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, job.Namespace, job.BuildID)
	if err != nil {
		return nil, err
	}
	bugKey := jobKey.Parent()
	crashKey := db.NewKey(c, "Crash", "", job.CrashID, bugKey)
	crash := new(Crash)
	if err := db.Get(c, crashKey, crash); err != nil {
		return nil, fmt.Errorf("failed to get crash: %v", err)
	}
	bug := new(Bug)
	if err := db.Get(c, bugKey, bug); err != nil {
		return nil, fmt.Errorf("failed to load job parent bug: %v", err)
	}
	bugReporting := bugReportingByName(bug, job.Reporting)
	if bugReporting == nil {
		return nil, fmt.Errorf("job bug has no reporting %q", job.Reporting)
	}
	var typ dashapi.ReportType
	switch job.Type {
	case JobTestPatch:
		typ = dashapi.ReportTestPatch
	case JobBisectCause:
		typ = dashapi.ReportBisectCause
	case JobBisectFix:
		typ = dashapi.ReportBisectFix
	default:
		return nil, fmt.Errorf("unknown job type %v", job.Type)
	}
	rep := &dashapi.BugReport{
		Type:         typ,
		Config:       reportingConfig,
		JobID:        extJobID(jobKey),
		ExtID:        job.ExtID,
		CC:           job.CC,
		Log:          crashLog,
		LogLink:      externalLink(c, textCrashLog, job.CrashLog),
		Report:       report,
		ReportLink:   externalLink(c, textCrashReport, job.CrashReport),
		ReproCLink:   externalLink(c, textReproC, crash.ReproC),
		ReproSyzLink: externalLink(c, textReproSyz, crash.ReproSyz),
		CrashTitle:   job.CrashTitle,
		Error:        jobError,
		ErrorLink:    externalLink(c, textError, job.Error),
		PatchLink:    externalLink(c, textPatch, job.Patch),
	}
	if job.Type == JobBisectCause || job.Type == JobBisectFix {
		kernelRepo := kernelRepoInfo(build)
		rep.Maintainers = append(crash.Maintainers, kernelRepo.CC...)
		rep.ExtID = bugReporting.ExtID
		if bugReporting.CC != "" {
			rep.CC = strings.Split(bugReporting.CC, "|")
		}
		switch job.Type {
		case JobBisectCause:
			rep.BisectCause = bisectFromJob(c, rep, job)
		case JobBisectFix:
			rep.BisectFix = bisectFromJob(c, rep, job)
		}
	}
	// Build error output and failing VM boot log can be way too long to inline.
	if len(rep.Error) > maxInlineError {
		rep.Error = rep.Error[len(rep.Error)-maxInlineError:]
		rep.ErrorTruncated = true
	}
	if err := fillBugReport(c, rep, bug, bugReporting, build); err != nil {
		return nil, err
	}
	return rep, nil
}

func bisectFromJob(c context.Context, rep *dashapi.BugReport, job *Job) *dashapi.BisectResult {
	bisect := &dashapi.BisectResult{
		LogLink:         externalLink(c, textLog, job.Log),
		CrashLogLink:    externalLink(c, textCrashLog, job.CrashLog),
		CrashReportLink: externalLink(c, textCrashReport, job.CrashReport),
	}
	for _, com := range job.Commits {
		bisect.Commits = append(bisect.Commits, &dashapi.Commit{
			Hash:       com.Hash,
			Title:      com.Title,
			Author:     com.Author,
			AuthorName: com.AuthorName,
			Date:       com.Date,
		})
	}
	if len(bisect.Commits) == 1 {
		bisect.Commit = bisect.Commits[0]
		bisect.Commits = nil
		com := job.Commits[0]
		rep.Maintainers = append(rep.Maintainers, com.Author)
		rep.Maintainers = append(rep.Maintainers, strings.Split(com.CC, "|")...)
	}
	return bisect
}

func jobReported(c context.Context, jobID string) error {
	jobKey, err := jobID2Key(c, jobID)
	if err != nil {
		return err
	}
	tx := func(c context.Context) error {
		job := new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get job: %v", jobID, err)
		}
		job.Reported = true
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		return nil
	}
	return db.RunInTransaction(c, tx, nil)
}

func loadPendingJob(c context.Context, testManagers, bisectManagers map[string]bool) (*Job, *db.Key, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Finished=", time.Time{}).
		Order("Attempts").
		Order("Created").
		GetAll(c, &jobs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query jobs: %v", err)
	}
	for i, job := range jobs {
		switch job.Type {
		case JobTestPatch:
			if !testManagers[job.Manager] {
				continue
			}
		case JobBisectCause, JobBisectFix:
			if !bisectManagers[job.Manager] {
				continue
			}
			// Don't retry bisection jobs too often.
			// This allows to have several syz-ci's doing bisection
			// and protects from bisection job crashing syz-ci.
			const bisectRepeat = 3 * 24 * time.Hour
			if timeSince(c, job.Created) < bisectRepeat ||
				timeSince(c, job.Started) < bisectRepeat {
				continue
			}
		default:
			return nil, nil, fmt.Errorf("bad job type %v", job.Type)
		}
		return job, keys[i], nil
	}
	return nil, nil, nil
}

func extJobID(jobKey *db.Key) string {
	return fmt.Sprintf("%v|%v", jobKey.Parent().StringID(), jobKey.IntID())
}

func jobID2Key(c context.Context, id string) (*db.Key, error) {
	keyStr := strings.Split(id, "|")
	if len(keyStr) != 2 {
		return nil, fmt.Errorf("bad job id %q", id)
	}
	jobKeyID, err := strconv.ParseInt(keyStr[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad job id %q", id)
	}
	bugKey := db.NewKey(c, "Bug", keyStr[0], 0, nil)
	jobKey := db.NewKey(c, "Job", "", jobKeyID, bugKey)
	return jobKey, nil
}
