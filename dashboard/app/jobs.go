// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

type testReqArgs struct {
	bug          *Bug
	bugKey       *db.Key
	bugReporting *BugReporting
	user         string
	extID        string
	link         string
	patch        []byte
	repo         string
	branch       string
	jobCC        []string
}

// handleTestRequest added new job to db.
// Returns nil if job added successfully.
// If the arguments are invalid, the error is of type *BadTestRequest.
// If the request was denied, the error is of type *TestRequestDenied.
// All other errors correspond to internal processing problems.
func handleTestRequest(c context.Context, args *testReqArgs) error {
	log.Infof(c, "test request: bug=%s user=%q extID=%q patch=%v, repo=%q branch=%q",
		args.bug.Title, args.user, args.extID, len(args.patch), args.repo, args.branch)
	for _, blocked := range config.EmailBlocklist {
		if args.user == blocked {
			return &TestRequestDeniedError{
				fmt.Sprintf("test request from blocked user: %v", args.user),
			}
		}
	}
	now := timeNow(c)
	crash, crashKey, err := findCrashForBug(c, args.bug)
	if err != nil {
		return fmt.Errorf("failed to find a crash: %v", err)
	}
	err = addTestJob(c, &testJobArgs{
		testReqArgs: *args,
		crash:       crash, crashKey: crashKey,
	}, now)
	if err != nil {
		return err
	}
	// Update bug CC and last activity time.
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, args.bugKey, bug); err != nil {
			return err
		}
		bug.LastActivity = now
		bugReporting := args.bugReporting
		bugReporting = bugReportingByName(bug, bugReporting.Name)
		bugCC := strings.Split(bugReporting.CC, "|")
		merged := email.MergeEmailLists(bugCC, args.jobCC)
		bugReporting.CC = strings.Join(merged, "|")
		if _, err := db.Put(c, args.bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	if err := db.RunInTransaction(c, tx, nil); err != nil {
		// We've already stored the job, so just log the error.
		log.Errorf(c, "failed to update bug: %v", err)
	}
	return nil
}

type testJobArgs struct {
	crash     *Crash
	crashKey  *db.Key
	configRef int64
	testReqArgs
}

func addTestJob(c context.Context, args *testJobArgs, now time.Time) error {
	if reason := checkTestJob(c, args.bug, args.bugReporting, args.crash,
		args.repo, args.branch); reason != "" {
		return &BadTestRequestError{reason}
	}
	manager, mgrConfig := activeManager(args.crash.Manager, args.bug.Namespace)
	if mgrConfig != nil && mgrConfig.RestrictedTestingRepo != "" &&
		args.repo != mgrConfig.RestrictedTestingRepo {
		return &BadTestRequestError{mgrConfig.RestrictedTestingReason}
	}
	patchID, err := putText(c, args.bug.Namespace, textPatch, args.patch, false)
	if err != nil {
		return err
	}
	reportingName := ""
	if args.bugReporting != nil {
		reportingName = args.bugReporting.Name
	}
	job := &Job{
		Type:         JobTestPatch,
		Created:      now,
		User:         args.user,
		CC:           args.jobCC,
		Reporting:    reportingName,
		ExtID:        args.extID,
		Link:         args.link,
		Namespace:    args.bug.Namespace,
		Manager:      manager,
		BugTitle:     args.bug.displayTitle(),
		CrashID:      args.crashKey.IntID(),
		KernelRepo:   args.repo,
		KernelBranch: args.branch,
		Patch:        patchID,
		KernelConfig: args.configRef,
	}

	deletePatch := false
	tx := func(c context.Context) error {
		deletePatch = false
		// We can get 2 emails for the same request: one direct and one from a mailing list.
		// Filter out such duplicates (for dup we only need link update).
		var jobs []*Job
		var keys []*db.Key
		var err error
		if args.extID != "" {
			keys, err = db.NewQuery("Job").
				Ancestor(args.bugKey).
				Filter("ExtID=", args.extID).
				GetAll(c, &jobs)
			if len(jobs) > 1 || err != nil {
				return fmt.Errorf("failed to query jobs: jobs=%v err=%v", len(jobs), err)
			}
		}
		if len(jobs) != 0 {
			// The job is already present, update link.
			deletePatch = true
			existingJob, jobKey := jobs[0], keys[0]
			if existingJob.Link != "" || args.link == "" {
				return nil
			}
			existingJob.Link = args.link
			if _, err := db.Put(c, jobKey, existingJob); err != nil {
				return fmt.Errorf("failed to put job: %v", err)
			}
			return nil
		}
		// Create a new job.
		jobKey := db.NewIncompleteKey(c, "Job", args.bugKey)
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		return addCrashReference(c, job.CrashID, args.bugKey,
			CrashReference{CrashReferenceJob, extJobID(jobKey), now})
	}
	err = db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 30})
	if patchID != 0 && deletePatch || err != nil {
		if err := db.Delete(c, db.NewKey(c, textPatch, "", patchID, nil)); err != nil {
			log.Errorf(c, "failed to delete patch for dup job: %v", err)
		}
	}
	if err != nil {
		return fmt.Errorf("job tx failed: %v", err)
	}
	return nil
}

func checkTestJob(c context.Context, bug *Bug, bugReporting *BugReporting, crash *Crash,
	repo, branch string) string {
	needRepro := !strings.Contains(crash.Title, "boot error:") &&
		!strings.Contains(crash.Title, "test error:") &&
		!strings.Contains(crash.Title, "build error")
	switch {
	case needRepro && crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it."
	case !vcs.CheckRepoAddress(repo):
		return fmt.Sprintf("%q does not look like a valid git repo address.", repo)
	case !vcs.CheckBranch(branch) && !vcs.CheckCommitHash(branch):
		return fmt.Sprintf("%q does not look like a valid git branch or commit.", branch)
	case bug.Status == BugStatusFixed:
		return "This bug is already marked as fixed. No point in testing."
	case bug.Status == BugStatusInvalid:
		return "This bug is already marked as invalid. No point in testing."
	// TODO(dvyukov): for BugStatusDup check status of the canonical bug.
	case bugReporting != nil && !bugReporting.Closed.IsZero():
		return "This bug is already upstreamed. Please test upstream."
	}
	return ""
}

type BadTestRequestError struct {
	message string
}

func (e *BadTestRequestError) Error() string {
	return e.message
}

type TestRequestDeniedError struct {
	message string
}

func (e *TestRequestDeniedError) Error() string {
	return e.message
}

// pollPendingJobs returns the next job to execute for the provided list of managers.
func pollPendingJobs(c context.Context, managers map[string]dashapi.ManagerJobs) (
	*dashapi.JobPollResp, error) {
retry:
	job, jobKey, err := getNextJob(c, managers)
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

func getNextJob(c context.Context, managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	job, jobKey, err := loadPendingJob(c, managers)
	if job != nil || err != nil {
		return job, jobKey, err
	}
	// We need both C and syz repros, but the crazy datastore query restrictions
	// do not allow to use ReproLevel>ReproLevelNone in the query. So we do 2 separate queries.
	// C repros tend to be of higher reliability so maybe it's not bad.
	job, jobKey, err = createBisectJob(c, managers, ReproLevelC)
	if job != nil || err != nil {
		return job, jobKey, err
	}
	return createBisectJob(c, managers, ReproLevelSyz)
}

// Ensure that for each manager there's one pending retest repro job.
func updateRetestReproJobs(c context.Context, ns string) error {
	if config.Obsoleting.ReproRetestPeriod == 0 {
		return nil
	}
	var jobs []*Job
	_, err := db.NewQuery("Job").
		Filter("Finished=", time.Time{}).
		GetAll(c, &jobs)
	if err != nil {
		return fmt.Errorf("failed to query jobs: %w", err)
	}
	managerHasJob := map[string]bool{}
	for _, job := range jobs {
		if job.User == "" && job.Type == JobTestPatch {
			managerHasJob[job.Manager] = true
		}
	}
	// Let's save resources and only re-check repros for bugs with no recent crashes.
	now := timeNow(c)
	maxLastTime := now.Add(-config.Obsoleting.ReproRetestPeriod)
	bugs, keys, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen).
			Filter("Namespace=", ns).
			Filter("LastTime<", maxLastTime)
	})
	if err != nil {
		return fmt.Errorf("failed to query bugs: %w", err)
	}
	for id, bug := range bugs {
		err := handleRetestForBug(c, now, bug, keys[id], managerHasJob)
		if err != nil {
			return fmt.Errorf("bug %v repro retesting failed: %w", keys[id], err)
		}
	}
	return nil
}

func handleRetestForBug(c context.Context, now time.Time, bug *Bug, bugKey *db.Key,
	managerHasJob map[string]bool) error {
	if len(bug.Commits) > 0 {
		// Let's save resources -- there's no point in retesting repros for bugs
		// for which we were already given fixing commits.
		return nil
	}
	crashes, crashKeys, err := queryCrashesForBug(c, bugKey, maxCrashes())
	if err != nil {
		return err
	}
	for crashID, crash := range crashes {
		if crash.ReproSyz == 0 && crash.ReproC == 0 {
			continue
		}
		if now.Sub(crash.LastReproRetest) < config.Obsoleting.ReproRetestPeriod {
			continue
		}
		if crash.ReproIsRevoked {
			// No sense in retesting the already revoked repro.
			continue
		}
		// TODO: check if the manager can do such jobs.
		if managerHasJob[crash.Manager] {
			continue
		}
		// We could have decommissioned the original manager since then.
		manager, _ := activeManager(crash.Manager, bug.Namespace)
		if manager == "" {
			continue
		}
		// Take the last successful build -- the build on which this crash happened
		// might contain already obsolete repro and branch values.
		build, err := lastManagerBuild(c, bug.Namespace, manager)
		if err != nil {
			return err
		}
		err = addTestJob(c, &testJobArgs{
			crash:     crash,
			crashKey:  crashKeys[crashID],
			configRef: build.KernelConfig,
			testReqArgs: testReqArgs{
				bug:    bug,
				bugKey: bugKey,
				repo:   build.KernelRepo,
				branch: build.KernelBranch,
			},
		}, now)
		if err != nil {
			return fmt.Errorf("failed to add job: %w", err)
		}
		managerHasJob[crash.Manager] = true
	}
	return nil
}

func createBisectJob(c context.Context, managers map[string]dashapi.ManagerJobs,
	reproLevel dashapi.ReproLevel) (*Job, *db.Key, error) {
	causeManagers := make(map[string]bool)
	fixManagers := make(map[string]bool)
	for mgr, jobs := range managers {
		if jobs.BisectCause {
			causeManagers[mgr] = true
		}
		if jobs.BisectFix {
			fixManagers[mgr] = true
		}
	}
	job, jobKey, err := findBugsForBisection(c, causeManagers, reproLevel, JobBisectCause)
	if job != nil || err != nil {
		return job, jobKey, err
	}
	return findBugsForBisection(c, fixManagers, reproLevel, JobBisectFix)
}

func findBugsForBisection(c context.Context, managers map[string]bool,
	reproLevel dashapi.ReproLevel, jobType JobType) (*Job, *db.Key, error) {
	if len(managers) == 0 {
		return nil, nil, nil
	}
	// Note: we could also include len(Commits)==0 but datastore does not work this way.
	// So we would need an additional HasCommits field or something.
	// Note: For JobBisectCause, order the bugs from newest to oldest. For JobBisectFix,
	// order the bugs from oldest to newest.
	// Sort property should be the same as property used in the inequality filter.
	// We only need 1 job, but we skip some because the query is not precise.
	bugs, keys, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		query = query.Filter("Status=", BugStatusOpen)
		if jobType == JobBisectCause {
			query = query.Filter("FirstTime>", time.Time{}).
				Filter("ReproLevel=", reproLevel).
				Filter("BisectCause=", BisectNot).
				Order("-FirstTime")
		} else {
			query = query.Filter("LastTime>", time.Time{}).
				Filter("ReproLevel=", reproLevel).
				Filter("BisectFix=", BisectNot).
				Order("LastTime")
		}
		return query
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query bugs: %v", err)
	}
	for bi, bug := range bugs {
		if !shouldBisectBug(bug, managers) {
			continue
		}
		crash, crashKey, err := bisectCrashForBug(c, bug, keys[bi], managers, jobType)
		if err != nil {
			return nil, nil, err
		}
		if crash == nil {
			continue
		}
		if jobType == JobBisectFix && timeSince(c, bug.LastTime) < 24*30*time.Hour {
			continue
		}
		return createBisectJobForBug(c, bug, crash, keys[bi], crashKey, jobType)
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

func bisectCrashForBug(c context.Context, bug *Bug, bugKey *db.Key, managers map[string]bool, jobType JobType) (
	*Crash, *db.Key, error) {
	crashes, crashKeys, err := queryCrashesForBug(c, bugKey, maxCrashes())
	if err != nil {
		return nil, nil, err
	}
	for ci, crash := range crashes {
		if crash.ReproSyz == 0 || !managers[crash.Manager] {
			continue
		}
		if jobType == JobBisectFix &&
			config.Namespaces[bug.Namespace].Managers[crash.Manager].FixBisectionDisabled {
			continue
		}
		return crash, crashKeys[ci], nil
	}
	return nil, nil, nil
}

func createBisectJobForBug(c context.Context, bug0 *Bug, crash *Crash, bugKey, crashKey *db.Key, jobType JobType) (
	*Job, *db.Key, error) {
	build, err := loadBuild(c, bug0.Namespace, crash.BuildID)
	if err != nil {
		return nil, nil, err
	}
	now := timeNow(c)
	job := &Job{
		Type:         jobType,
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
		if jobType == JobBisectFix && bug.BisectFix != BisectNot ||
			jobType == JobBisectCause && bug.BisectCause != BisectNot {
			// Race, we could do a more complex retry, but we just rely on the next poll.
			job = nil
			return nil
		}
		if jobType == JobBisectCause {
			bug.BisectCause = BisectPending
		} else {
			bug.BisectFix = BisectPending
		}
		// Create a new job.
		var err error
		jobKey = db.NewIncompleteKey(c, "Job", bugKey)
		if jobKey, err = db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return addCrashReference(c, job.CrashID, bugKey,
			CrashReference{CrashReferenceJob, extJobID(jobKey), now})
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{
		// We're accessing two different kinds in addCrashReference.
		XG: true,
	}); err != nil {
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

	configRef := job.KernelConfig
	if configRef == 0 {
		configRef = build.KernelConfig
	}
	kernelConfig, _, err := getText(c, textKernelConfig, configRef)
	if err != nil {
		return nil, false, err
	}

	reproC, _, err := getText(c, textReproC, crash.ReproC)
	if err != nil {
		return nil, false, err
	}
	reproSyz, err := loadReproSyz(c, crash)
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
		job.IsRunning = true
		job.LastStarted = now
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

// It would be easier to just check if the User field is empty, but let's also not
// miss the situation when some actual user sends a patch testing request without
// patch.
func isRetestReproJob(job *Job, build *Build) bool {
	return (job.Type == JobTestPatch || job.Type == JobBisectFix) &&
		job.Patch == 0 &&
		job.KernelRepo == build.KernelRepo &&
		job.KernelBranch == build.KernelBranch
}

func handleRetestedRepro(c context.Context, now time.Time, job *Job, jobKey *db.Key,
	lastBuild *Build, req *dashapi.JobDoneReq) error {
	bugKey := jobKey.Parent()
	crashKey := db.NewKey(c, "Crash", "", job.CrashID, bugKey)
	crash := new(Crash)
	if err := db.Get(c, crashKey, crash); err != nil {
		return fmt.Errorf("failed to get crash: %v", crashKey)
	}
	bug := new(Bug)
	if err := db.Get(c, bugKey, bug); err != nil {
		return fmt.Errorf("failed to get bug: %v", bugKey)
	}
	allTitles := gatherCrashTitles(req)
	// Update the crash.
	crash.LastReproRetest = now
	if req.Error == nil && !crash.ReproIsRevoked {
		// If repro testing itself failed, it might be just a temporary issue.
		if job.Type == JobTestPatch {
			// If there was any crash at all, the repro is still not worth discarding.
			crash.ReproIsRevoked = len(allTitles) == 0
		} else if job.Type == JobBisectFix {
			// More than one commit is suspected => repro stopped working at some point.
			crash.ReproIsRevoked = len(req.Commits) > 0
		}
	}
	crash.UpdateReportingPriority(lastBuild, bug)
	if _, err := db.Put(c, crashKey, crash); err != nil {
		return fmt.Errorf("failed to put crash: %v", err)
	}
	reproCrashes, crashKeys, err := queryCrashesForBug(c, bugKey, 2)
	if err != nil {
		return fmt.Errorf("failed to fetch crashes with repro: %v", err)
	}
	// Now we can update the bug.
	bug.HeadReproLevel = ReproLevelNone
	for id, bestCrash := range reproCrashes {
		if crashKeys[id].Equal(crashKey) {
			// In Datastore, we don't see previous writes in a transaction...
			bestCrash = crash
		}
		if bestCrash.ReproIsRevoked {
			continue
		}
		if bestCrash.ReproC > 0 {
			bug.HeadReproLevel = ReproLevelC
		} else if bug.HeadReproLevel != ReproLevelC && bestCrash.ReproSyz > 0 {
			bug.HeadReproLevel = ReproLevelSyz
		}
	}
	if stringInList(allTitles, bug.Title) || stringListsIntersect(bug.AltTitles, allTitles) {
		// We don't want to confuse users, so only update LastTime if the generated crash
		// really relates to the existing bug.
		bug.LastTime = now
	}
	if _, err := db.Put(c, bugKey, bug); err != nil {
		return fmt.Errorf("failed to put bug: %v", err)
	}
	return nil
}

func gatherCrashTitles(req *dashapi.JobDoneReq) []string {
	ret := append([]string{}, req.CrashAltTitles...)
	if req.CrashTitle != "" {
		ret = append(ret, req.CrashTitle)
	}
	return ret
}

// resetJobs is called to indicate that, for the specified managers, all started jobs are no longer
// in progress.
func resetJobs(c context.Context, req *dashapi.JobResetReq) error {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Finished=", time.Time{}).
		Filter("IsRunning=", true).
		GetAll(c, &jobs)
	if err != nil {
		return err
	}
	managerMap := map[string]bool{}
	for _, name := range req.Managers {
		managerMap[name] = true
	}
	for idx, job := range jobs {
		if !managerMap[job.Manager] {
			continue
		}
		jobKey := keys[idx]
		tx := func(c context.Context) error {
			job = new(Job)
			if err := db.Get(c, jobKey, job); err != nil {
				return fmt.Errorf("job %v: failed to get in tx: %v", jobKey, err)
			}
			if job.IsFinished() {
				// Just in case.
				return nil
			}
			job.IsRunning = false
			if _, err := db.Put(c, jobKey, job); err != nil {
				return fmt.Errorf("job %v: failed to put: %v", jobKey, err)
			}
			return nil
		}
		if err := db.RunInTransaction(c, tx, nil); err != nil {
			return err
		}
	}
	return nil
}

// doneJob is called by syz-ci to mark completion of a job.
func doneJob(c context.Context, req *dashapi.JobDoneReq) error {
	jobID := req.ID
	jobKey, err := jobID2Key(c, req.ID)
	if err != nil {
		return err
	}
	// Datastore prohibits cross-group queries even inside XG transactions.
	// So we have to query last build for the manager before the transaction.
	job := new(Job)
	if err := db.Get(c, jobKey, job); err != nil {
		return fmt.Errorf("job %v: failed to get job: %v", jobID, err)
	}
	lastBuild, err := lastManagerBuild(c, job.Namespace, job.Manager)
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
		if isRetestReproJob(job, lastBuild) {
			err := handleRetestedRepro(c, now, job, jobKey, lastBuild, req)
			if err != nil {
				return fmt.Errorf("job %v: failed to handle retested repro, %w", jobID, err)
			}
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
			cc := email.MergeEmailLists(com.CC,
				GetEmails(com.Recipients, dashapi.To),
				GetEmails(com.Recipients, dashapi.Cc))
			job.Commits = append(job.Commits, Commit{
				Hash:       com.Hash,
				Title:      com.Title,
				Author:     com.Author,
				AuthorName: com.AuthorName,
				CC:         strings.Join(sanitizeCC(c, cc), "|"),
				Date:       com.Date,
			})
		}
		job.BuildID = req.Build.ID
		job.CrashTitle = req.CrashTitle
		job.Finished = now
		job.IsRunning = false
		job.Flags = JobFlags(req.Flags)
		if job.Type == JobBisectCause || job.Type == JobBisectFix {
			// Update bug.BisectCause/Fix status and also remember current bug reporting to send results.
			if err := updateBugBisection(c, job, jobKey, req, now); err != nil {
				return err
			}
		}
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		log.Infof(c, "DONE JOB %v: reported=%v reporting=%v", jobID, job.Reported, job.Reporting)
		return nil
	}
	return db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 30})
}

func updateBugBisection(c context.Context, job *Job, jobKey *db.Key, req *dashapi.JobDoneReq, now time.Time) error {
	bug := new(Bug)
	bugKey := jobKey.Parent()
	if err := db.Get(c, bugKey, bug); err != nil {
		return fmt.Errorf("job %v: failed to get bug: %v", req.ID, err)
	}
	result := BisectYes
	if len(req.Error) != 0 {
		result = BisectError
	} else if len(req.Commits) > 1 {
		result = BisectInconclusive
	} else if len(req.Commits) == 0 {
		result = BisectHorizont
	} else if job.isUnreliableBisect() {
		result = BisectUnreliable
	}
	if job.Type == JobBisectCause {
		bug.BisectCause = result
	} else {
		bug.BisectFix = result
	}
	// If the crash still occurs on HEAD, update the bug's LastTime so that it will be
	// retried after 30 days.
	if job.Type == JobBisectFix && req.Error == nil && len(req.Commits) == 0 && len(req.CrashLog) != 0 {
		bug.BisectFix = BisectNot
		bug.LastTime = now
	}
	if _, err := db.Put(c, bugKey, bug); err != nil {
		return fmt.Errorf("failed to put bug: %v", err)
	}
	_, bugReporting, _, _, _ := currentReporting(c, bug)
	// The bug is either already closed or not yet reported in the current reporting,
	// either way we don't need to report it. If it wasn't reported, it will be reported
	// with the bisection results.
	if bugReporting == nil || bugReporting.Reported.IsZero() ||
		// Don't report errors for non-user-initiated jobs.
		job.Error != 0 ||
		// Don't report unreliable/wrong bisections.
		job.isUnreliableBisect() {
		job.Reported = true
	} else {
		job.Reporting = bugReporting.Name
	}
	return nil
}

// TODO: this is temporal for gradual bisection rollout.
// Notify only about successful cause bisection for now.
// For now we only enable this in tests.
var notifyAboutUnsuccessfulBisections = false

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
			if job.User != "" {
				log.Criticalf(c, "no reporting for job %v", extJobID(keys[i]))
			}
			// In some cases (e.g. repro retesting), it's ok not to have a reporting.
			continue
		}
		reporting := config.Namespaces[job.Namespace].ReportingByName(job.Reporting)
		if reporting.Config.Type() != typ {
			continue
		}
		if job.Type == JobBisectCause && !notifyAboutUnsuccessfulBisections && len(job.Commits) != 1 {
			continue
		}
		// If BisectFix results in a crash on HEAD, no notification is sent out.
		if job.Type == JobBisectFix && len(job.Commits) != 1 {
			continue
		}
		// If the bug is already known to be fixed, invalid or duplicate, do not report the bisection results.
		if job.Type == JobBisectCause || job.Type == JobBisectFix {
			bug := new(Bug)
			bugKey := keys[i].Parent()
			if err := db.Get(c, bugKey, bug); err != nil {
				return nil, fmt.Errorf("job %v: failed to get bug: %v", extJobID(keys[i]), err)
			}
			if len(bug.Commits) != 0 || bug.Status != BugStatusOpen {
				jobReported(c, extJobID(keys[i]))
				continue
			}
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
	kernelRepo := kernelRepoInfo(build)
	rep := &dashapi.BugReport{
		Type:            job.Type.toDashapiReportType(),
		Config:          reportingConfig,
		JobID:           extJobID(jobKey),
		ExtID:           job.ExtID,
		CC:              append(job.CC, kernelRepo.CC.Always...),
		Log:             crashLog,
		LogLink:         externalLink(c, textCrashLog, job.CrashLog),
		Report:          report,
		ReportLink:      externalLink(c, textCrashReport, job.CrashReport),
		ReproCLink:      externalLink(c, textReproC, crash.ReproC),
		ReproSyzLink:    externalLink(c, textReproSyz, crash.ReproSyz),
		ReproOpts:       crash.ReproOpts,
		MachineInfoLink: externalLink(c, textMachineInfo, crash.MachineInfo),
		CrashTitle:      job.CrashTitle,
		Error:           jobError,
		ErrorLink:       externalLink(c, textError, job.Error),
		PatchLink:       externalLink(c, textPatch, job.Patch),
	}
	if job.Type == JobBisectCause || job.Type == JobBisectFix {
		rep.Maintainers = append(crash.Maintainers, kernelRepo.CC.Maintainers...)
		rep.ExtID = bugReporting.ExtID
		if bugReporting.CC != "" {
			rep.CC = strings.Split(bugReporting.CC, "|")
		}
		var emails []string
		switch job.Type {
		case JobBisectCause:
			rep.BisectCause, emails = bisectFromJob(c, job)
		case JobBisectFix:
			rep.BisectFix, emails = bisectFromJob(c, job)
		}
		rep.Maintainers = append(rep.Maintainers, emails...)
	}
	if mgr := bug.managerConfig(); mgr != nil {
		rep.CC = append(rep.CC, mgr.CC.Always...)
		if job.Type == JobBisectCause || job.Type == JobBisectFix {
			rep.Maintainers = append(rep.Maintainers, mgr.CC.Maintainers...)
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

func bisectFromJob(c context.Context, job *Job) (*dashapi.BisectResult, []string) {
	bisect := &dashapi.BisectResult{
		LogLink:         externalLink(c, textLog, job.Log),
		CrashLogLink:    externalLink(c, textCrashLog, job.CrashLog),
		CrashReportLink: externalLink(c, textCrashReport, job.CrashReport),
		Fix:             job.Type == JobBisectFix,
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
	var newEmails []string
	if len(bisect.Commits) == 1 {
		bisect.Commit = bisect.Commits[0]
		bisect.Commits = nil
		com := job.Commits[0]
		newEmails = []string{com.Author}
		newEmails = append(newEmails, strings.Split(com.CC, "|")...)
	}
	return bisect, newEmails
}

func jobReported(c context.Context, jobID string) error {
	jobKey, err := jobID2Key(c, jobID)
	if err != nil {
		return err
	}
	now := timeNow(c)
	tx := func(c context.Context) error {
		job := new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get job: %v", jobID, err)
		}
		job.Reported = true
		// Auto-mark the bug as fixed by the result of fix bisection,
		// if the setting is enabled for the namespace.
		if job.Type == JobBisectFix &&
			config.Namespaces[job.Namespace].FixBisectionAutoClose &&
			len(job.Commits) == 1 {
			bug := new(Bug)
			bugKey := jobKey.Parent()
			if err := db.Get(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to get bug: %v", err)
			}
			if bug.Status == BugStatusOpen && len(bug.Commits) == 0 {
				bug.updateCommits([]string{job.Commits[0].Title}, now)
				if _, err := db.Put(c, bugKey, bug); err != nil {
					return fmt.Errorf("failed to put bug: %v", err)
				}
			}
		}
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		return nil
	}
	return db.RunInTransaction(c, tx, nil)
}

func handleExternalTestRequest(c context.Context, req *dashapi.TestPatchRequest) error {
	bug, bugKey, err := findBugByReportingID(c, req.BugID)
	if err != nil {
		return fmt.Errorf("failed to find the bug: %w", err)
	}
	bugReporting, _ := bugReportingByID(bug, req.BugID)
	if bugReporting == nil {
		return fmt.Errorf("failed to find the bug reporting object")
	}
	crash, crashKey, err := findCrashForBug(c, bug)
	if err != nil {
		return fmt.Errorf("failed to find a crash: %v", err)
	}
	if req.Branch == "" && req.Repo == "" {
		build, err := loadBuild(c, bug.Namespace, crash.BuildID)
		if err != nil {
			return fmt.Errorf("failed to find the bug reporting object: %w", err)
		}
		req.Branch = build.KernelBranch
		req.Repo = build.KernelRepo
	} else if req.Branch == "" || req.Repo == "" {
		return fmt.Errorf("branch and repo should be either both set or both empty")
	}
	now := timeNow(c)
	return addTestJob(c, &testJobArgs{
		crash:    crash,
		crashKey: crashKey,
		testReqArgs: testReqArgs{
			bug:          bug,
			bugKey:       bugKey,
			bugReporting: bugReporting,
			repo:         req.Repo,
			branch:       req.Branch,
			user:         req.User,
			link:         req.Link,
			patch:        req.Patch,
		},
	}, now)
}

type jobSorter struct {
	jobs []*Job
	keys []*db.Key
}

func (sorter *jobSorter) Len() int { return len(sorter.jobs) }
func (sorter *jobSorter) Less(i, j int) bool {
	// Give priority to user-initiated jobs to reduce the perceived processing time.
	return sorter.jobs[i].User != "" && sorter.jobs[j].User == ""
}
func (sorter *jobSorter) Swap(i, j int) {
	sorter.jobs[i], sorter.jobs[j] = sorter.jobs[j], sorter.jobs[i]
	sorter.keys[i], sorter.keys[j] = sorter.keys[j], sorter.keys[i]
}

func loadPendingJob(c context.Context, managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Finished=", time.Time{}).
		Filter("IsRunning=", false).
		Order("Attempts").
		Order("Created").
		GetAll(c, &jobs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query jobs: %v", err)
	}
	sort.Stable(&jobSorter{jobs: jobs, keys: keys})
	for i, job := range jobs {
		switch job.Type {
		case JobTestPatch:
			if !managers[job.Manager].TestPatches {
				continue
			}
		case JobBisectCause, JobBisectFix:
			if job.Type == JobBisectCause && !managers[job.Manager].BisectCause ||
				job.Type == JobBisectFix && !managers[job.Manager].BisectFix {
				continue
			}
			// Don't retry bisection jobs too often.
			// This allows to have several syz-ci's doing bisection
			// and protects from bisection job crashing syz-ci.
			const bisectRepeat = 3 * 24 * time.Hour
			if timeSince(c, job.Created) < bisectRepeat ||
				timeSince(c, job.LastStarted) < bisectRepeat {
				continue
			}
		default:
			return nil, nil, fmt.Errorf("bad job type %v", job.Type)
		}
		return job, keys[i], nil
	}
	return nil, nil, nil
}

// activeManager determines the manager currently responsible for all bugs found by
// the specified manager.
func activeManager(manager, ns string) (string, *ConfigManager) {
	nsConfig := config.Namespaces[ns]
	if mgr, ok := nsConfig.Managers[manager]; ok {
		if mgr.Decommissioned {
			newMgr := nsConfig.Managers[mgr.DelegatedTo]
			return mgr.DelegatedTo, &newMgr
		}
		return manager, &mgr
	}
	// This manager is not mentioned in the configuration, therefore it was
	// definitely not decommissioned.
	return manager, nil
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
