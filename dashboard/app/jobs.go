// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/user"
)

type testReqArgs struct {
	bug             *Bug
	bugKey          *db.Key
	bugReporting    *BugReporting
	user            string
	extID           string
	link            string
	patch           []byte
	repo            string
	branch          string
	jobCC           []string
	mergeBaseRepo   string
	mergeBaseBranch string
}

// handleTestRequest added new job to db.
// Returns nil if job added successfully.
// If the arguments are invalid, the error is of type *BadTestRequest.
// If the request was denied, the error is of type *TestRequestDenied.
// All other errors correspond to internal processing problems.
func handleTestRequest(c context.Context, args *testReqArgs) error {
	log.Infof(c, "test request: bug=%s user=%q extID=%q patch=%v, repo=%q branch=%q",
		args.bug.Title, args.user, args.extID, len(args.patch), args.repo, args.branch)
	for _, blocked := range getConfig(c).EmailBlocklist {
		if args.user == blocked {
			return &TestRequestDeniedError{
				fmt.Sprintf("test request from blocked user: %v", args.user),
			}
		}
	}
	crash, crashKey, err := findCrashForBug(c, args.bug)
	if err != nil {
		return fmt.Errorf("failed to find a crash: %w", err)
	}
	_, _, err = addTestJob(c, &testJobArgs{
		testReqArgs: *args,
		crash:       crash, crashKey: crashKey,
	})
	if err != nil {
		return err
	}
	// Update bug CC and last activity time.
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, args.bugKey, bug); err != nil {
			return err
		}
		bug.LastActivity = timeNow(c)
		bugReporting := args.bugReporting
		bugReporting = bugReportingByName(bug, bugReporting.Name)
		bugCC := strings.Split(bugReporting.CC, "|")
		merged := email.MergeEmailLists(bugCC, args.jobCC)
		bugReporting.CC = strings.Join(merged, "|")
		if _, err := db.Put(c, args.bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
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
	crash         *Crash
	crashKey      *db.Key
	configRef     int64
	configAppend  string
	treeOrigin    bool
	inTransaction bool
	testReqArgs
}

func addTestJob(c context.Context, args *testJobArgs) (*Job, *db.Key, error) {
	now := timeNow(c)
	if err := patchTestJobArgs(c, args); err != nil {
		return nil, nil, err
	}
	if reason := checkTestJob(args); reason != "" {
		return nil, nil, &BadTestRequestError{reason}
	}
	manager, mgrConfig := activeManager(c, args.crash.Manager, args.bug.Namespace)
	if mgrConfig != nil && mgrConfig.RestrictedTestingRepo != "" &&
		args.repo != mgrConfig.RestrictedTestingRepo {
		return nil, nil, &BadTestRequestError{mgrConfig.RestrictedTestingReason}
	}
	patchID, err := putText(c, args.bug.Namespace, textPatch, args.patch)
	if err != nil {
		return nil, nil, err
	}
	configRef := args.configRef
	if args.configAppend != "" {
		kernelConfig, _, err := getText(c, textKernelConfig, configRef)
		if err != nil {
			return nil, nil, err
		}
		configRef, err = putText(c, args.bug.Namespace, textKernelConfig,
			append(kernelConfig, []byte(args.configAppend)...))
		if err != nil {
			return nil, nil, err
		}
	}
	reportingName := ""
	if args.bugReporting != nil {
		reportingName = args.bugReporting.Name
	}
	job := &Job{
		Type:            JobTestPatch,
		Created:         now,
		User:            args.user,
		CC:              args.jobCC,
		Reporting:       reportingName,
		ExtID:           args.extID,
		Link:            args.link,
		Namespace:       args.bug.Namespace,
		Manager:         manager,
		BugTitle:        args.bug.displayTitle(),
		CrashID:         args.crashKey.IntID(),
		KernelRepo:      args.repo,
		KernelBranch:    args.branch,
		MergeBaseRepo:   args.mergeBaseRepo,
		MergeBaseBranch: args.mergeBaseBranch,
		Patch:           patchID,
		KernelConfig:    configRef,
		TreeOrigin:      args.treeOrigin,
	}

	var jobKey *db.Key
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
				return fmt.Errorf("failed to query jobs: jobs=%v err=%w", len(jobs), err)
			}
		}
		if len(jobs) != 0 {
			// The job is already present, update link.
			deletePatch = true
			job, jobKey = jobs[0], keys[0]
			if job.Link != "" || args.link == "" {
				return nil
			}
			job.Link = args.link
			if jobKey, err = db.Put(c, jobKey, job); err != nil {
				return fmt.Errorf("failed to put job: %w", err)
			}
			return nil
		}
		jobKey, err = saveJob(c, job, args.bugKey)
		return err
	}
	if args.inTransaction {
		err = tx(c)
	} else {
		err = db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 30})
	}
	if patchID != 0 && (deletePatch || err != nil) {
		if err := db.Delete(c, db.NewKey(c, textPatch, "", patchID, nil)); err != nil {
			log.Errorf(c, "failed to delete patch for dup job: %v", err)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("job tx failed: %w", err)
	}
	return job, jobKey, nil
}

func saveJob(c context.Context, job *Job, bugKey *db.Key) (*db.Key, error) {
	jobKey := db.NewIncompleteKey(c, "Job", bugKey)
	var err error
	if jobKey, err = db.Put(c, jobKey, job); err != nil {
		return nil, fmt.Errorf("failed to put job: %w", err)
	}
	return jobKey, addCrashReference(c, job.CrashID, bugKey,
		CrashReference{CrashReferenceJob, extJobID(jobKey), timeNow(c)})
}

func patchTestJobArgs(c context.Context, args *testJobArgs) error {
	if args.branch == "" && args.repo == "" {
		// If no arguments were passed, we need to auto-guess them.
		build, err := loadBuild(c, args.bug.Namespace, args.crash.BuildID)
		if err != nil {
			return fmt.Errorf("failed to find the bug reporting object: %w", err)
		}
		args.branch = build.KernelBranch
		args.repo = build.KernelRepo
	}
	// Let trees be also identified by their alias names.
	for _, repo := range getNsConfig(c, args.bug.Namespace).Repos {
		if repo.Alias != "" && repo.Alias == args.repo {
			args.repo = repo.URL
			break
		}
	}
	return nil
}

func crashNeedsRepro(title string) bool {
	return !strings.Contains(title, "boot error:") &&
		!strings.Contains(title, "test error:") &&
		!strings.Contains(title, "build error")
}

func checkTestJob(args *testJobArgs) string {
	crash, bug := args.crash, args.bug
	needRepro := crashNeedsRepro(crash.Title)
	switch {
	case needRepro && crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it."
	case !vcs.CheckRepoAddress(args.repo):
		return fmt.Sprintf("%q does not look like a valid git repo address.", args.repo)
	case !vcs.CheckBranch(args.branch) && !vcs.CheckCommitHash(args.branch):
		return fmt.Sprintf("%q does not look like a valid git branch or commit.", args.branch)
	case bug.Status == BugStatusFixed:
		return "This bug is already marked as fixed. No point in testing."
	case bug.Status == BugStatusInvalid:
		return "This bug is already marked as invalid. No point in testing."
	// TODO(dvyukov): for BugStatusDup check status of the canonical bug.
	case args.bugReporting != nil && !args.bugReporting.Closed.IsZero():
		return "This bug is already upstreamed. Please test upstream."
	}
	return ""
}

// Mark bisection job as invalid and, if restart=true, reset bisection state of the related bug.
func invalidateBisection(c context.Context, jobKey *db.Key, restart bool) error {
	u := user.Current(c)
	tx := func(c context.Context) error {
		job := new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to get job: %w", err)
		}

		if job.Type != JobBisectCause && job.Type != JobBisectFix {
			return fmt.Errorf("can only invalidate bisection jobs")
		}

		// Update the job.
		job.InvalidatedBy = u.Email
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %w", err)
		}

		if restart {
			// Update the bug.
			bug := new(Bug)
			bugKey := jobKey.Parent()
			if err := db.Get(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to get bug: %w", err)
			}
			if job.Type == JobBisectCause {
				bug.BisectCause = BisectNot
			} else if job.IsCrossTree() {
				bug.FixCandidateJob = ""
			} else if job.Type == JobBisectFix {
				bug.BisectFix = BisectNot
			}
			if _, err := db.Put(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to put bug: %w", err)
			}
		}
		return nil
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 10}); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	return nil
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
	// Each syz-ci polls dashboard every 10 seconds. At the times when there are no
	// matching jobs, it just doesn't make much sense to execute heavy algorithms that
	// try to generate them too often.
	// Note that it won't affect user-created jobs as they are not auto-generated.
	if err := throttleJobGeneration(c, managers); err != nil {
		return nil, nil, err
	}
	var handlers []func(context.Context, map[string]dashapi.ManagerJobs) (*Job, *db.Key, error)
	// Let's alternate handlers, so that neither patch tests nor bisections overrun one another.
	if timeNow(c).UnixMilli()%2 == 0 {
		handlers = append(handlers, jobFromBugSample, createBisectJob)
	} else {
		handlers = append(handlers, createBisectJob, jobFromBugSample)
	}
	for _, f := range handlers {
		job, jobKey, err := f(c, managers)
		if job != nil || err != nil {
			return job, jobKey, err
		}
	}
	return nil, nil, nil
}

const jobGenerationPeriod = time.Minute

func throttleJobGeneration(c context.Context, managers map[string]dashapi.ManagerJobs) error {
	drop := map[string]struct{}{}
	for name := range managers {
		// Technically the key is Namespace+Manager, so it's not guaranteed
		// that there'll be only one.
		// But for throttling purposes any single entity will do.
		// Also note that we do the query outside of the transaction as
		// datastore prohibits non-ancestor queries.
		keys, err := db.NewQuery("Manager").
			Filter("Name=", name).
			Limit(1).
			KeysOnly().
			GetAll(c, nil)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			drop[name] = struct{}{}
			continue
		}
		tx := func(c context.Context) error {
			manager := new(Manager)
			if err := db.Get(c, keys[0], manager); err != nil {
				return fmt.Errorf("failed to get %v: %w", keys[0], err)
			}
			if timeNow(c).Sub(manager.LastGeneratedJob) < jobGenerationPeriod {
				drop[name] = struct{}{}
				return nil
			}
			manager.LastGeneratedJob = timeNow(c)
			if _, err = db.Put(c, keys[0], manager); err != nil {
				return fmt.Errorf("failed to put Manager: %w", err)
			}
			return nil
		}
		if err := db.RunInTransaction(c, tx, &db.TransactionOptions{}); err != nil {
			return fmt.Errorf("failed to throttle: %w", err)
		}
	}
	for name := range drop {
		delete(managers, name)
	}
	return nil
}

// Randomly sample a subset of open bugs with reproducers and try to generate
// a job for them.
// Suitable for cases when we must look deeper than just into Bug fields.
// Sampling allows to evenly spread the load over time.
func jobFromBugSample(c context.Context, managers map[string]dashapi.ManagerJobs) (*Job,
	*db.Key, error) {
	var managersList []string
	for name, jobs := range managers {
		if !jobs.Any() {
			continue
		}
		managersList = append(managersList, name)
		managersList = append(managersList, decommissionedInto(c, name)...)
	}
	managersList = unique(managersList)

	var allBugs []*Bug
	var allBugKeys []*db.Key
	for _, mgrName := range managersList {
		bugs, bugKeys, err := loadAllBugs(c, func(query *db.Query) *db.Query {
			return query.Filter("Status=", BugStatusOpen).
				Filter("HappenedOn=", mgrName).
				Filter("HeadReproLevel>", 0)
		})
		if err != nil {
			return nil, nil, err
		}
		bugs, bugKeys = filterBugs(bugs, bugKeys, func(bug *Bug) bool {
			if len(bug.Commits) > 0 {
				// Let's save resources -- there's no point in doing analysis for bugs
				// for which we were already given fixing commits.
				return false
			}
			if getNsConfig(c, bug.Namespace).Decommissioned {
				return false
			}
			return true
		})
		allBugs = append(allBugs, bugs...)
		allBugKeys = append(allBugKeys, bugKeys...)
	}
	r := rand.New(rand.NewSource(timeNow(c).UnixNano()))
	// Bugs often happen on multiple instances, so let's filter out duplicates.
	allBugs, allBugKeys = uniqueBugs(c, allBugs, allBugKeys)
	r.Shuffle(len(allBugs), func(i, j int) {
		allBugs[i], allBugs[j] = allBugs[j], allBugs[i]
		allBugKeys[i], allBugKeys[j] = allBugKeys[j], allBugKeys[i]
	})
	// Also shuffle the creator functions.
	funcs := []func(context.Context, []*Bug, []*db.Key,
		map[string]dashapi.ManagerJobs) (*Job, *db.Key, error){
		createPatchRetestingJobs,
		createTreeTestJobs,
		createTreeBisectionJobs,
	}
	r.Shuffle(len(funcs), func(i, j int) { funcs[i], funcs[j] = funcs[j], funcs[i] })
	for _, f := range funcs {
		job, jobKey, err := f(c, allBugs, allBugKeys, managers)
		if job != nil || err != nil {
			return job, jobKey, err
		}
	}
	return nil, nil, nil
}

func createTreeBisectionJobs(c context.Context, bugs []*Bug, bugKeys []*db.Key,
	managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	log.Infof(c, "createTreeBisectionJobs is called for %d bugs", len(bugs))
	const maxProcess = 5
	processed := 0
	for _, bug := range bugs {
		if bug.FixCandidateJob != "" {
			continue
		}
		if processed >= maxProcess {
			break
		}
		any := false
		for _, mgr := range bug.HappenedOn {
			newMgr, _ := activeManager(c, mgr, bug.Namespace)
			any = any || managers[newMgr].BisectFix
		}
		if !any {
			continue
		}
		job, key, expensive, err := crossTreeBisection(c, bug, managers)
		if job != nil || err != nil {
			return job, key, err
		}
		if expensive {
			// Only count expensive lookups.
			// If we didn't have to query anything from the DB, it's not a problem to
			// examine more bugs.
			processed++
		}
	}
	return nil, nil, nil
}

func createTreeTestJobs(c context.Context, bugs []*Bug, bugKeys []*db.Key,
	managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	takeBugs := 5
	prio, next := []int{}, []int{}
	for i, bug := range bugs {
		if !getNsConfig(c, bug.Namespace).FindBugOriginTrees {
			continue
		}
		if timeNow(c).Before(bug.TreeTests.NextPoll) {
			continue
		}
		if bug.TreeTests.NeedPoll {
			prio = append(prio, i)
		} else {
			next = append(next, i)
		}
		if len(prio) >= takeBugs {
			prio = prio[:takeBugs]
			break
		} else if len(prio)+len(next) > takeBugs {
			next = next[:takeBugs-len(prio)]
		}
	}
	for _, i := range append(prio, next...) {
		job, jobKey, err := generateTreeOriginJobs(c, bugKeys[i], managers)
		if err != nil {
			return nil, nil, fmt.Errorf("bug %v job creation failed: %w", bugKeys[i], err)
		} else if job != nil {
			return job, jobKey, nil
		}
	}
	return nil, nil, nil
}

func createPatchRetestingJobs(c context.Context, bugs []*Bug, bugKeys []*db.Key,
	managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	takeBugs := 5
	for i, bug := range bugs {
		if !getNsConfig(c, bug.Namespace).RetestRepros {
			// Repro retesting is disabled for the namespace.
			continue
		}
		if getConfig(c).Obsoleting.ReproRetestPeriod == 0 ||
			timeNow(c).Sub(bug.LastTime) < getConfig(c).Obsoleting.ReproRetestStart {
			// Don't retest reproducers if crashes are still happening.
			continue
		}
		takeBugs--
		if takeBugs == 0 {
			break
		}
		job, jobKey, err := handleRetestForBug(c, bug, bugKeys[i], managers)
		if err != nil {
			return nil, nil, fmt.Errorf("bug %v repro retesting failed: %w", bugKeys[i], err)
		} else if job != nil {
			return job, jobKey, nil
		}
	}
	return nil, nil, nil
}

func decommissionedInto(c context.Context, jobMgr string) []string {
	var ret []string
	for _, nsConfig := range getConfig(c).Namespaces {
		for name, mgr := range nsConfig.Managers {
			if mgr.DelegatedTo == jobMgr {
				ret = append(ret, name)
			}
		}
	}
	return ret
}

// There are bugs with dozens of reproducer.
// Let's spread the load more evenly by limiting the number of jobs created at a time.
const maxRetestJobsAtOnce = 5

func handleRetestForBug(c context.Context, bug *Bug, bugKey *db.Key,
	managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	crashes, crashKeys, err := queryCrashesForBug(c, bugKey, maxCrashes())
	if err != nil {
		return nil, nil, err
	}
	var job *Job
	var jobKey *db.Key
	now := timeNow(c)
	jobsLeft := maxRetestJobsAtOnce
	for crashID, crash := range crashes {
		if crash.ReproSyz == 0 && crash.ReproC == 0 {
			continue
		}
		if now.Sub(crash.LastReproRetest) < getConfig(c).Obsoleting.ReproRetestPeriod {
			continue
		}
		if crash.ReproIsRevoked {
			// No sense in retesting the already revoked repro.
			continue
		}
		// We could have decommissioned the original manager since then.
		manager, _ := activeManager(c, crash.Manager, bug.Namespace)
		if manager == "" || !managers[manager].TestPatches {
			continue
		}
		if jobsLeft == 0 {
			break
		}
		jobsLeft--
		// Take the last successful build -- the build on which this crash happened
		// might contain already obsolete repro and branch values.
		build, err := lastManagerBuild(c, bug.Namespace, manager)
		if err != nil {
			return nil, nil, err
		}
		job, jobKey, err = addTestJob(c, &testJobArgs{
			crash:     crash,
			crashKey:  crashKeys[crashID],
			configRef: build.KernelConfig,
			testReqArgs: testReqArgs{
				bug:    bug,
				bugKey: bugKey,
				repo:   build.KernelRepo,
				branch: build.KernelBranch,
			},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to add job: %w", err)
		}
	}
	return job, jobKey, nil
}

func createBisectJob(c context.Context, managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	// We need both C and syz repros, but the crazy datastore query restrictions
	// do not allow to use ReproLevel>ReproLevelNone in the query. So we do 2 separate queries.
	// C repros tend to be of higher reliability so maybe it's not bad.
	job, jobKey, err := createBisectJobRepro(c, managers, ReproLevelC)
	if job != nil || err != nil {
		return job, jobKey, err
	}
	return createBisectJobRepro(c, managers, ReproLevelSyz)
}

func createBisectJobRepro(c context.Context, managers map[string]dashapi.ManagerJobs,
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
		return nil, nil, fmt.Errorf("failed to query bugs: %w", err)
	}
	for bi, bug := range bugs {
		if !shouldBisectBug(c, bug, managers, jobType) {
			continue
		}
		crash, crashKey, err := bisectCrashForBug(c, bug, keys[bi], managers, jobType)
		if err != nil {
			return nil, nil, err
		}
		if crash == nil {
			continue
		}
		return createBisectJobForBug(c, bug, crash, keys[bi], crashKey, jobType)
	}
	return nil, nil, nil
}

func shouldBisectBug(c context.Context, bug *Bug, managers map[string]bool, jobType JobType) bool {
	// We already have a fixing commit, no need to bisect.
	if len(bug.Commits) != 0 {
		return false
	}

	if getNsConfig(c, bug.Namespace).Decommissioned {
		return false
	}

	// There likely is no fix yet, as the bug recently reproduced.
	const fixJobRepeat = 24 * 30 * time.Hour
	if jobType == JobBisectFix && timeSince(c, bug.LastTime) < fixJobRepeat {
		return false
	}
	// Likely to find the same (invalid) result without admin intervention, don't try too often.
	const causeJobRepeat = 24 * 7 * time.Hour
	if jobType == JobBisectCause && timeSince(c, bug.LastCauseBisect) < causeJobRepeat {
		return false
	}

	// Ensure one of the managers the bug reproduced on is taking bisection jobs.
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
			getNsConfig(c, bug.Namespace).Managers[crash.Manager].FixBisectionDisabled {
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
			return fmt.Errorf("failed to get bug %v: %w", bugKey.StringID(), err)
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
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		jobKey, err = saveJob(c, job, bugKey)
		return err
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{
		// We're accessing two different kinds in addCrashReference.
		XG: true,
	}); err != nil {
		return nil, nil, fmt.Errorf("create bisect job tx failed: %w", err)
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
		return nil, false, fmt.Errorf("job %v: failed to get crash: %w", jobID, err)
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
			return fmt.Errorf("job %v: failed to get in tx: %w", jobID, err)
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
			return fmt.Errorf("job %v: failed to put: %w", jobID, err)
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
		ID:              jobID,
		Manager:         job.Manager,
		KernelRepo:      job.KernelRepo,
		KernelBranch:    job.KernelBranch,
		MergeBaseRepo:   job.MergeBaseRepo,
		MergeBaseBranch: job.MergeBaseBranch,
		KernelCommit:    job.BisectFrom,
		KernelConfig:    kernelConfig,
		SyzkallerCommit: build.SyzkallerCommit,
		Patch:           patch,
		ReproOpts:       crash.ReproOpts,
		ReproSyz:        reproSyz,
		ReproC:          reproC,
	}
	if resp.KernelCommit == "" {
		resp.KernelCommit = build.KernelCommit
		resp.KernelCommitTitle = build.KernelCommitTitle
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
	bug *Bug, lastBuild *Build, req *dashapi.JobDoneReq) (*Bug, error) {
	bugKey := jobKey.Parent()
	if bug == nil {
		bug = new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return nil, fmt.Errorf("failed to get bug: %v", bugKey)
		}
	}
	crashKey := db.NewKey(c, "Crash", "", job.CrashID, bugKey)
	crash := new(Crash)
	if err := db.Get(c, crashKey, crash); err != nil {
		return nil, fmt.Errorf("failed to get crash: %v", crashKey)
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
	crash.UpdateReportingPriority(c, lastBuild, bug)
	if _, err := db.Put(c, crashKey, crash); err != nil {
		return nil, fmt.Errorf("failed to put crash: %w", err)
	}
	reproCrashes, crashKeys, err := queryCrashesForBug(c, bugKey, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch crashes with repro: %w", err)
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
	return bug, nil
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
				return fmt.Errorf("job %v: failed to get in tx: %w", jobKey, err)
			}
			if job.IsFinished() {
				// Just in case.
				return nil
			}
			job.IsRunning = false
			if _, err := db.Put(c, jobKey, job); err != nil {
				return fmt.Errorf("job %v: failed to put: %w", jobKey, err)
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
// nolint: gocyclo
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
		return fmt.Errorf("job %v: failed to get job: %w", jobID, err)
	}
	lastBuild, err := lastManagerBuild(c, job.Namespace, job.Manager)
	if err != nil {
		return err
	}
	now := timeNow(c)
	tx := func(c context.Context) error {
		job = new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get job: %w", jobID, err)
		}
		if !job.Finished.IsZero() {
			return fmt.Errorf("job %v: already finished", jobID)
		}
		var bug *Bug
		if isRetestReproJob(job, lastBuild) {
			var err error
			bug, err = handleRetestedRepro(c, now, job, jobKey, bug, lastBuild, req)
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
		if job.Log, err = putText(c, ns, textLog, req.Log); err != nil {
			return err
		}
		if job.Error, err = putText(c, ns, textError, req.Error); err != nil {
			return err
		}
		if job.CrashLog, err = putText(c, ns, textCrashLog, req.CrashLog); err != nil {
			return err
		}
		if job.CrashReport, err = putText(c, ns, textCrashReport, req.CrashReport); err != nil {
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
		job.Flags = req.Flags
		if job.Type == JobBisectCause || job.Type == JobBisectFix {
			// Update bug.BisectCause/Fix status and also remember current bug reporting to send results.
			var err error
			bug, err = updateBugBisection(c, job, jobKey, req, bug, now)
			if err != nil {
				return err
			}
		}
		if jobKey, err = db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %w", err)
		}
		if bug != nil {
			if _, err := db.Put(c, jobKey.Parent(), bug); err != nil {
				return fmt.Errorf("failed to put bug: %w", err)
			}
		}
		log.Infof(c, "DONE JOB %v: reported=%v reporting=%v", jobID, job.Reported, job.Reporting)
		return nil
	}
	err = db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true, Attempts: 30})
	if err != nil {
		return err
	}
	return postJob(c, jobKey, job)
}

func postJob(c context.Context, jobKey *db.Key, job *Job) error {
	if job.TreeOrigin {
		err := treeOriginJobDone(c, jobKey, job)
		if err != nil {
			return fmt.Errorf("job %v: failed to execute tree origin handlers: %w", jobKey, err)
		}
	}
	err := doneCrossTreeBisection(c, jobKey, job)
	if err != nil {
		return fmt.Errorf("job %s: cross tree bisection handlers failed: %w", jobKey, err)
	}
	return nil
}

func updateBugBisection(c context.Context, job *Job, jobKey *db.Key, req *dashapi.JobDoneReq,
	bug *Bug, now time.Time) (*Bug, error) {
	if bug == nil {
		bug = new(Bug)
		if err := db.Get(c, jobKey.Parent(), bug); err != nil {
			return nil, fmt.Errorf("failed to get bug: %v", jobKey.Parent())
		}
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
		bug.LastCauseBisect = now
	} else {
		bug.BisectFix = result
	}
	infraError := (req.Flags & dashapi.BisectResultInfraError) == dashapi.BisectResultInfraError
	if infraError {
		log.Errorf(c, "bisection of %q failed due to infra errors", job.BugTitle)
	}
	// If the crash still occurs on HEAD, update the bug's LastTime so that it will be
	// retried after 30 days.
	if job.Type == JobBisectFix && (result != BisectError || infraError) &&
		len(req.Commits) == 0 && len(req.CrashLog) != 0 {
		bug.BisectFix = BisectNot
		bug.LastTime = now
	}
	// If the cause bisection failed due to infrastructure problems, also repeat it.
	if job.Type == JobBisectCause && infraError {
		bug.BisectCause = BisectNot
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
	return bug, nil
}

// TODO: this is temporal for gradual bisection rollout.
// Notify only about successful cause bisection for now.
// For now we only enable this in tests.
var notifyAboutUnsuccessfulBisections = false

// There's really no reason to query all our completed jobs every time.
// If we did not report a finished job within a month, let it stay unreported.
const maxReportedJobAge = time.Hour * 24 * 30

func pollCompletedJobs(c context.Context, typ string) ([]*dashapi.BugReport, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Finished>", timeNow(c).Add(-maxReportedJobAge)).
		Filter("Reported=", false).
		GetAll(c, &jobs)
	if err != nil {
		return nil, fmt.Errorf("failed to query jobs: %w", err)
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
		reporting := getNsConfig(c, job.Namespace).ReportingByName(job.Reporting)
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
				return nil, fmt.Errorf("job %v: failed to get bug: %w", extJobID(keys[i]), err)
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
		return nil, fmt.Errorf("failed to get crash: %w", err)
	}
	bug := new(Bug)
	if err := db.Get(c, bugKey, bug); err != nil {
		return nil, fmt.Errorf("failed to load job parent bug: %w", err)
	}
	bugReporting := bugReportingByName(bug, job.Reporting)
	if bugReporting == nil {
		return nil, fmt.Errorf("job bug has no reporting %q", job.Reporting)
	}
	kernelRepo := kernelRepoInfo(c, build)
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
	if mgr := bug.managerConfig(c); mgr != nil {
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
		CrossTree:       job.IsCrossTree(),
	}
	for _, com := range job.Commits {
		bisect.Commits = append(bisect.Commits, com.toDashapi())
	}
	var newEmails []string
	if len(bisect.Commits) == 1 {
		bisect.Commit = bisect.Commits[0]
		bisect.Commits = nil
		com := job.Commits[0]
		newEmails = []string{com.Author}
		newEmails = append(newEmails, strings.Split(com.CC, "|")...)
	}
	if job.BackportedCommit.Title != "" {
		bisect.Backported = job.BackportedCommit.toDashapi()
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
			return fmt.Errorf("job %v: failed to get job: %w", jobID, err)
		}
		job.Reported = true
		// Auto-mark the bug as fixed by the result of fix bisection,
		// if the setting is enabled for the namespace.
		if job.Type == JobBisectFix &&
			getNsConfig(c, job.Namespace).FixBisectionAutoClose &&
			!job.IsCrossTree() &&
			len(job.Commits) == 1 {
			bug := new(Bug)
			bugKey := jobKey.Parent()
			if err := db.Get(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to get bug: %w", err)
			}
			if bug.Status == BugStatusOpen && len(bug.Commits) == 0 {
				bug.updateCommits([]string{job.Commits[0].Title}, now)
				if _, err := db.Put(c, bugKey, bug); err != nil {
					return fmt.Errorf("failed to put bug: %w", err)
				}
			}
		}
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %w", err)
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
		return fmt.Errorf("failed to find a crash: %w", err)
	}
	_, _, err = addTestJob(c, &testJobArgs{
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
	})
	return err
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
		return nil, nil, fmt.Errorf("failed to query jobs: %w", err)
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
func activeManager(c context.Context, manager, ns string) (string, *ConfigManager) {
	nsConfig := getNsConfig(c, ns)
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

func fetchJob(c context.Context, key string) (*Job, *db.Key, error) {
	jobKey, err := db.DecodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	job := new(Job)
	if err := db.Get(c, jobKey, job); err != nil {
		return nil, nil, fmt.Errorf("failed to get job: %w", err)
	}
	return job, jobKey, nil
}

func makeJobInfo(c context.Context, job *Job, jobKey *db.Key, bug *Bug, build *Build,
	crash *Crash) *dashapi.JobInfo {
	kernelRepo, kernelCommit := job.KernelRepo, job.KernelBranch
	if build != nil {
		kernelCommit = build.KernelCommit
	}
	info := &dashapi.JobInfo{
		JobKey:           jobKey.Encode(),
		Type:             dashapi.JobType(job.Type),
		Flags:            job.Flags,
		Created:          job.Created,
		BugLink:          bugLink(jobKey.Parent().StringID()),
		ExternalLink:     job.Link,
		User:             job.User,
		Reporting:        job.Reporting,
		Namespace:        job.Namespace,
		Manager:          job.Manager,
		BugTitle:         job.BugTitle,
		KernelRepo:       job.KernelRepo,
		KernelBranch:     job.KernelBranch,
		KernelAlias:      kernelRepoInfoRaw(c, job.Namespace, job.KernelRepo, job.KernelBranch).Alias,
		KernelLink:       vcs.CommitLink(job.KernelRepo, job.KernelBranch),
		KernelCommit:     kernelCommit,
		KernelCommitLink: vcs.CommitLink(kernelRepo, kernelCommit),
		PatchLink:        textLink(textPatch, job.Patch),
		Attempts:         job.Attempts,
		Started:          job.LastStarted,
		Finished:         job.Finished,
		CrashTitle:       job.CrashTitle,
		CrashLogLink:     externalLink(c, textCrashLog, job.CrashLog),
		CrashReportLink:  externalLink(c, textCrashReport, job.CrashReport),
		LogLink:          externalLink(c, textLog, job.Log),
		ErrorLink:        externalLink(c, textError, job.Error),
		Reported:         job.Reported,
		InvalidatedBy:    job.InvalidatedBy,
		TreeOrigin:       job.TreeOrigin,
		OnMergeBase:      job.MergeBaseRepo != "",
	}
	if !job.Finished.IsZero() {
		info.Duration = job.Finished.Sub(job.LastStarted)
	}
	if job.Type == JobBisectCause || job.Type == JobBisectFix {
		// We don't report these yet (or at all), see pollCompletedJobs.
		if len(job.Commits) != 1 ||
			bug != nil && (len(bug.Commits) != 0 || bug.Status != BugStatusOpen) {
			info.Reported = true
		}
	}
	for _, com := range job.Commits {
		info.Commits = append(info.Commits, &dashapi.Commit{
			Hash:   com.Hash,
			Title:  com.Title,
			Author: fmt.Sprintf("%v <%v>", com.AuthorName, com.Author),
			CC:     strings.Split(com.CC, "|"),
			Date:   com.Date,
			Link:   vcs.CommitLink(kernelRepo, com.Hash),
		})
	}
	if len(info.Commits) == 1 {
		info.Commit = info.Commits[0]
		info.Commits = nil
	}
	if crash != nil {
		info.ReproCLink = externalLink(c, textReproC, crash.ReproC)
		info.ReproSyzLink = externalLink(c, textReproSyz, crash.ReproSyz)
	}
	return info
}

func uniqueBugs(c context.Context, inBugs []*Bug, inKeys []*db.Key) ([]*Bug, []*db.Key) {
	var bugs []*Bug
	var keys []*db.Key

	dups := map[string]bool{}
	for i, bug := range inBugs {
		hash := bug.keyHash(c)
		if dups[hash] {
			continue
		}
		dups[hash] = true
		bugs = append(bugs, bug)
		keys = append(keys, inKeys[i])
	}
	return bugs, keys
}

func relevantBackportJobs(c context.Context) (
	bugs []*Bug, jobs []*Job, jobKeys []*db.Key, err error) {
	allBugs, _, bugsErr := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("FixCandidateJob>", "").Filter("Status=", BugStatusOpen)
	})
	if bugsErr != nil {
		err = bugsErr
		return
	}
	var allJobKeys []*db.Key
	for _, bug := range allBugs {
		jobKey, decodeErr := db.DecodeKey(bug.FixCandidateJob)
		if decodeErr != nil {
			err = decodeErr
			return
		}
		allJobKeys = append(allJobKeys, jobKey)
	}
	allJobs := make([]*Job, len(allJobKeys))
	err = db.GetMulti(c, allJobKeys, allJobs)
	if err != nil {
		return
	}
	for i, job := range allJobs {
		// Some assertions just in case.
		jobKey := allJobKeys[i]
		if !job.IsCrossTree() {
			err = fmt.Errorf("job %s: expected to be cross-tree", jobKey)
			return
		}
		if len(job.Commits) != 1 || job.InvalidatedBy != "" ||
			job.BackportedCommit.Title != "" {
			continue
		}
		bugs = append(bugs, allBugs[i])
		jobs = append(jobs, job)
		jobKeys = append(jobKeys, jobKey)
	}
	return
}

func updateBackportCommits(c context.Context, ns string, commits []dashapi.Commit) error {
	if len(commits) == 0 {
		return nil
	}
	perTitle := map[string]dashapi.Commit{}
	for _, commit := range commits {
		perTitle[commit.Title] = commit
	}
	bugs, jobs, jobKeys, err := relevantBackportJobs(c)
	if err != nil {
		return fmt.Errorf("failed to query backport jobs: %w", err)
	}
	for i, job := range jobs {
		rawCommit, ok := perTitle[job.Commits[0].Title]
		if !ok {
			continue
		}
		if bugs[i].Namespace != ns {
			continue
		}
		commit := Commit{
			Hash:       rawCommit.Hash,
			Title:      rawCommit.Title,
			Author:     rawCommit.Author,
			AuthorName: rawCommit.AuthorName,
			Date:       rawCommit.Date,
		}
		err := commitBackported(c, jobKeys[i], commit)
		if err != nil {
			return fmt.Errorf("failed to update backport job: %w", err)
		}
	}
	return nil
}

func commitBackported(c context.Context, jobKey *db.Key, commit Commit) error {
	tx := func(c context.Context) error {
		job := new(Job)
		if err := db.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to get job: %w", err)
		}
		if job.BackportedCommit.Title != "" {
			// Nothing to update.
			return nil
		}
		job.BackportedCommit = commit
		job.Reported = false
		if _, err := db.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %w", err)
		}
		return nil
	}
	return db.RunInTransaction(c, tx, &db.TransactionOptions{Attempts: 5})
}

type bugJobs struct {
	list []*bugJob
}

type bugJob struct {
	bug      *Bug
	job      *Job
	key      *db.Key
	crash    *Crash
	crashKey *db.Key
	build    *Build
}

func queryBugJobs(c context.Context, bug *Bug, jobType JobType) (*bugJobs, error) {
	// Just in case.
	const limitJobs = 25
	var jobs []*Job
	jobKeys, err := db.NewQuery("Job").
		Ancestor(bug.key(c)).
		Filter("Type=", jobType).
		Order("-Finished").
		Limit(limitJobs).
		GetAll(c, &jobs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bug jobs: %w", err)
	}
	bugKey := bug.key(c)
	ret := &bugJobs{}
	for i := range jobs {
		job := jobs[i]
		var crashKey *db.Key
		if job.CrashID != 0 {
			crashKey = db.NewKey(c, "Crash", "", job.CrashID, bugKey)
		}
		ret.list = append(ret.list, &bugJob{
			bug:      bug,
			job:      job,
			key:      jobKeys[i],
			crashKey: crashKey,
		})
	}
	return ret, nil
}

func queryBestBisection(c context.Context, bug *Bug, jobType JobType) (*bugJob, error) {
	jobs, err := queryBugJobs(c, bug, jobType)
	if err != nil {
		return nil, err
	}
	return jobs.bestBisection(), nil
}

// Find the most representative bisection result.
func (b *bugJobs) bestBisection() *bugJob {
	// Let's take the most recent finished one.
	for _, j := range b.list {
		if !j.job.IsFinished() {
			continue
		}
		if j.job.InvalidatedBy != "" {
			continue
		}
		if j.job.MergeBaseRepo != "" {
			// It was a cross-tree bisection.
			continue
		}
		return j
	}
	return nil
}

// Find the most representative fix candidate bisection result.
func (b *bugJobs) bestFixCandidate() *bugJob {
	// Let's take the most recent finished one.
	for _, j := range b.list {
		if !j.job.IsFinished() {
			continue
		}
		if j.job.InvalidatedBy != "" {
			continue
		}
		if !j.job.IsCrossTree() {
			continue
		}
		return j
	}
	return nil
}

func (b *bugJobs) all() []*bugJob {
	return b.list
}

func (j *bugJob) load(c context.Context) error {
	err := j.loadCrash(c)
	if err != nil {
		return fmt.Errorf("failed to load crash: %w", err)
	}
	return j.loadBuild(c)
}

func (j *bugJob) loadCrash(c context.Context) error {
	if j.crash != nil {
		return nil
	}
	j.crash = new(Crash)
	return db.Get(c, j.crashKey, j.crash)
}

func (j *bugJob) loadBuild(c context.Context) error {
	if j.build != nil {
		return nil
	}
	err := j.loadCrash(c)
	if err != nil {
		return fmt.Errorf("failed to load crash: %w", err)
	}
	j.build, err = loadBuild(c, j.bug.Namespace, j.crash.BuildID)
	if err != nil {
		return err
	}
	return nil
}
