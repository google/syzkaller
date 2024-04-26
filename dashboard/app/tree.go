// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

// Given information on how commits flow from one kernel source tree to another, assign
// bugs labels of two kinds:
// a) LabelIntroduced -- reproducer does not work in any other kernel tree, FROM which commits flow.
// b) LabelReached -- reproducer does not work in any other kernel tree, TO which commits flow.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/sync/errgroup"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// generateTreeOriginJobs generates new jobs for bug origin tree determination.
func generateTreeOriginJobs(cGlobal context.Context, bugKey *db.Key,
	managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, error) {
	var job *Job
	var jobKey *db.Key
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %w", err)
		}
		ctx := &bugTreeContext{
			c:       c,
			cGlobal: cGlobal,
			bug:     bug,
			bugKey:  bug.key(c),
		}
		ret := ctx.pollBugTreeJobs(managers)
		switch ret.(type) {
		case pollResultError:
			return ret.(error)
		case pollResultWait:
			newTime, ok := ret.(time.Time)
			if ok && newTime.After(bug.TreeTests.NextPoll) {
				bug.TreeTests.NextPoll = newTime
			}
		}
		bug.TreeTests.NeedPoll = false
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		job, jobKey = ctx.job, ctx.jobKey
		return nil
	}
	if err := db.RunInTransaction(cGlobal, tx,
		&db.TransactionOptions{XG: true, Attempts: 10}); err != nil {
		return nil, nil, err
	}
	return job, jobKey, nil
}

// treeOriginJobDone is supposed to be called when tree origin job is done.
// It keeps the cached info in Bug up to date and assigns bug tree origin labels.
func treeOriginJobDone(cGlobal context.Context, jobKey *db.Key, job *Job) error {
	bugKey := jobKey.Parent()
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %w", err)
		}
		ctx := &bugTreeContext{
			c:         c,
			cGlobal:   cGlobal,
			bug:       bug,
			bugKey:    bug.key(c),
			noNewJobs: true,
		}
		ret := ctx.pollBugTreeJobs(
			map[string]dashapi.ManagerJobs{job.Manager: {TestPatches: true}},
		)
		switch ret.(type) {
		case pollResultError:
			return ret.(error)
		case pollResultPending:
			bug.TreeTests.NextPoll = time.Time{}
			bug.TreeTests.NeedPoll = true
		}
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %w", err)
		}
		return nil
	}
	return db.RunInTransaction(cGlobal, tx, &db.TransactionOptions{XG: true, Attempts: 10})
}

type pollTreeJobResult interface{}

// pollResultPending is returned when we wait some job to finish.
type pollResultPending struct{}

// pollResultWait is returned when we know the next time the process could be repeated.
type pollResultWait time.Time

// pollResultSkip means that there are no poll jobs we could run at the moment.
// It's impossible to say when it changes, so it's better not to repeat polling soon.
type pollResultSkip struct{}

type pollResultError error

type pollResultDone struct {
	Crashed  bool
	Finished time.Time
}

type bugTreeContext struct {
	c context.Context
	// Datastore puts limits on how often a single entity can be accessed by transactions.
	// And we actually don't always need a consistent view of the DB, we just want to query
	// a single entity. So, when possible, let's make queries outside of a transaction.
	cGlobal   context.Context
	crash     *Crash
	crashKey  *db.Key
	bugKey    *db.Key
	bug       *Bug
	build     *Build
	repoNode  *repoNode
	noNewJobs bool

	// If any jobs were created, here'll be one of them.
	job    *Job
	jobKey *db.Key
}

func (ctx *bugTreeContext) pollBugTreeJobs(managers map[string]dashapi.ManagerJobs) pollTreeJobResult {
	// Determine the crash we'd stick to.
	err := ctx.loadCrashInfo()
	if err != nil {
		log.Errorf(ctx.c, "bug %q: failed to load crash info: %s", ctx.bug.displayTitle(), err)
		return pollResultError(err)
	}
	if ctx.crash == nil {
		// There are no crashes we could further work with.
		// TODO: consider looking at the recent repro retest results.
		log.Infof(ctx.c, "bug %q: no suitable crash", ctx.bug.displayTitle())
		return pollResultSkip{}
	}
	if ctx.repoNode == nil {
		// We have no information about the tree on which the bug happened.
		log.Errorf(ctx.c, "bug %q: no information about the tree", ctx.bug.displayTitle())
		return pollResultSkip{}
	}
	if !managers[ctx.crash.Manager].TestPatches {
		return pollResultSkip{}
	}
	if len(ctx.bug.TreeTests.List) > 0 && ctx.crashKey.IntID() != ctx.bug.TreeTests.List[0].CrashID {
		// Clean up old job records, they are no longer relevant.
		ctx.bug.TreeTests.List = nil
	}
	for i := range ctx.bug.TreeTests.List {
		err := ctx.bug.TreeTests.List[i].applyPending(ctx.c)
		if err != nil {
			return pollResultError(err)
		}
	}
	return ctx.groupResults([]pollTreeJobResult{
		ctx.setOriginLabels(),
		ctx.missingBackports(),
	})
}

func (ctx *bugTreeContext) setOriginLabels() pollTreeJobResult {
	if !ctx.labelsCanBeSet() || ctx.bug.HasUserLabel(OriginLabel) {
		return pollResultSkip{}
	}
	ctx.bug.UnsetLabels(OriginLabel)

	var results []pollTreeJobResult
	perNode := map[*repoNode]pollTreeJobResult{}
	for node, merge := range ctx.repoNode.allReachable() {
		var result pollTreeJobResult
		if merge {
			// Merge base gives a much better result quality, so use it whenever possible.
			result = ctx.runRepro(node.repo, wantFirstAny{}, runOnMergeBase{
				Repo:   ctx.build.KernelRepo,
				Branch: ctx.build.KernelBranch,
			})
		} else {
			result = ctx.runRepro(node.repo, wantFirstAny{}, runOnHEAD{})
		}
		perNode[node] = result
		results = append(results, result)
	}
	result := ctx.groupResults(results)
	if _, ok := result.(pollResultPending); ok {
		// At least wait until all started jobs have finished (successfully or not).
		return result
	}
	lastDone := ctx.lastDone(results)
	if lastDone.IsZero() {
		// Demand that at least one of the finished jobs has finished successfully.
		return pollResultSkip{}
	}
	// Since we have a repro for it, it definitely crashed at some point.
	perNode[ctx.repoNode] = pollResultDone{Crashed: true}
	allLabels := append(ctx.selectRepoLabels(true, perNode), ctx.selectRepoLabels(false, perNode)...)
	for _, label := range allLabels {
		if label == ctx.repoNode.repo.LabelIntroduced || label == ctx.repoNode.repo.LabelReached {
			// It looks like our reproducer does not work on other trees.
			// Just in case verify that it still works on the original one.
			result := ctx.runRepro(ctx.repoNode.repo, wantNewAny(lastDone), runOnHEAD{})
			resultDone, ok := result.(pollResultDone)
			if !ok {
				return result
			}
			if !resultDone.Crashed {
				// Unfortunately the repro no longer works. Don't assign labels.
				return pollResultSkip{}
			}
		}
	}
	var labels []BugLabel
	for _, label := range allLabels {
		labels = append(labels, BugLabel{Label: OriginLabel, Value: label})
	}
	ctx.bug.SetLabels(makeLabelSet(ctx.c, ctx.bug.Namespace), labels)
	return pollResultSkip{}
}

// selectRepoLabels attributes bugs to trees depending on the patch testing results.
func (ctx *bugTreeContext) selectRepoLabels(in bool, results map[*repoNode]pollTreeJobResult) []string {
	crashed := map[*repoNode]bool{}
	for node, result := range results {
		done, ok := result.(pollResultDone)
		if ok {
			crashed[node] = done.Crashed
		}
	}
	for node := range crashed {
		if !crashed[node] {
			continue
		}
		// (1) The in = true case:
		// If, for a tree X, there's a tree Y from which commits flow to X and the reproducer crashed
		// on Y, X cannot be among bug origin trees.
		// (1) The in = false case:
		// If, for a tree X, there's a tree Y to which commits flow to X and the reproducer crashed
		// on Y, X cannot be the last tree to which the bug has spread.
		for otherNode := range node.reachable(!in) {
			crashed[otherNode] = false
		}
	}
	ret := []string{}
	for node, set := range crashed {
		if !set {
			continue
		}
		if in && node.repo.LabelIntroduced != "" {
			ret = append(ret, node.repo.LabelIntroduced)
		} else if !in && node.repo.LabelReached != "" {
			ret = append(ret, node.repo.LabelReached)
		}
	}
	return ret
}

// Test if there's any sense in testing other trees.
// For example, if we hit a bug on a mainline, there's no sense to test linux-next to check
// if it's a linux-next bug.
func (ctx *bugTreeContext) labelsCanBeSet() bool {
	for node := range ctx.repoNode.reachable(true) {
		if node.repo.LabelIntroduced != "" {
			return true
		}
	}
	for node := range ctx.repoNode.reachable(false) {
		if node.repo.LabelReached != "" {
			return true
		}
	}
	return ctx.repoNode.repo.LabelIntroduced != "" ||
		ctx.repoNode.repo.LabelReached != ""
}

func (ctx *bugTreeContext) missingBackports() pollTreeJobResult {
	if !ctx.repoNode.repo.DetectMissingBackports || ctx.bug.HasUserLabel(MissingBackportLabel) {
		return pollResultSkip{}
	}
	var okDate time.Time
	results := []pollTreeJobResult{}
	for node, merge := range ctx.repoNode.reachable(true) {
		resultOK := ctx.runRepro(node.repo, wantFirstOK{}, runOnHEAD{})
		doneOK, ok := resultOK.(pollResultDone)
		if !ok {
			results = append(results, resultOK)
			continue
		}
		var resultCrash pollTreeJobResult
		if merge {
			resultCrash = ctx.runRepro(node.repo, wantFirstAny{}, runOnMergeBase{
				Repo:   ctx.build.KernelRepo,
				Branch: ctx.build.KernelBranch,
			})
		} else {
			// We already know that the reproducer doesn't crash the tree.
			// There'd be no sense to call runRepro in the hope of getting a crash,
			// so let's just look into the past tree testing results.
			resultCrash, _ = ctx.bug.findResult(ctx.c, node.repo, wantFirstCrash{}, runOnAny{})
		}
		doneCrash, ok := resultCrash.(pollResultDone)
		if !ok {
			results = append(results, resultCrash)
			continue
		} else if merge && doneCrash.Crashed || doneOK.Finished.After(doneCrash.Finished) {
			// That's what we want: earlier it crashed and then stopped.
			okDate = doneOK.Finished
			break
		}
	}
	if okDate.IsZero() {
		return ctx.groupResults(results)
	}
	// We are about to assign the "missing backport" label.
	// To reduce the number of backports, just in case run once more on HEAD.
	// The bug fix could have already reached the repository.
	result := ctx.runRepro(ctx.repoNode.repo, wantNewAny(okDate), runOnHEAD{})
	resultDone, ok := result.(pollResultDone)
	if !ok {
		return result
	}
	ctx.bug.UnsetLabels(MissingBackportLabel)
	if resultDone.Crashed {
		ctx.bug.SetLabels(makeLabelSet(ctx.c, ctx.bug.Namespace), []BugLabel{
			{Label: MissingBackportLabel},
		})
	}
	return pollResultSkip{}
}

func (ctx *bugTreeContext) lastDone(results []pollTreeJobResult) time.Time {
	var maxTime time.Time
	for _, item := range results {
		done, ok := item.(pollResultDone)
		if !ok {
			continue
		}
		if done.Finished.After(maxTime) {
			maxTime = done.Finished
		}
	}
	return maxTime
}

func (ctx *bugTreeContext) groupResults(results []pollTreeJobResult) pollTreeJobResult {
	var minWait time.Time
	for _, result := range results {
		switch v := result.(type) {
		case pollResultPending, pollResultError:
			// Wait for the job result to continue.
			return result
		case pollResultWait:
			t := time.Time(v)
			if minWait.IsZero() || minWait.After(t) {
				minWait = t
			}
		}
	}
	if !minWait.IsZero() {
		return pollResultWait(minWait)
	}
	return pollResultSkip{}
}

type expectedResult interface{}

// resultFreshness subtypes.
type wantFirstOK struct{}
type wantFirstCrash struct{}
type wantFirstAny struct{}
type wantNewAny time.Time

type runReproOn interface{}

// runReproOn subtypes.
type runOnAny struct{} // attempts to find any result, if unsuccessful, runs on HEAD
type runOnHEAD struct{}
type runOnMergeBase struct {
	Repo   string
	Branch string
}

func (ctx *bugTreeContext) runRepro(repo KernelRepo, result expectedResult, runOn runReproOn) pollTreeJobResult {
	ret := ctx.doRunRepro(repo, result, runOn)
	log.Infof(ctx.c, "runRepro on %s, %T, %T: %#v", repo.Alias, result, runOn, ret)
	return ret
}

func (ctx *bugTreeContext) doRunRepro(repo KernelRepo, result expectedResult, runOn runReproOn) pollTreeJobResult {
	existingResult, _ := ctx.bug.findResult(ctx.c, repo, result, runOn)
	if _, ok := existingResult.(pollResultSkip); !ok {
		return existingResult
	}
	// Okay, nothing suitable was found. We need to set up a new job.
	if ctx.noNewJobs {
		return pollResultPending{}
	}
	// First check if there's existing BugTreeTest object.
	if _, ok := runOn.(runOnAny); ok {
		runOn = runOnHEAD{}
	}
	candidates := ctx.bug.matchingTreeTests(repo, runOn)
	var bugTreeTest *BugTreeTest
	if len(candidates) > 0 {
		bugTreeTest = &ctx.bug.TreeTests.List[candidates[0]]
	} else {
		item := BugTreeTest{
			CrashID: ctx.crashKey.IntID(),
			Repo:    repo.URL,
			Branch:  repo.Branch,
		}
		if v, ok := runOn.(runOnMergeBase); ok {
			item.MergeBaseRepo = v.Repo
			item.MergeBaseBranch = v.Branch
		}
		ctx.bug.TreeTests.List = append(ctx.bug.TreeTests.List, item)
		bugTreeTest = &ctx.bug.TreeTests.List[len(ctx.bug.TreeTests.List)-1]
	}

	if bugTreeTest.Error != "" {
		const errorRetryTime = 24 * time.Hour * 14
		result := ctx.ensureRepeatPeriod(bugTreeTest.Error, errorRetryTime)
		if _, ok := result.(pollResultSkip); !ok {
			return result
		}
		bugTreeTest.Error = ""
	}
	if bugTreeTest.Last != "" {
		const fixRetryTime = 24 * time.Hour * 45
		result := ctx.ensureRepeatPeriod(bugTreeTest.Last, fixRetryTime)
		if _, ok := result.(pollResultSkip); !ok {
			return result
		}
	}
	var err error
	ctx.job, ctx.jobKey, err = addTestJob(ctx.c, &testJobArgs{
		crash:         ctx.crash,
		crashKey:      ctx.crashKey,
		configRef:     ctx.build.KernelConfig,
		configAppend:  repo.AppendConfig,
		inTransaction: true,
		treeOrigin:    true,
		testReqArgs: testReqArgs{
			bug:             ctx.bug,
			bugKey:          ctx.bugKey,
			repo:            bugTreeTest.Repo,
			branch:          bugTreeTest.Branch,
			mergeBaseRepo:   bugTreeTest.MergeBaseRepo,
			mergeBaseBranch: bugTreeTest.MergeBaseBranch,
		},
	})
	if err != nil {
		return pollResultError(err)
	}
	bugTreeTest.Pending = ctx.jobKey.Encode()
	return pollResultPending{}
}

func (ctx *bugTreeContext) ensureRepeatPeriod(jobKey string, period time.Duration) pollTreeJobResult {
	job, _, err := fetchJob(ctx.c, jobKey)
	if err != nil {
		return pollResultError(err)
	}
	timePassed := timeNow(ctx.c).Sub(job.Finished)
	if timePassed < period {
		return pollResultWait(job.Finished.Add(period))
	}
	return pollResultSkip{}
}

func (bug *Bug) findResult(c context.Context,
	repo KernelRepo, result expectedResult, runOn runReproOn) (pollTreeJobResult, *Job) {
	anyPending := false
	for _, i := range bug.matchingTreeTests(repo, runOn) {
		info := &bug.TreeTests.List[i]
		anyPending = anyPending || info.Pending != ""
		key := ""
		switch result.(type) {
		case wantFirstOK:
			key = info.FirstOK
		case wantFirstCrash:
			key = info.FirstCrash
		case wantFirstAny:
			key = info.First
		case wantNewAny:
			key = info.Last
		default:
			return pollResultError(fmt.Errorf("unexpected expected result: %T", result)), nil
		}
		if key == "" {
			continue
		}
		job, _, err := fetchJob(c, key)
		if err != nil {
			return pollResultError(err), nil
		}
		if date, ok := result.(wantNewAny); ok {
			if job.Finished.Before(time.Time(date)) {
				continue
			}
		}
		return pollResultDone{
			Crashed:  job.CrashTitle != "",
			Finished: job.Finished,
		}, job
	}
	if anyPending {
		return pollResultPending{}, nil
	} else {
		return pollResultSkip{}, nil
	}
}

func (bug *Bug) matchingTreeTests(repo KernelRepo, runOn runReproOn) []int {
	ret := []int{}
	for i, item := range bug.TreeTests.List {
		if item.Repo != repo.URL {
			continue
		}
		ok := true
		switch v := runOn.(type) {
		case runOnHEAD:
			// TODO: should we check for an empty merge base here?
			ok = item.Branch == repo.Branch
		case runOnMergeBase:
			ok = item.Branch == repo.Branch &&
				item.MergeBaseRepo == v.Repo &&
				item.MergeBaseBranch == v.Branch
		}
		if ok {
			ret = append(ret, i)
		}
	}
	return ret
}

func (ctx *bugTreeContext) loadCrashInfo() error {
	// First look at the crash from previous tests.
	if len(ctx.bug.TreeTests.List) > 0 {
		crashID := ctx.bug.TreeTests.List[len(ctx.bug.TreeTests.List)-1].CrashID
		crashKey := db.NewKey(ctx.c, "Crash", "", crashID, ctx.bugKey)
		crash := new(Crash)
		// We need to also tolerate the case when the crash was just deleted.
		err := db.Get(ctx.cGlobal, crashKey, crash)
		if err != nil && err != db.ErrNoSuchEntity {
			return fmt.Errorf("failed to get crash: %w", err)
		} else if err == nil {
			ok, build, err := ctx.isCrashRelevant(crash)
			if err != nil {
				return err
			}
			if ok {
				ctx.build = build
				ctx.crash = crash
				ctx.crashKey = crashKey
			}
		}
	}

	// Query the most relevant crash with repro.
	crash, crashKey, err := findCrashForBug(ctx.cGlobal, ctx.bug)
	if err != nil {
		return err
	}
	ok, build, err := ctx.isCrashRelevant(crash)
	if err != nil {
		return err
	} else if ok && (ctx.crash == nil || crash.ReportLen > ctx.crash.ReportLen) {
		// Update the crash only if we found a better one.
		ctx.build = build
		ctx.crash = crash
		ctx.crashKey = crashKey
	}
	// Load the rest of the data.
	if ctx.crash != nil {
		var err error
		ns := ctx.bug.Namespace
		repoGraph, err := makeRepoGraph(getNsConfig(ctx.c, ns).Repos)
		if err != nil {
			return err
		}
		ctx.repoNode = repoGraph.nodeByRepo(ctx.build.KernelRepo, ctx.build.KernelBranch)
	}
	return nil
}

func (ctx *bugTreeContext) isCrashRelevant(crash *Crash) (bool, *Build, error) {
	if crash.ReproIsRevoked {
		// No sense in running the reproducer.
		return false, nil, nil
	} else if crash.ReproC == 0 && crash.ReproSyz == 0 {
		// Let's wait for the repro.
		return false, nil, nil
	}
	newManager, _ := activeManager(ctx.cGlobal, crash.Manager, ctx.bug.Namespace)
	if newManager != crash.Manager {
		// The manager was deprecated since the crash.
		// Let's just ignore such bugs for now.
		return false, nil, nil
	}
	build, err := loadBuild(ctx.cGlobal, ctx.bug.Namespace, crash.BuildID)
	if err != nil {
		return false, nil, err
	}
	mgrBuild, err := lastManagerBuild(ctx.cGlobal, build.Namespace, newManager)
	if err != nil {
		return false, build, err
	}
	// It does happen that we sometimes update the tested tree.
	// It's not frequent at all, but it will make all results very confusing.
	return build.KernelRepo == mgrBuild.KernelRepo &&
		build.KernelBranch == mgrBuild.KernelBranch, build, nil
}

func (test *BugTreeTest) applyPending(c context.Context) error {
	if test.Pending == "" {
		return nil
	}
	job, _, err := fetchJob(c, test.Pending)
	if err != nil {
		return err
	}
	if job.Finished.IsZero() {
		// Not yet ready.
		return nil
	}
	pendingKey := test.Pending
	test.Pending = ""
	if job.Error != 0 {
		test.Error = pendingKey
		return nil
	}
	test.Last = pendingKey
	if test.First == "" {
		test.First = pendingKey
	}
	if test.FirstOK == "" && job.CrashTitle == "" {
		test.FirstOK = pendingKey
	} else if test.FirstCrash == "" && job.CrashTitle != "" {
		test.FirstCrash = pendingKey
	}
	return nil
}

// treeTestJobs fetches relevant tree testing results.
func treeTestJobs(c context.Context, bug *Bug) ([]*dashapi.JobInfo, error) {
	g, _ := errgroup.WithContext(context.Background())
	jobIDs := make(chan string)

	var ret []*dashapi.JobInfo
	var mu sync.Mutex

	// The underlying code makes a number of queries, so let's do it in parallel to speed up processing.
	const threads = 3
	for i := 0; i < threads; i++ {
		g.Go(func() error {
			for id := range jobIDs {
				job, jobKey, err := fetchJob(c, id)
				if err != nil {
					return err
				}
				build, err := loadBuild(c, job.Namespace, job.BuildID)
				if err != nil {
					return err
				}
				crashKey := db.NewKey(c, "Crash", "", job.CrashID, bug.key(c))
				crash := new(Crash)
				if err := db.Get(c, crashKey, crash); err != nil {
					return fmt.Errorf("failed to get crash: %w", err)
				}
				info := makeJobInfo(c, job, jobKey, bug, build, crash)
				mu.Lock()
				ret = append(ret, info)
				mu.Unlock()
			}
			return nil
		})
	}
	for _, info := range bug.TreeTests.List {
		if info.FirstOK != "" {
			jobIDs <- info.FirstOK
		}
		if info.FirstCrash != "" {
			jobIDs <- info.FirstCrash
		}
		if info.Error != "" {
			jobIDs <- info.Error
		}
	}
	// Wait until we have all information.
	close(jobIDs)
	err := g.Wait()
	if err != nil {
		return nil, err
	}
	// Sort structures to keep output consistent.
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].KernelAlias != ret[j].KernelAlias {
			return ret[i].KernelAlias < ret[j].KernelAlias
		}
		return ret[i].Finished.Before(ret[j].Finished)
	})
	return ret, nil
}

// Create a cross-tree bisection job (if needed).
// Returns:
// a) Job object and its key -- in case of success.
// b) Whether the lookup was expensive (it can help optimize crossTreeBisection calls).
func crossTreeBisection(c context.Context, bug *Bug,
	managers map[string]dashapi.ManagerJobs) (*Job, *db.Key, bool, error) {
	repoGraph, err := makeRepoGraph(getNsConfig(c, bug.Namespace).Repos)
	if err != nil {
		return nil, nil, false, err
	}
	bugJobs := &lazyJobList{
		c:       c,
		bug:     bug,
		jobType: JobBisectFix,
	}
	var job *Job
	var jobKey *db.Key
	expensive := false
	err = repoGraph.forEachEdge(func(from, to *repoNode, info KernelRepoLink) error {
		if jobKey != nil {
			return nil
		}
		if !info.BisectFixes {
			return nil
		}
		expensive = true
		log.Infof(c, "%s: considering cross-tree bisection %s/%s",
			bug.displayTitle(), from.repo.Alias, to.repo.Alias)
		_, crashJob := bug.findResult(c, to.repo, wantNewAny{}, runOnHEAD{})
		if crashJob == nil {
			// No patch testing was performed yet.
			return nil
		}
		if crashJob.CrashTitle == "" {
			// The bug is already fixed on the target tree.
			return nil
		}
		crashBuild, err := loadBuild(c, bug.Namespace, crashJob.BuildID)
		if err != nil {
			return err
		}
		manager, _ := activeManager(c, crashJob.Manager, crashJob.Namespace)
		if !managers[manager].BisectFix {
			return nil
		}
		_, successJob := bug.findResult(c, from.repo, wantNewAny{}, runOnHEAD{})
		if successJob == nil {
			// The jobs is not done yet.
			return nil
		}
		if successJob.CrashTitle != "" {
			// The kernel tree is still crashed by the repro.
			return nil
		}
		newJob := &Job{
			Type:            JobBisectFix,
			Created:         timeNow(c),
			Namespace:       bug.Namespace,
			Manager:         crashJob.Manager,
			BisectFrom:      crashBuild.KernelCommit,
			KernelRepo:      from.repo.URL,
			KernelBranch:    from.repo.Branch,
			MergeBaseRepo:   to.repo.URL,
			MergeBaseBranch: to.repo.Branch,
			BugTitle:        bug.displayTitle(),
			CrashID:         crashJob.CrashID,
		}
		// It's expected that crossTreeBisection is not concurrently called with the same
		// manager list.
		prevJob, err := bugJobs.lastMatch(newJob)
		if err != nil {
			return err
		}
		const repeatPeriod = time.Hour * 24 * 30
		if prevJob != nil && (prevJob.Error == 0 ||
			prevJob.Finished.After(timeNow(c).Add(-repeatPeriod))) {
			// The job is already pending or failed recently. Skip.
			return nil
		}
		job = newJob
		jobKey, err = saveJob(c, newJob, bug.key(c))
		return err
	})
	return job, jobKey, expensive, err
}

type lazyJobList struct {
	c       context.Context
	bug     *Bug
	jobType JobType
	jobs    *bugJobs
}

func (list *lazyJobList) lastMatch(job *Job) (*Job, error) {
	if list.jobs == nil {
		var err error
		list.jobs, err = queryBugJobs(list.c, list.bug, list.jobType)
		if err != nil {
			return nil, err
		}
	}
	var best *Job
	for _, item := range list.jobs.all() {
		otherJob := item.job
		same := otherJob.Manager == job.Manager &&
			otherJob.KernelRepo == job.KernelRepo &&
			otherJob.KernelBranch == job.KernelBranch &&
			otherJob.CrashID == job.CrashID &&
			otherJob.MergeBaseRepo == job.MergeBaseRepo &&
			otherJob.MergeBaseBranch == job.MergeBaseBranch
		if !same {
			continue
		}
		if best == nil || best.Created.Before(otherJob.Created) {
			best = otherJob
		}
	}
	return best, nil
}

func doneCrossTreeBisection(c context.Context, jobKey *db.Key, job *Job) error {
	if job.Type != JobBisectFix || job.MergeBaseRepo == "" {
		// Not a cross tree bisection.
		return nil
	}
	if job.Error != 0 || job.isUnreliableBisect() || len(job.Commits) != 1 {
		// The result is not interesting.
		return nil
	}
	return updateSingleBug(c, jobKey.Parent(), func(bug *Bug) error {
		bug.FixCandidateJob = jobKey.Encode()
		return nil
	})
}

type repoNode struct {
	repo  KernelRepo
	edges []repoEdge
}

type repoEdge struct {
	in    bool
	info  KernelRepoLink
	other *repoNode
}

type repoGraph struct {
	nodes map[string]*repoNode
}

func makeRepoGraph(repos []KernelRepo) (*repoGraph, error) {
	g := &repoGraph{
		nodes: map[string]*repoNode{},
	}
	for _, repo := range repos {
		if repo.Alias == "" {
			return nil, fmt.Errorf("one of the repos has an empty alias")
		}
		g.nodes[repo.Alias] = &repoNode{repo: repo}
	}
	for _, repo := range repos {
		for _, link := range repo.CommitInflow {
			if g.nodes[link.Alias] == nil {
				return nil, fmt.Errorf("no repo with alias %q", link.Alias)
			}
			g.nodes[repo.Alias].addEdge(true, link, g.nodes[link.Alias])
			g.nodes[link.Alias].addEdge(false, link, g.nodes[repo.Alias])
		}
	}
	for alias, node := range g.nodes {
		reachable := node.reachable(true)
		if _, ok := reachable[node]; ok {
			return nil, fmt.Errorf("%q lies on a cycle", alias)
		}
	}
	return g, nil
}

func (g *repoGraph) nodeByRepo(url, branch string) *repoNode {
	for _, node := range g.nodes {
		if node.repo.URL == url && node.repo.Branch == branch {
			return node
		}
	}
	return nil
}

func (g *repoGraph) nodeByAlias(alias string) *repoNode {
	for _, node := range g.nodes {
		if node.repo.Alias == alias {
			return node
		}
	}
	return nil
}

func (g *repoGraph) forEachEdge(cb func(from, to *repoNode, info KernelRepoLink) error) error {
	for _, node := range g.nodes {
		for _, e := range node.edges {
			if !e.in {
				continue
			}
			err := cb(e.other, node, e.info)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// reachable returns a map *repoNode -> bool (whether commits are merged).
func (n *repoNode) reachable(in bool) map[*repoNode]bool {
	ret := map[*repoNode]bool{}
	// First collect nodes only reachable via merge=true links.
	n.reachableMerged(in, true, ret)
	n.reachableMerged(in, false, ret)
	return ret
}

func (n *repoNode) reachableMerged(in, onlyMerge bool, ret map[*repoNode]bool) {
	var dfs func(*repoNode, bool)
	dfs = func(node *repoNode, merge bool) {
		for _, edge := range node.edges {
			if edge.in != in || onlyMerge && !edge.info.Merge {
				continue
			}
			if _, ok := ret[edge.other]; ok {
				continue
			}
			ret[edge.other] = merge && edge.info.Merge
			dfs(edge.other, merge && edge.info.Merge)
		}
	}
	dfs(n, true)
}

func (n *repoNode) allReachable() map[*repoNode]bool {
	ret := n.reachable(true)
	for node, merge := range n.reachable(false) {
		ret[node] = merge
	}
	return ret
}

func (n *repoNode) addEdge(in bool, info KernelRepoLink, other *repoNode) {
	n.edges = append(n.edges, repoEdge{
		in:    in,
		info:  info,
		other: other,
	})
}
