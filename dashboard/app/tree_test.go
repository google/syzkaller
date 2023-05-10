// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	db "google.golang.org/appengine/v2/datastore"
)

func TestTreeOriginDownstream(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, downstreamUpstreamRepos)
	ctx.uploadBug(`https://downstream.repo/repo`, `master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `downstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:      `lts`,
			mergeAlias: `downstream`,
			results:    []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels(`origin:downstream`)
	// It should habe been enough to run jobs just once.
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
	c.expectEQ(ctx.entries[2].jobsDone, 1)
	// Test that we can render the bug page.
	_, err := c.GET(ctx.bugLink())
	c.expectEQ(err, nil)
}

func TestTreeOriginLts(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, downstreamUpstreamRepos)
	ctx.uploadBug(`https://downstream.repo/repo`, `master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `downstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:      `lts`,
			mergeAlias: `downstream`,
			results:    []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels(`origin:lts`)
	c.expectEQ(ctx.entries[0].jobsDone, 0)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
	c.expectEQ(ctx.entries[2].jobsDone, 1)
}

func TestTreeOriginErrors(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Make sure testing works fine despite patch testing errors.
	ctx := setUpTreeTest(c, downstreamUpstreamRepos)
	ctx.uploadBug(`https://downstream.repo/repo`, `master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
		{
			alias:      `lts`,
			mergeAlias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestError},
				{fromDay: 16, result: treeTestCrash},
			},
		},
		{
			alias: `upstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestError},
				{fromDay: 31, result: treeTestCrash},
			},
		},
	}
	ctx.jobTestDays = []int{1, 16, 31}
	ctx.moveToDay(1)
	ctx.ensureLabels() // Not enough information yet.
	// Lts got unbroken.
	ctx.moveToDay(16)
	ctx.ensureLabels(`origin:lts`) // We don't know any better so far.
	// Upstream got unbroken.
	ctx.moveToDay(31)
	ctx.ensureLabels(`origin:upstream`)
	c.expectEQ(ctx.entries[0].jobsDone, 0)
	c.expectEQ(ctx.entries[1].jobsDone, 2)
	c.expectEQ(ctx.entries[2].jobsDone, 3)
}

var downstreamUpstreamRepos = []KernelRepo{
	{
		URL:             `https://downstream.repo/repo`,
		Branch:          `master`,
		Alias:           `downstream`,
		LabelIntroduced: `downstream`,
		CommitInflow: []KernelRepoLink{
			{
				Alias: `upstream`,
			},
			{
				Alias: `lts`,
				Merge: true,
			},
		},
	},
	{
		URL:             `https://lts.repo/repo`,
		Branch:          `lts-master`,
		Alias:           `lts`,
		LabelIntroduced: `lts`,
		CommitInflow: []KernelRepoLink{
			{
				Alias: `upstream`,
				Merge: false,
			},
		},
	},
	{
		URL:             `https://upstream.repo/repo`,
		Branch:          `upstream-master`,
		Alias:           `upstream`,
		LabelIntroduced: `upstream`,
	},
}

func TestOriginTreeNoMergeLts(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, ltsUpstreamRepos)
	ctx.uploadBug(`https://lts.repo/repo`, `lts-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `lts`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels(`origin:lts-only`)
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

func TestOriginTreeNoMergeNoLabel(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, ltsUpstreamRepos)
	ctx.uploadBug(`https://lts.repo/repo`, `lts-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `lts`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels()
	// It should habe been enough to run jobs just once.
	c.expectEQ(ctx.entries[0].jobsDone, 0)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

func TestTreeOriginRepoChanged(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, ltsUpstreamRepos)

	// First do tests from one repository.
	ctx.uploadBug(`https://lts.repo/repo`, `lts-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `lts`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.jobTestDays = []int{10, 20, 25, 30, 62}
	ctx.moveToDay(10)
	ctx.ensureLabels(`origin:lts-only`)
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)

	// Now update the repository.
	ctx.updateRepos([]KernelRepo{
		{
			URL:               `https://new-lts.repo/repo`,
			Branch:            `lts-master`,
			Alias:             `lts`,
			LabelIntroduced:   `lts-only`,
			ReportingPriority: 9,
			CommitInflow: []KernelRepoLink{
				{
					Alias: `upstream`,
					Merge: false,
				},
			},
		},
		{
			URL:    `https://upstream.repo/repo`,
			Branch: `upstream-master`,
			Alias:  `upstream`,
		},
	})
	ctx.entries = []treeTestEntry{
		{
			alias: `lts`,
			results: []treeTestEntryPeriod{
				{fromDay: 30, result: treeTestError},
				{fromDay: 60, result: treeTestCrash},
			},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.moveToDay(20)
	ctx.ensureLabels(`origin:lts-only`) // No new builds -- nothing we can do.

	// Upload a new manager build.
	build := ctx.uploadBuild(`https://new-lts.repo/repo`, `lts-master`)
	ctx.moveToDay(25)
	ctx.ensureLabels(`origin:lts-only`) // Still nothing we can do, no crashes so far.

	// Now upload a new crash.
	ctx.uploadBuildCrash(build, dashapi.ReproLevelC)
	ctx.moveToDay(30)
	ctx.ensureLabels() // We are no longer sure about tags.

	// After the new tree starts to build again, we can calculate the results again.
	ctx.moveToDay(62)
	ctx.ensureLabels(`origin:lts-only`) // We are no longer sure about tags.
	c.expectEQ(ctx.entries[0].jobsDone, 2)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

var ltsUpstreamRepos = []KernelRepo{
	{
		URL:             `https://lts.repo/repo`,
		Branch:          `lts-master`,
		Alias:           `lts`,
		LabelIntroduced: `lts-only`,
		CommitInflow: []KernelRepoLink{
			{
				Alias: `upstream`,
				Merge: false,
			},
		},
	},
	{
		URL:    `https://upstream.repo/repo`,
		Branch: `upstream-master`,
		Alias:  `upstream`,
	},
}

func TestOriginNoNextTree(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, upstreamNextRepos)
	ctx.uploadBug(`https://upstream.repo/repo`, `upstream-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels()
}

func TestOriginNoNextFixed(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, upstreamNextRepos)
	ctx.uploadBug(`https://next.repo/repo`, `next-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `next`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels()
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

func TestOriginNoNext(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, upstreamNextRepos)
	ctx.uploadBug(`https://next.repo/repo`, `next-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `next`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels()
	c.expectEQ(ctx.entries[0].jobsDone, 0)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

func TestOriginNext(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, upstreamNextRepos)
	ctx.uploadBug(`https://next.repo/repo`, `next-master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias:   `next`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestCrash}},
		},
		{
			alias:   `upstream`,
			results: []treeTestEntryPeriod{{fromDay: 0, result: treeTestOK}},
		},
	}
	ctx.jobTestDays = []int{10}
	ctx.moveToDay(10)
	ctx.ensureLabels(`origin:next`)
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

var upstreamNextRepos = []KernelRepo{
	{
		URL:    `https://upstream.repo/repo`,
		Branch: `upstream-master`,
		Alias:  `upstream`,
		CommitInflow: []KernelRepoLink{
			{
				Alias: `next`,
				Merge: false,
			},
		},
	},
	{
		URL:          `https://next.repo/repo`,
		Branch:       `next-master`,
		Alias:        `next`,
		LabelReached: `next`,
	},
}

func TestMissingLtsBackport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, downstreamUpstreamBackports)
	ctx.uploadBug(`https://downstream.repo/repo`, `master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
		{
			alias:      `lts`,
			mergeAlias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
		{
			alias: `lts`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
				{fromDay: 46, result: treeTestOK},
			},
		},
		{
			alias: `upstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
	}
	ctx.jobTestDays = []int{0, 46}
	ctx.moveToDay(46)
	ctx.ensureLabels(`missing-backport`)
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
}

func TestMissingUpstreamBackport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, downstreamUpstreamBackports)
	ctx.uploadBug(`https://downstream.repo/repo`, `master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
		{
			alias: `lts`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
		{
			alias: `upstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
				{fromDay: 31, result: treeTestOK},
			},
		},
	}
	ctx.jobTestDays = []int{0, 46}
	ctx.moveToDay(46)
	ctx.ensureLabels(`missing-backport`)
	c.expectEQ(ctx.entries[0].jobsDone, 1)
	c.expectEQ(ctx.entries[1].jobsDone, 2)
	c.expectEQ(ctx.entries[1].jobsDone, 2)
}

func TestNotMissingBackport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	ctx := setUpTreeTest(c, downstreamUpstreamBackports)
	ctx.uploadBug(`https://downstream.repo/repo`, `master`, dashapi.ReproLevelC)
	ctx.entries = []treeTestEntry{
		{
			alias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
		{
			alias:      `lts`,
			mergeAlias: `downstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestOK},
			},
		},
		{
			alias: `lts`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestOK},
			},
		},
		{
			alias: `upstream`,
			results: []treeTestEntryPeriod{
				{fromDay: 0, result: treeTestCrash},
			},
		},
	}
	ctx.jobTestDays = []int{0, 46}
	ctx.moveToDay(46)
	ctx.ensureLabels()
	c.expectEQ(ctx.entries[0].jobsDone, 0)
	c.expectEQ(ctx.entries[1].jobsDone, 1)
	c.expectEQ(ctx.entries[2].jobsDone, 1)
	c.expectEQ(ctx.entries[3].jobsDone, 2)
}

var downstreamUpstreamBackports = []KernelRepo{
	{
		URL:    `https://downstream.repo/repo`,
		Branch: `master`,
		Alias:  `downstream`,
		CommitInflow: []KernelRepoLink{
			{
				Alias: `lts`,
				Merge: true,
			},
			{
				Alias: `upstream`,
			},
		},
		DetectMissingBackports: true,
	},
	{
		URL:    `https://lts.repo/repo`,
		Branch: `lts-master`,
		Alias:  `lts`,
		CommitInflow: []KernelRepoLink{
			{
				Alias: `upstream`,
				Merge: false,
			},
		},
	},
	{
		URL:    `https://upstream.repo/repo`,
		Branch: `upstream-master`,
		Alias:  `upstream`,
	},
}

func setUpTreeTest(ctx *Ctx, repos []KernelRepo) *treeTestCtx {
	ret := &treeTestCtx{
		ctx:     ctx,
		client:  ctx.makeClient(clientPublic, keyPublic, true),
		manager: "test-manager",
	}
	ret.updateRepos(repos)
	return ret
}

type treeTestCtx struct {
	ctx         *Ctx
	client      *apiClient
	bug         *Bug
	start       time.Time
	entries     []treeTestEntry
	perAlias    map[string]KernelRepo
	jobTestDays []int
	manager     string
}

func (ctx *treeTestCtx) now() time.Time {
	// Yep, that's a bit too much repetition.
	return timeNow(ctx.ctx.ctx)
}

func (ctx *treeTestCtx) updateRepos(repos []KernelRepo) {
	checkKernelRepos("access-public", config.Namespaces["access-public"], repos)
	ctx.perAlias = map[string]KernelRepo{}
	for _, repo := range repos {
		ctx.perAlias[repo.Alias] = repo
	}
	ctx.ctx.setKernelRepos(repos)
}

func (ctx *treeTestCtx) uploadBuild(repo, branch string) *dashapi.Build {
	build := testBuild(1)
	build.ID = fmt.Sprintf("%d", ctx.now().Unix())
	build.Manager = ctx.manager
	build.KernelRepo = repo
	build.KernelBranch = branch
	build.KernelCommit = build.ID
	ctx.client.UploadBuild(build)
	return build
}

func (ctx *treeTestCtx) uploadBuildCrash(build *dashapi.Build, lvl dashapi.ReproLevel) {
	crash := testCrash(build, 1)
	if lvl > dashapi.ReproLevelNone {
		crash.ReproSyz = []byte("getpid()")
	}
	if lvl == dashapi.ReproLevelC {
		crash.ReproC = []byte("getpid()")
	}
	ctx.client.ReportCrash(crash)
	if ctx.bug == nil || ctx.bug.ReproLevel < lvl {
		rep := ctx.client.pollBug()
		if ctx.bug == nil {
			bug, _, err := findBugByReportingID(ctx.ctx.ctx, rep.ID)
			ctx.ctx.expectOK(err)
			ctx.bug = bug
		}
	}
}

func (ctx *treeTestCtx) uploadBug(repo, branch string, lvl dashapi.ReproLevel) {
	build := ctx.uploadBuild(repo, branch)
	ctx.uploadBuildCrash(build, lvl)
}

func (ctx *treeTestCtx) moveToDay(tillDay int) {
	ctx.ctx.t.Helper()
	if ctx.start.IsZero() {
		ctx.start = ctx.now()
	}
	for _, seqDay := range ctx.jobTestDays {
		if seqDay > tillDay {
			break
		}
		now := ctx.now()
		day := ctx.start.Add(time.Hour * 24 * time.Duration(seqDay))
		if day.Before(now) || ctx.start != ctx.now() && day.Equal(now) {
			continue
		}
		ctx.ctx.advanceTime(day.Sub(now))
		ctx.ctx.t.Logf("executing jobs on day %d", seqDay)
		// Execute jobs until they exist.
		for {
			pollResp := ctx.client.pollSpecificJobs(ctx.manager, dashapi.ManagerJobs{
				TestPatches: true,
			})
			if pollResp.ID == "" {
				break
			}
			ctx.ctx.advanceTime(time.Minute)
			ctx.doJob(pollResp, seqDay)
		}
	}
}

func (ctx *treeTestCtx) doJob(resp *dashapi.JobPollResp, day int) {
	respValues := []string{
		resp.KernelRepo,
		resp.KernelBranch,
		resp.MergeBaseRepo,
		resp.MergeBaseBranch,
	}
	sort.Strings(respValues)
	var found *treeTestEntry
	for i, entry := range ctx.entries {
		entryValues := []string{
			ctx.perAlias[entry.alias].URL,
			ctx.perAlias[entry.alias].Branch,
		}
		if entry.mergeAlias != "" {
			entryValues = append(entryValues,
				ctx.perAlias[entry.mergeAlias].URL,
				ctx.perAlias[entry.mergeAlias].Branch)
		} else {
			entryValues = append(entryValues, "", "")
		}
		sort.Strings(entryValues)
		if reflect.DeepEqual(respValues, entryValues) {
			found = &ctx.entries[i]
			break
		}
	}
	if found == nil {
		ctx.ctx.t.Fatalf("unknown job request: %#v", resp)
	}
	build := testBuild(1)
	build.KernelRepo = resp.KernelRepo
	build.KernelBranch = resp.KernelBranch
	build.KernelCommit = fmt.Sprintf("%d", ctx.now().Unix())
	// Figure out what should the result be.
	result := treeTestOK
	for _, item := range found.results {
		if day >= item.fromDay {
			result = item.result
		}
	}
	jobDoneReq := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Build: *build,
	}
	switch result {
	case treeTestOK:
	case treeTestCrash:
		jobDoneReq.CrashTitle = "crash title"
		jobDoneReq.CrashLog = []byte("test crash log")
		jobDoneReq.CrashReport = []byte("test crash report")
	case treeTestError:
		jobDoneReq.Error = []byte("failed to apply patch")
	}
	found.jobsDone++
	ctx.ctx.expectOK(ctx.client.JobDone(jobDoneReq))
}

func (ctx *treeTestCtx) ensureLabels(labels ...string) {
	ctx.ctx.t.Helper()
	if ctx.bug == nil {
		ctx.ctx.t.Fatalf("no bug has been created so far")
	}
	bug := new(Bug)
	ctx.ctx.expectOK(db.Get(ctx.ctx.ctx, ctx.bug.key(ctx.ctx.ctx), bug))
	ctx.bug = bug

	var bugLabels []string
	for _, item := range bug.Labels {
		bugLabels = append(bugLabels, item.String())
	}
	sort.Strings(bugLabels)
	sort.Strings(labels)
	ctx.ctx.expectEQ(labels, bugLabels)
}

func (ctx *treeTestCtx) bugLink() string {
	return fmt.Sprintf("/bug?id=%v", ctx.bug.key(ctx.ctx.ctx).StringID())
}

type treeTestEntry struct {
	alias      string
	mergeAlias string
	results    []treeTestEntryPeriod
	jobsDone   int
}

type treeTestResult string

const (
	treeTestCrash treeTestResult = "crash"
	treeTestOK    treeTestResult = "ok"
	treeTestError treeTestResult = "error"
)

type treeTestEntryPeriod struct {
	fromDay int
	result  treeTestResult
}

func TestRepoGraph(t *testing.T) {
	g, err := makeRepoGraph(downstreamUpstreamRepos)
	if err != nil {
		t.Fatal(err)
	}

	downstream := g.nodeByAlias(`downstream`)
	lts := g.nodeByAlias(`lts`)
	upstream := g.nodeByAlias(`upstream`)

	// Test the downstream node.
	if diff := cmp.Diff(map[*repoNode]bool{
		lts:      true,
		upstream: false,
	}, downstream.reachable(true)); diff != "" {
		t.Fatal(diff)
	}
	if diff := cmp.Diff(map[*repoNode]bool{}, downstream.reachable(false)); diff != "" {
		t.Fatal(diff)
	}

	// Test the lts node.
	if diff := cmp.Diff(map[*repoNode]bool{
		upstream: false,
	}, lts.reachable(true)); diff != "" {
		t.Fatal(diff)
	}
	if diff := cmp.Diff(map[*repoNode]bool{
		downstream: true,
	}, lts.reachable(false)); diff != "" {
		t.Fatal(diff)
	}

	// Test the upstream node.
	if diff := cmp.Diff(map[*repoNode]bool{}, upstream.reachable(true)); diff != "" {
		t.Fatal(diff)
	}
	if diff := cmp.Diff(map[*repoNode]bool{
		downstream: false,
		lts:        false,
	}, upstream.reachable(false)); diff != "" {
		t.Fatal(diff)
	}
}

func TestRepoGraphMergeFirst(t *testing.T) {
	// Test whether we prioritize merge links.
	g, err := makeRepoGraph([]KernelRepo{
		{
			URL:    `https://downstream.repo/repo`,
			Branch: `master`,
			Alias:  `downstream`,
			CommitInflow: []KernelRepoLink{
				{
					Alias: `upstream`,
					Merge: false,
				},
				{
					Alias: `lts`,
					Merge: true,
				},
			},
		},
		{
			URL:    `https://lts.repo/repo`,
			Branch: `lts-master`,
			Alias:  `lts`,
			CommitInflow: []KernelRepoLink{
				{
					Alias: `upstream`,
					Merge: true,
				},
			},
		},
		{
			URL:    `https://upstream.repo/repo`,
			Branch: `upstream-master`,
			Alias:  `upstream`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	downstream := g.nodeByAlias(`downstream`)
	lts := g.nodeByAlias(`lts`)
	upstream := g.nodeByAlias(`upstream`)

	// Test the downstream node.
	if diff := cmp.Diff(map[*repoNode]bool{
		lts:      true,
		upstream: true,
	}, downstream.reachable(true)); diff != "" {
		t.Fatal(diff)
	}
	if diff := cmp.Diff(map[*repoNode]bool{}, downstream.reachable(false)); diff != "" {
		t.Fatal(diff)
	}
}
