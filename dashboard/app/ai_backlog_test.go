// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/stretchr/testify/require"
)

func TestAIBacklogPacing(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	require.NoError(t, c.aiClient.UploadBuild(build))
	reportCrash := func(num int, title string) {
		crash := testCrashWithRepro(build, num)
		crash.Title = title
		_, err := c.aiClient.ReportCrash(crash)
		require.NoError(t, err)
		c.aiClient.pollEmailExtID()
	}
	// poll returns the workflow and the title of the bug of the job it gets, if any.
	// Each poll comes from a new agent: an agent that polls again while it has an unfinished job
	// is considered restarted, and gets its job again.
	agents := 0
	poll := func(workflows ...ai.WorkflowType) string {
		t.Helper()
		var req []dashapi.AIWorkflow
		for _, typ := range workflows {
			req = append(req, dashapi.AIWorkflow{Type: typ, Name: string(typ)})
		}
		agents++
		resp := c.pollAIJob(t, fmt.Sprintf("agent%v", agents), req...)
		if resp.ID == "" {
			return ""
		}
		return fmt.Sprintf("%v: %v", resp.Workflow, resp.Args["BugTitle"])
	}
	const oldBugs = 6
	for i := range oldBugs {
		reportCrash(i, fmt.Sprintf("KASAN: slab-use-after-free in old%v", i))
	}
	// The bugs were not seen for 30 days, so they qualify for both cause and fix bisection.
	c.advanceTime(31 * 24 * time.Hour)

	// Old bugs get at most one job per hour for each of the workflows.
	require.Contains(t, poll(ai.WorkflowBisectCause), "bisect-cause: KASAN: slab-use-after-free in old")
	require.Empty(t, poll(ai.WorkflowBisectCause))
	require.Contains(t, poll(ai.WorkflowBisectFix), "bisect-fix: KASAN: slab-use-after-free in old")
	require.Empty(t, poll(ai.WorkflowBisectFix))
	c.advanceTime(time.Hour)
	require.Contains(t, poll(ai.WorkflowBisectCause), "bisect-cause: KASAN: slab-use-after-free in old")
	require.Empty(t, poll(ai.WorkflowBisectCause))

	// Jobs for new bugs are created right away, and they don't delay jobs for old bugs.
	c.advanceTime(30 * time.Minute)
	reportCrash(oldBugs, "KASAN: slab-use-after-free in new")
	require.Equal(t, "bisect-cause: KASAN: slab-use-after-free in new", poll(ai.WorkflowBisectCause))
	require.Empty(t, poll(ai.WorkflowBisectCause))
	c.advanceTime(30 * time.Minute)
	require.Contains(t, poll(ai.WorkflowBisectCause), "bisect-cause: KASAN: slab-use-after-free in old")
	require.Empty(t, poll(ai.WorkflowBisectCause))

	// A pending job of a new bug is created even if the jobs of the remaining old bugs have to wait:
	// here assessment-kcsan is created first, and bisect-cause stays pending.
	reportCrash(oldBugs+1, "KCSAN: data-race in foo / bar")
	require.Equal(t, "assessment-kcsan: KCSAN: data-race in foo / bar",
		poll(ai.WorkflowAssessmentKCSAN, ai.WorkflowBisectCause))
	require.Equal(t, "bisect-cause: KCSAN: data-race in foo / bar",
		poll(ai.WorkflowAssessmentKCSAN, ai.WorkflowBisectCause))
	require.Empty(t, poll(ai.WorkflowAssessmentKCSAN, ai.WorkflowBisectCause))
}
