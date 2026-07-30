// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagersGraphs(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client2.UploadBuild(build1)
	build2 := testBuild(2)
	c.client2.UploadBuild(build2)

	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 100,
		PCs:    1000,
		Cover:  2000,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 200,
		PCs:    2000,
		Cover:  4000,
	}))
	c.advanceTime(25 * time.Hour)
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 110,
		PCs:    1100,
		Cover:  2200,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 220,
		PCs:    2200,
		Cover:  4400,
	}))
	c.advanceTime(25 * time.Hour)
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 150,
		PCs:    1500,
		Cover:  2900,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 270,
		PCs:    2700,
		Cover:  5400,
	}))
	c.advanceTime(25 * time.Hour)
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 50,
		PCs:    500,
		Cover:  900,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 70,
		PCs:    700,
		Cover:  400,
	}))

	for i := range 3 {
		c.advanceTime(7 * 25 * time.Hour)
		for j := range i + 1 {
			crash := testCrash(build1, i*i+j)
			c.client2.ReportCrash(crash)
		}
	}

	for {
		c.advanceTime(7 * 25 * time.Hour)
		_, err := c.GET("/cron/email_poll")
		c.expectOK(err)
		if len(c.emailSink) == 0 {
			break
		}
		for len(c.emailSink) != 0 {
			<-c.emailSink
		}
	}

	reply, err := c.AuthGET(AccessAdmin, "/test2/graph/bugs")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/lifetimes")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/fuzzing")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/crashes")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/found-bugs")
	c.expectOK(err)
	// TODO: check reply
	_ = reply
}

func managersGraphFixture(t *testing.T) *Ctx {
	c := NewCtx(t)
	t.Cleanup(c.Close)

	build1 := testBuild(1)
	c.client2.UploadBuild(build1)

	c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 100,
		PCs:    1000,
		Cover:  2000,
	})

	return c
}

func TestManagersGraph_FuzzingMetric_OK_OnValidInput(t *testing.T) {
	c := managersGraphFixture(t)
	_, err := c.AuthGET(AccessAdmin, "/test2/graph/fuzzing?Metrics=MaxCorpus")
	c.expectOK(err)
}

func TestManagersGraph_FuzzingMetric_BadRequest_OnMalformedInput(t *testing.T) {
	c := managersGraphFixture(t)
	_, err := c.AuthGET(AccessAdmin, "/test2/graph/fuzzing?Metrics=MaxCorpus'%2F*%22ZYLQ%22*%2F+AND+'0'%3D'0&Months=27")
	c.expectBadReqest(err)
}

func TestResolutionGraph(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	type testBug struct {
		reportedMonthsAgo int
		closedMonthsAgo   int
		fixedMonthsAgo    int
		status            int
		auto              bool
	}
	makeBug := func(tb testBug) *Bug {
		b := &Bug{
			FirstTime: now.AddDate(0, -tb.reportedMonthsAgo, 0),
			Reporting: []BugReporting{
				{Name: "stage0", Reported: now.AddDate(0, -tb.reportedMonthsAgo, 0)},
				{Name: "stage1", Reported: now.AddDate(0, -tb.reportedMonthsAgo, 0), Auto: tb.auto},
			},
			Status: tb.status,
		}
		if tb.closedMonthsAgo > 0 {
			b.Closed = now.AddDate(0, -tb.closedMonthsAgo, 0)
		}
		if tb.fixedMonthsAgo > 0 {
			b.CommitInfo = append(b.CommitInfo, Commit{Date: now.AddDate(0, -tb.fixedMonthsAgo, 0)})
		}
		return b
	}

	testBugs := []testBug{
		// Included in cohort (reported 6-24 months ago):
		{
			// Fixed 1m after report.
			reportedMonthsAgo: 6,
			fixedMonthsAgo:    5,
			status:            BugStatusFixed,
		},
		{
			// Fixed 3m after report.
			reportedMonthsAgo: 7,
			closedMonthsAgo:   4,
			status:            BugStatusFixed,
		},
		{
			// Auto-obsoleted 3m after report.
			reportedMonthsAgo: 8,
			closedMonthsAgo:   5,
			status:            BugStatusInvalid,
			auto:              true,
		},
		{
			// Manually closed 2m after report.
			reportedMonthsAgo: 9,
			closedMonthsAgo:   7,
			status:            BugStatusInvalid,
		},
		// Excluded from cohort:
		{
			// Too recent (< 6m).
			reportedMonthsAgo: 0,
			status:            BugStatusOpen,
		},
		{
			// Too old (> 24m).
			reportedMonthsAgo: 36,
			closedMonthsAgo:   36,
			status:            BugStatusFixed,
		},
		{
			// Duplicate.
			reportedMonthsAgo: 6,
			closedMonthsAgo:   1,
			status:            BugStatusDup,
		},
	}

	var bugs []*Bug
	for _, tb := range testBugs {
		bugs = append(bugs, makeBug(tb))
	}

	graph := createResolutionGraph(now, bugs, 1)
	require.Len(t, graph.Columns, 6)

	expected := []struct {
		val  float32
		hint string
	}{
		{val: 25.0, hint: "1/4 bugs (25.0%)"}, // Month 1: bug1 fixed (1m).
		{val: 50.0, hint: "2/4 bugs (50.0%)"}, // Month 2: bug1, bugManualInvalid (2m).
		{val: 75.0, hint: "3/4 bugs (75.0%)"}, // Month 3: bug1, bug2 (3m), bugManualInvalid.
		{val: 75.0, hint: "3/4 bugs (75.0%)"}, // Month 4.
		{val: 75.0, hint: "3/4 bugs (75.0%)"}, // Month 5.
		{val: 75.0, hint: "3/4 bugs (75.0%)"}, // Month 6.
	}

	for i, tt := range expected {
		require.Equal(t, tt.val, graph.Columns[i].Annotation)
		require.Len(t, graph.Columns[i].Vals, 1)
		require.Equal(t, tt.val, graph.Columns[i].Vals[0].Val)
		require.Equal(t, tt.hint, graph.Columns[i].Vals[0].Hint)
	}
}

func TestResolutionGraphEndpoint(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	reply, err := c.AuthGET(AccessAdmin, "/test2/graph/resolution")
	require.NoError(t, err)
	assert.Contains(t, string(reply), "bug resolution rates")
}
