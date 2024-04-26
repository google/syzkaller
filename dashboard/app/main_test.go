// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
)

func TestOnlyManagerFilter(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build1 := testBuild(1)
	client.UploadBuild(build1)
	build2 := testBuild(2)
	client.UploadBuild(build2)

	crash1 := testCrash(build1, 1)
	crash1.Title = "only the first manager"
	client.ReportCrash(crash1)

	crash2 := testCrash(build2, 2)
	crash2.Title = "only the second manager"
	client.ReportCrash(crash2)

	crashBoth1 := testCrash(build1, 3)
	crashBoth1.Title = "both managers"
	client.ReportCrash(crashBoth1)

	crashBoth2 := testCrash(build2, 4)
	crashBoth2.Title = "both managers"
	client.ReportCrash(crashBoth2)

	// Make sure all those bugs are present on the main page.
	reply, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	for _, title := range []string{crash1.Title, crash2.Title, crashBoth1.Title} {
		if !bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is not contained on the main page", title)
		}
	}

	// Check that filtering on the main page works.
	reply, err = c.AuthGET(AccessAdmin, "/test1?only_manager="+build1.Manager)
	c.expectOK(err)
	for _, title := range []string{crash2.Title, crashBoth1.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the main page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash1.Title)) {
		t.Fatalf("%#v is not contained on the main page", crash1.Title)
	}

	// Invalidate all these bugs.
	polledBugs := client.pollBugs(3)
	for _, bug := range polledBugs {
		client.updateBug(bug.ID, dashapi.BugStatusInvalid, "")
	}

	// Verify that the filtering works on the invalid bugs page.
	reply, err = c.AuthGET(AccessAdmin, "/test1/invalid?only_manager="+build2.Manager)
	c.expectOK(err)
	for _, title := range []string{crash1.Title, crashBoth1.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the invalid bugs page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash2.Title)) {
		t.Fatalf("%#v is not contained on the invalid bugs page", crash2.Title)
	}
}

const (
	subsystemA = "subsystemA"
	subsystemB = "subsystemB"
)

func TestSubsystemFilterMain(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "first bug"
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	crash2.Title = "second bug"
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)

	client.pollBugs(2)
	// Make sure all those bugs are present on the main page.
	reply, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	for _, title := range []string{crash1.Title, crash2.Title} {
		if !bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is not contained on the main page", title)
		}
	}
	// Check that filtering on the main page works.
	reply, err = c.AuthGET(AccessAdmin, "/test1?label=subsystems:"+subsystemA)
	c.expectOK(err)
	for _, title := range []string{crash2.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the main page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash1.Title)) {
		t.Fatalf("%#v is not contained on the main page", crash2.Title)
	}
}

func TestSubsystemFilterTerminal(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "first bug"
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	crash2.Title = "second bug"
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)

	// Invalidate all these bugs.
	polledBugs := client.pollBugs(2)
	for _, bug := range polledBugs {
		client.updateBug(bug.ID, dashapi.BugStatusInvalid, "")
	}

	// Verify that the filtering works on the invalid bugs page.
	reply, err := c.AuthGET(AccessAdmin, "/test1/invalid?label=subsystems:"+subsystemB)
	c.expectOK(err)
	for _, title := range []string{crash1.Title} {
		if bytes.Contains(reply, []byte(title)) {
			t.Fatalf("%#v is contained on the invalid bugs page", title)
		}
	}
	if !bytes.Contains(reply, []byte(crash2.Title)) {
		t.Fatalf("%#v is not contained on the invalid bugs page", crash2.Title)
	}
}

func TestMainBugFilters(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build1 := testBuild(1)
	build1.Manager = "manager-name-123"
	client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	crash1.Title = "my-crash-title"
	client.ReportCrash(crash1)
	client.pollBugs(1)

	// The normal main page.
	reply, err := c.AuthGET(AccessAdmin, "/test1")
	c.expectOK(err)
	assert.Contains(t, string(reply), build1.Manager)
	assert.NotContains(t, string(reply), "Applied filters")

	reply, err = c.AuthGET(AccessAdmin, "/test1?label=subsystems:abcd")
	c.expectOK(err)
	assert.NotContains(t, string(reply), build1.Manager) // managers are hidden
	assert.Contains(t, string(reply), "Applied filters") // we're seeing a prompt to disable the filter
	assert.NotContains(t, string(reply), crash1.Title)   // the bug does not belong to the subsystem

	reply, err = c.AuthGET(AccessAdmin, "/test1?no_subsystem=true")
	c.expectOK(err)
	assert.Contains(t, string(reply), crash1.Title) // the bug has no subsystems
}

func TestSubsystemsList(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)
	client.pollBug()

	crash2 := testCrash(build, 2)
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)
	client.updateBug(client.pollBug().ID, dashapi.BugStatusInvalid, "")

	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)

	reply, err := c.AuthGET(AccessAdmin, "/test1/subsystems")
	c.expectOK(err)
	assert.Contains(t, string(reply), "subsystemA")
	assert.NotContains(t, string(reply), "subsystemB")

	reply, err = c.AuthGET(AccessAdmin, "/test1/subsystems?all=true")
	c.expectOK(err)
	assert.Contains(t, string(reply), "subsystemA")
	assert.Contains(t, string(reply), "subsystemB")
}

func TestSubsystemPage(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "test crash title"
	crash1.GuiltyFiles = []string{"a.c"}
	client.ReportCrash(crash1)
	client.pollBug()

	crash2 := testCrash(build, 2)
	crash2.GuiltyFiles = []string{"b.c"}
	client.ReportCrash(crash2)
	crash2.Title = "crash that must not be present"
	client.updateBug(client.pollBug().ID, dashapi.BugStatusInvalid, "")

	reply, err := c.AuthGET(AccessAdmin, "/test1/s/subsystemA")
	c.expectOK(err)
	assert.Contains(t, string(reply), crash1.Title)
	assert.NotContains(t, string(reply), crash2.Title)
}

func TestMultiLabelFilter(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublicEmail, keyPublicEmail, true)
	mailingList := c.config().Namespaces["access-public-email"].Reporting[0].Config.(*EmailConfig).Email

	build1 := testBuild(1)
	build1.Manager = "manager-name-123"
	client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	crash1.GuiltyFiles = []string{"a.c"}
	crash1.Title = "crash-with-subsystem-A"
	client.ReportCrash(crash1)
	c.pollEmailBug()

	crash2 := testCrash(build1, 2)
	crash2.GuiltyFiles = []string{"a.c"}
	crash2.Title = "prio-crash-subsystem-A"
	client.ReportCrash(crash2)

	c.incomingEmail(c.pollEmailBug().Sender, "#syz set prio: low\n",
		EmailOptFrom("test@requester.com"), EmailOptCC([]string{mailingList}))

	// The normal main page.
	reply, err := c.AuthGET(AccessAdmin, "/access-public-email")
	c.expectOK(err)
	assert.Contains(t, string(reply), build1.Manager)
	assert.NotContains(t, string(reply), "Applied filters")

	reply, err = c.AuthGET(AccessAdmin, "/access-public-email?label=subsystems:subsystemA")
	c.expectOK(err)
	assert.Contains(t, string(reply), "Applied filters") // we're seeing a prompt to disable the filter
	assert.Contains(t, string(reply), crash1.Title)
	assert.Contains(t, string(reply), crash2.Title)

	// Test filters together.
	reply, err = c.AuthGET(AccessAdmin, "/access-public-email?label=subsystems:subsystemA&&label=prio:low")
	c.expectOK(err)
	assert.NotContains(t, string(reply), crash1.Title)
	assert.Contains(t, string(reply), crash2.Title)

	// Ensure we provide links that drop labels.
	assert.NotContains(t, string(reply), "/access-public-email?label=subsystems:subsystemA\"")
	assert.NotContains(t, string(reply), "/access-public-email?label=prop:low\"")
}

func TestAdminJobList(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client2
	build := testBuild(1)
	client.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Title = "some bug title"
	crash.GuiltyFiles = []string{"a.c"}
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("repro syz")
	crash.ReproC = []byte("repro C")
	client.ReportCrash(crash)
	client.pollEmailBug()

	c.advanceTime(24 * time.Hour)

	pollResp := client.pollSpecificJobs(build.Manager, dashapi.ManagerJobs{BisectCause: true})
	c.expectNE(pollResp.ID, "")

	causeJobsLink := "/admin?job_type=1"
	fixJobsLink := "/admin?job_type=2"
	reply, err := c.AuthGET(AccessAdmin, "/admin")
	c.expectOK(err)
	assert.Contains(t, string(reply), causeJobsLink)
	assert.Contains(t, string(reply), fixJobsLink)

	// Verify the bug is in the bisect cause jobs list.
	reply, err = c.AuthGET(AccessAdmin, causeJobsLink)
	c.expectOK(err)
	assert.Contains(t, string(reply), crash.Title)

	// Verify the bug is NOT in the fix jobs list.
	reply, err = c.AuthGET(AccessAdmin, fixJobsLink)
	c.expectOK(err)
	assert.NotContains(t, string(reply), crash.Title)
}

func TestSubsystemsPageRedirect(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Verify that the normal subsystem page works.
	_, err := c.AuthGET(AccessAdmin, "/access-public-email/s/subsystemA")
	c.expectOK(err)

	// Verify that the old subsystem name points to the new one.
	_, err = c.AuthGET(AccessAdmin, "/access-public-email/s/oldSubsystem")
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, http.StatusMovedPermanently)
	c.expectEQ(httpErr.Headers["Location"], []string{"/access-public-email/s/subsystemA"})
}

func TestNoThrottle(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	assert.True(t, c.config().Throttle.Empty())
	for i := 0; i < 10; i++ {
		c.advanceTime(time.Millisecond)
		_, err := c.AuthGET(AccessPublic, "/access-public-email")
		c.expectOK(err)
	}
}

func TestThrottle(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	c.transformContext = func(c context.Context) context.Context {
		newConfig := *getConfig(c)
		newConfig.Throttle = ThrottleConfig{
			Window: 10 * time.Second,
			Limit:  10,
		}
		return contextWithConfig(c, &newConfig)
	}

	// Adhere to the limit.
	for i := 0; i < 15; i++ {
		c.advanceTime(time.Second)
		_, err := c.AuthGET(AccessPublic, "/access-public-email")
		c.expectOK(err)
	}

	// Break the limit.
	c.advanceTime(time.Millisecond)
	_, err := c.AuthGET(AccessPublic, "/access-public-email")
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, http.StatusTooManyRequests)

	// Still too frequent requests.
	c.advanceTime(time.Millisecond)
	_, err = c.AuthGET(AccessPublic, "/access-public-email")
	c.expectTrue(err != nil)

	// Wait a bit.
	c.advanceTime(3 * time.Second)
	_, err = c.AuthGET(AccessPublic, "/access-public-email")
	c.expectOK(err)
}

func TestManagerPage(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	const firstManager = "manager-name"
	const secondManager = "another-manager-name"

	client := c.makeClient(clientPublicEmail, keyPublicEmail, true)
	build1 := testBuild(1)
	build1.Manager = firstManager
	c.expectOK(client.UploadBuild(build1))

	c.advanceTime(time.Hour)
	build2 := testBuild(2)
	build2.Manager = firstManager
	buildErrorReq := &dashapi.BuildErrorReq{
		Build: *build2,
		Crash: dashapi.Crash{
			Title:  "failed build 1",
			Report: []byte("report\n"),
			Log:    []byte("log\n"),
		},
	}
	c.expectOK(client.ReportBuildError(buildErrorReq))
	c.pollEmailBug()

	c.advanceTime(time.Hour)
	build3 := testBuild(3)
	build3.Manager = firstManager
	c.expectOK(client.UploadBuild(build3))

	// And one more build from a different manager.
	c.advanceTime(time.Hour)
	build4 := testBuild(4)
	build4.Manager = secondManager
	c.expectOK(client.UploadBuild(build4))

	// Query the first manager.
	reply, err := c.AuthGET(AccessPublic, "/access-public-email/manager/"+firstManager)
	c.expectOK(err)
	assert.Contains(t, string(reply), "kernel_commit_title1")
	assert.NotContains(t, string(reply), "kernel_commit_title2") // build error
	assert.Contains(t, string(reply), "kernel_commit_title3")
	assert.NotContains(t, string(reply), "kernel_commit_title4") // another manager

	// Query the second manager.
	reply, err = c.AuthGET(AccessPublic, "/access-public-email/manager/"+secondManager)
	c.expectOK(err)
	assert.NotContains(t, string(reply), "kernel_commit_title1")
	assert.NotContains(t, string(reply), "kernel_commit_title2")
	assert.NotContains(t, string(reply), "kernel_commit_title3")
	assert.Contains(t, string(reply), "kernel_commit_title4") // another manager

	// Query unknown manager.
	_, err = c.AuthGET(AccessPublic, "/access-public-email/manager/abcd")
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, http.StatusBadRequest)
}
