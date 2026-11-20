// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	db "google.golang.org/appengine/v2/datastore"
)

// Test that historical syz-ci bisection results show up on UI.
func TestBugBisectionResults(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build, _ := addBuildAndCrash(c)
	_, bugKey := c.loadSingleBug()

	addBisectCauseJob(c, build)
	addBisectFixJob(c, build)

	// Ensure expected results show up on web UI.
	url := fmt.Sprintf("/bug?id=%v", bugKey.StringID())
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("Cause bisection: introduced by")))
	c.expectTrue(bytes.Contains(content, []byte("kernel: add a bug")))
	c.expectTrue(bytes.Contains(content, []byte("Fix bisection: fixed by")))
	c.expectTrue(bytes.Contains(content, []byte("kernel: add a fix")))
}

// Test that bisection status shows up on main page.
func TestBugBisectionStatus(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload a crash report.
	build, _ := addBuildAndCrash(c)

	addBisectCauseJob(c, build)

	// Fetch bug, namespace details.
	var bugs []*Bug
	_, err := db.NewQuery("Bug").GetAll(c.ctx, &bugs)
	c.expectEQ(err, nil)
	c.expectEQ(len(bugs), 1)
	url := fmt.Sprintf("/%v", bugs[0].Namespace)
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("done")))

	addBisectFixJob(c, build)

	content, err = c.GET(url)
	c.expectEQ(err, nil)
	c.expectTrue(bytes.Contains(content, []byte("done")))
}

// Test that invalidated bisections are not shown in the UI and marked as invalid.
func TestBugBisectionInvalidation(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build, _ := addBuildAndCrash(c)
	addBisectCauseJob(c, build)

	// Ensure expected results show up on web UI.
	bug, bugKey := c.loadSingleBug()
	job, jobKey := c.loadSingleJob()
	bugURL := fmt.Sprintf("/bug?id=%v", bugKey.StringID())
	content, err := c.GET(bugURL)
	c.expectEQ(err, nil)
	c.expectEQ(bug.BisectCause, BisectYes)
	c.expectTrue(bytes.Contains(content, []byte("Cause bisection: introduced by")))
	c.expectTrue(bytes.Contains(content, []byte("kernel: add a bug")))
	c.expectEQ(job.InvalidatedBy, "")

	// Mark bisection as invalid.
	_, err = c.AuthGET(AccessAdmin, "/admin?action=invalidate_bisection&key="+jobKey.Encode())
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, http.StatusFound)

	// The invalidated bisection should have vanished from the web UI.
	job, _ = c.loadSingleJob()
	content, err = c.GET(bugURL)
	c.expectEQ(err, nil)
	c.expectTrue(!bytes.Contains(content, []byte("Cause bisection: introduced by")))
	c.expectTrue(!bytes.Contains(content, []byte("kernel: add a bug")))
	c.expectEQ(job.InvalidatedBy, makeUser(AuthorizedAdmin).Email)
}

// Upload a build, a crash report and poll bug emails.
func addBuildAndCrash(c *Ctx) (*dashapi.Build, *dashapi.Crash) {
	build := testBuild(1)
	c.client2.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.client2.ReportCrash(crash)
	c.client2.pollEmailBug()

	c.advanceTime(30 * 24 * time.Hour)
	msg := c.client2.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "Sending this report to the next reporting stage."))
	msg = c.client2.pollEmailBug()
	c.expectTrue(strings.Contains(msg.Body, "syzbot found the following issue"))

	return build, crash
}

func addBisectCauseJob(c *Ctx, build *dashapi.Build) {
	_, bugKey := c.loadSingleBug()
	c.saveHistoricalBisectJob(historicalBisectJob{
		bugKey:      bugKey,
		jobType:     JobBisectCause,
		build:       build,
		crashTitle:  "bisectfix crash title 4",
		crashLog:    "bisectfix crash log 4",
		crashReport: "bisectfix crash report 4",
		log:         "bisectfix log 4",
		commits: []dashapi.Commit{
			{
				Hash:       "36e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:      "kernel: add a bug",
				Author:     "author@kernel.org",
				AuthorName: "Author Kernelov",
				CC: []string{
					"reviewer1@kernel.org", "\"Reviewer2\" <reviewer2@kernel.org>",
					"syzbot@testapp.appspotmail.com",
					"syzbot+1234@testapp.appspotmail.com",
					"\"syzbot\" <syzbot+1234@testapp.appspotmail.com>",
				},
				Date: time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	})
}

func addBisectFixJob(c *Ctx, build *dashapi.Build) {
	_, bugKey := c.loadSingleBug()
	c.saveHistoricalBisectJob(historicalBisectJob{
		bugKey:      bugKey,
		jobType:     JobBisectFix,
		build:       build,
		crashTitle:  "bisectfix crash title 4",
		crashLog:    "bisectfix crash log 4",
		crashReport: "bisectfix crash report 4",
		log:         "bisectfix log 4",
		commits: []dashapi.Commit{
			{
				Hash:       "46e65cb4a0448942ec316b24d60446bbd5cc7827",
				Title:      "kernel: add a fix",
				Author:     "author@kernel.org",
				AuthorName: "Author Kernelov",
				CC: []string{
					"reviewer1@kernel.org", "\"Reviewer2\" <reviewer2@kernel.org>",
					"syzbot@testapp.appspotmail.com",
					"syzbot+1234@testapp.appspotmail.com",
					"\"syzbot\" <syzbot+1234@testapp.appspotmail.com>",
				},
				Date: time.Date(2000, 2, 9, 4, 5, 6, 7, time.UTC),
			},
		},
	})
}
