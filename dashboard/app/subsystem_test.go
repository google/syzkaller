// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/stretchr/testify/assert"
)

const subsystemTestNs = "test1"

func TestSubsytemMaintainers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// This also indirectly tests getSubsystemService.
	assert.ElementsMatch(t,
		subsystemMaintainers(c.ctx, subsystemTestNs, "subsystemA"),
		[]string{
			"subsystemA@list.com", "subsystemA@person.com",
		},
	)
	assert.ElementsMatch(t, subsystemMaintainers(c.ctx, subsystemTestNs, "does-not-exist"), []string{})
}

func TestPeriodicSubsystemRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	ns := subsystemTestNs

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug without any subsystems.
	c.setSubsystems(ns, nil, 1)
	crash := testCrash(build, 1)
	crash.Title = "WARNING: abcd"
	crash.GuiltyFiles = []string{"test.c"}
	client.ReportCrash(crash)
	rep := client.pollBug()
	extID := rep.ID

	// Initially there should be no subsystems.
	expectSubsystems(t, client, extID)

	// Update subsystems.
	item := &subsystem.Subsystem{
		Name:      "first",
		PathRules: []subsystem.PathRule{{IncludeRegexp: `test\.c`}},
	}
	// Keep revision the same.
	c.setSubsystems(ns, []*subsystem.Subsystem{item}, 1)

	// Refresh subsystems.
	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID) // Not enough time has passed yet.

	// Wait until the refresh period is over.
	c.advanceTime(openBugsUpdateTime)

	_, err = c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID, "first")
}

func TestOpenBugRevRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	ns := subsystemTestNs

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug without any subsystems.
	c.setSubsystems(ns, nil, 0)
	crash := testCrash(build, 1)
	crash.GuiltyFiles = []string{"test.c"}
	client.ReportCrash(crash)
	rep := client.pollBug()
	extID := rep.ID

	// Initially there should be no subsystems.
	expectSubsystems(t, client, extID)

	// Update subsystems.
	c.advanceTime(time.Hour)
	item := &subsystem.Subsystem{
		Name:      "first",
		PathRules: []subsystem.PathRule{{IncludeRegexp: `test\.c`}},
	}
	// Update the revision number as well.
	c.setSubsystems(ns, []*subsystem.Subsystem{item}, 1)

	// Refresh subsystems.
	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID, "first")
}

func TestClosedBugSubsystemRefresh(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	ns := subsystemTestNs

	build := testBuild(1)
	client.UploadBuild(build)

	// Create a bug without any subsystems.
	c.setSubsystems(ns, nil, 0)
	crash := testCrash(build, 1)
	crash.GuiltyFiles = []string{"test.c"}
	client.ReportCrash(crash)
	rep := client.pollBug()
	extID := rep.ID

	// "Fix" the bug.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix the crash"},
	})
	c.expectEQ(reply.OK, true)
	build2 := testBuild(2)
	build2.Manager = build.Manager
	build2.Commits = []string{"foo: fix the crash"}
	client.UploadBuild(build2)
	client.pollNotifs(0)
	bug, _, _ := c.loadBug(rep.ID)
	c.expectEQ(bug.Status, BugStatusFixed)

	// Initially there should be no subsystems.
	expectSubsystems(t, client, extID)

	// Update subsystems.
	c.advanceTime(time.Hour)
	item := &subsystem.Subsystem{
		Name:      "first",
		PathRules: []subsystem.PathRule{{IncludeRegexp: `test\.c`}},
	}
	c.setSubsystems(ns, []*subsystem.Subsystem{item}, 1)

	// Refresh subsystems.
	c.advanceTime(time.Hour)
	_, err := c.AuthGET(AccessUser, "/cron/refresh_subsystems")
	c.expectOK(err)
	expectSubsystems(t, client, extID, "first")
}

func expectSubsystems(t *testing.T, client *apiClient, extID string, subsystems ...string) {
	t.Helper()
	bug, _, _ := client.Ctx.loadBug(extID)
	names := []string{}
	for _, item := range bug.Tags.Subsystems {
		names = append(names, item.Name)
	}
	assert.ElementsMatch(t, names, subsystems)
}
