// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

// TestAccessConfig checks that access level were properly assigned throughout the config.
func TestAccessConfig(t *testing.T) {
	tests := []struct {
		what  string
		want  AccessLevel
		level AccessLevel
	}{
		{"admin", AccessAdmin, config.Namespaces["access-admin"].AccessLevel},
		{"admin/0", AccessAdmin, config.Namespaces["access-admin"].Reporting[0].AccessLevel},
		{"admin/1", AccessAdmin, config.Namespaces["access-admin"].Reporting[1].AccessLevel},
		{"user", AccessUser, config.Namespaces["access-user"].AccessLevel},
		{"user/0", AccessAdmin, config.Namespaces["access-user"].Reporting[0].AccessLevel},
		{"user/1", AccessUser, config.Namespaces["access-user"].Reporting[1].AccessLevel},
		{"public", AccessPublic, config.Namespaces["access-public"].AccessLevel},
		{"public/0", AccessUser, config.Namespaces["access-public"].Reporting[0].AccessLevel},
		{"public/1", AccessPublic, config.Namespaces["access-public"].Reporting[1].AccessLevel},
	}
	for _, test := range tests {
		if test.level != test.want {
			t.Errorf("%v level %v, want %v", test.what, test.level, test.want)
		}
	}
}

// TestAccess checks that all UIs respect access levels.
func TestAccess(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// entity describes pages/bugs/texts/etc.
	type entity struct {
		level AccessLevel // level on which this entity must be visible.
		ref   string      // a unique entity reference id.
		url   string      // url at which this entity can be requested.
	}
	entities := []entity{
		{
			// Main page.
			level: config.AccessLevel,
			url:   "/",
		},
		{
			// Any references to namespace, reporting, links, etc.
			level: AccessUser,
			ref:   "access-user",
		},
		{
			// Any references to namespace, reporting, links, etc.
			level: AccessAdmin,
			ref:   "access-admin",
		},
	}

	// noteBugAccessLevel collects all entities associated with the extID bug.
	noteBugAccessLevel := func(extID string, level AccessLevel) {
		bug, _, err := findBugByReportingID(c.ctx, extID)
		if err != nil {
			t.Fatal(err)
		}
		crash, _, err := findCrashForBug(c.ctx, bug)
		if err != nil {
			t.Fatal(err)
		}
		bugID := bugKeyHash(bug.Namespace, bug.Title, bug.Seq)
		entities = append(entities, []entity{
			{
				level: level,
				ref:   bugID,
				url:   fmt.Sprintf("/bug?id=%v", bugID),
			},
			{
				level: level,
				ref:   bug.Reporting[0].ID,
				url:   fmt.Sprintf("/bug?extid=%v", bug.Reporting[0].ID),
			},
			{
				level: level,
				ref:   bug.Reporting[1].ID,
				url:   fmt.Sprintf("/bug?extid=%v", bug.Reporting[1].ID),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.Log),
				url:   fmt.Sprintf("/text?tag=CrashLog&id=%v", crash.Log),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.Report),
				url:   fmt.Sprintf("/text?tag=CrashReport&id=%v", crash.Report),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproC),
				url:   fmt.Sprintf("/text?tag=ReproC&id=%v", crash.ReproC),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproSyz),
				url:   fmt.Sprintf("/text?tag=ReproSyz&id=%v", crash.ReproSyz),
			},
		}...)
	}

	// noteBuildccessLevel collects all entities associated with the kernel build buildID.
	noteBuildccessLevel := func(ns, buildID string) {
		build, err := loadBuild(c.ctx, ns, buildID)
		if err != nil {
			t.Fatal(err)
		}
		entities = append(entities, entity{
			level: config.Namespaces[ns].AccessLevel,
			ref:   build.ID,
			url:   fmt.Sprintf("/text?tag=KernelConfig&id=%v", build.KernelConfig),
		})
	}

	// These strings are put into crash log/report, kernel config, etc.
	// If a request at level UserPublic sees a page containing "access-user",
	// that will be flagged as error.
	accessLevelPrefix := func(level AccessLevel) string {
		switch level {
		case AccessPublic:
			return "access-public-"
		case AccessUser:
			return "access-user-"
		default:
			return "access-admin-"
		}
	}

	// For each namespace we create 8 bugs:
	// invalid, dup, fixed and open for both reportings.
	// Bugs are setup in such a way that there are lots of
	// duplicate/similar cross-references.
	for _, ns := range []string{"access-admin", "access-user", "access-public"} {
		clientName, clientKey := "", ""
		for k, v := range config.Namespaces[ns].Clients {
			clientName, clientKey = k, v
		}
		namespaceAccessPrefix := accessLevelPrefix(config.Namespaces[ns].AccessLevel)
		client := c.makeClient(clientName, clientKey)
		build := testBuild(1)
		build.KernelConfig = []byte(namespaceAccessPrefix + "build")
		client.uploadBuild(build)
		noteBuildccessLevel(ns, build.ID)

		for reportingIdx := 0; reportingIdx < 2; reportingIdx++ {
			accessLevel := config.Namespaces[ns].Reporting[reportingIdx].AccessLevel
			accessPrefix := accessLevelPrefix(accessLevel)

			crashInvalid := testCrashWithRepro(build, reportingIdx*10+0)
			client.reportCrash(crashInvalid)
			repInvalid := reportAllBugs(c, 1)[0]
			if reportingIdx != 0 {
				c.expectTrue(client.updateBug(repInvalid.ID, dashapi.BugStatusUpstream, "").OK)
				repInvalid = reportAllBugs(c, 1)[0]
			}
			c.expectTrue(client.updateBug(repInvalid.ID, dashapi.BugStatusInvalid, "").OK)
			noteBugAccessLevel(repInvalid.ID, accessLevel)

			crashFixed := testCrashWithRepro(build, reportingIdx*10+0)
			client.reportCrash(crashFixed)
			repFixed := reportAllBugs(c, 1)[0]
			if reportingIdx != 0 {
				c.expectTrue(client.updateBug(repFixed.ID, dashapi.BugStatusUpstream, "").OK)
				repFixed = reportAllBugs(c, 1)[0]
			}
			cmd := &dashapi.BugUpdate{
				ID:         repFixed.ID,
				Status:     dashapi.BugStatusOpen,
				FixCommits: []string{ns + "-patch0"},
				ExtID:      accessPrefix + "reporting-ext-id",
				Link:       accessPrefix + "reporting-link",
			}
			reply := new(dashapi.BugUpdateReply)
			client.expectOK(client.API("reporting_update", cmd, reply))
			c.expectEQ(reply.OK, true)
			buildFixing := testBuild(reportingIdx*10 + 2)
			buildFixing.Manager = build.Manager
			buildFixing.Commits = []string{ns + "-patch0"}
			client.uploadBuild(buildFixing)
			noteBuildccessLevel(ns, buildFixing.ID)
			// Fixed bugs become visible up to the last reporting.
			finalLevel := config.Namespaces[ns].
				Reporting[len(config.Namespaces[ns].Reporting)-1].AccessLevel
			noteBugAccessLevel(repFixed.ID, finalLevel)

			crashOpen := testCrashWithRepro(build, reportingIdx*10+0)
			crashOpen.Log = []byte(accessPrefix + "log")
			crashOpen.Report = []byte(accessPrefix + "report")
			crashOpen.ReproC = []byte(accessPrefix + "repro c")
			crashOpen.ReproSyz = []byte(accessPrefix + "repro syz")
			client.reportCrash(crashOpen)
			repOpen := reportAllBugs(c, 1)[0]
			if reportingIdx != 0 {
				c.expectTrue(client.updateBug(repOpen.ID, dashapi.BugStatusUpstream, "").OK)
				repOpen = reportAllBugs(c, 1)[0]
			}
			noteBugAccessLevel(repOpen.ID, accessLevel)

			crashPatched := testCrashWithRepro(build, reportingIdx*10+1)
			client.reportCrash(crashPatched)
			repPatched := reportAllBugs(c, 1)[0]
			if reportingIdx != 0 {
				c.expectTrue(client.updateBug(repPatched.ID, dashapi.BugStatusUpstream, "").OK)
				repPatched = reportAllBugs(c, 1)[0]
			}
			cmd = &dashapi.BugUpdate{
				ID:         repPatched.ID,
				Status:     dashapi.BugStatusOpen,
				FixCommits: []string{ns + "-patch0"},
				ExtID:      accessPrefix + "reporting-ext-id",
				Link:       accessPrefix + "reporting-link",
			}
			reply = new(dashapi.BugUpdateReply)
			client.expectOK(client.API("reporting_update", cmd, reply))
			c.expectEQ(reply.OK, true)
			// Patched bugs are also visible up to the last reporting.
			noteBugAccessLevel(repPatched.ID, finalLevel)

			crashDup := testCrashWithRepro(build, reportingIdx*10+2)
			client.reportCrash(crashDup)
			repDup := reportAllBugs(c, 1)[0]
			if reportingIdx != 0 {
				c.expectTrue(client.updateBug(repDup.ID, dashapi.BugStatusUpstream, "").OK)
				repDup = reportAllBugs(c, 1)[0]
			}
			c.expectTrue(client.updateBug(repDup.ID, dashapi.BugStatusDup, repOpen.ID).OK)
			noteBugAccessLevel(repDup.ID, accessLevel)
		}
	}

	// checkReferences checks that page contents do not contain
	// references to entities that must not be visible.
	checkReferences := func(url string, requestLevel AccessLevel, reply []byte) {
		for _, ent := range entities {
			if requestLevel >= ent.level || ent.ref == "" {
				continue
			}
			if bytes.Contains(reply, []byte(ent.ref)) {
				t.Errorf("request %v at level %v contains ref %v at level %v:\n%s\n\n",
					url, requestLevel, ent.ref, ent.level, reply)
			}
		}
	}

	// checkPage checks that the page at url is accessible/not accessible as required.
	checkPage := func(requestLevel, pageLevel AccessLevel, url string) []byte {
		reply, err := c.AuthGET(requestLevel, url)
		if requestLevel >= pageLevel {
			c.expectOK(err)
		} else {
			c.expectForbidden(err)
		}
		return reply
	}

	// Finally, request all entities at all access levels and
	// check that we see only what we need to see.
	for requestLevel := AccessPublic; requestLevel < AccessAdmin; requestLevel++ {
		for _, ent := range entities {
			if ent.url == "" {
				continue
			}
			reply := checkPage(requestLevel, ent.level, ent.url)
			checkReferences(ent.url, requestLevel, reply)
		}
	}
}
