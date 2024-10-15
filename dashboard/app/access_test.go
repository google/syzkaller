// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"google.golang.org/appengine/v2/aetest"
	"google.golang.org/appengine/v2/user"
)

// TestAccessConfig checks that access level were properly assigned throughout the config.
func TestAccessConfig(t *testing.T) {
	config := getConfig(context.Background())
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
// nolint: funlen, goconst
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
		// Main pages.
		{
			level: AccessAdmin,
			url:   "/admin",
		},
		{
			level: AccessPublic,
			url:   "/access-public",
		},
		{
			level: AccessPublic,
			url:   "/access-public/fixed",
		},
		{
			level: AccessPublic,
			url:   "/access-public/invalid",
		},
		{
			level: AccessPublic,
			url:   "/access-public/graph/bugs",
		},
		{
			level: AccessPublic,
			url:   "/access-public/graph/lifetimes",
		},
		{
			level: AccessPublic,
			url:   "/access-public/graph/fuzzing",
		},
		{
			level: AccessPublic,
			url:   "/access-public/graph/crashes",
		},
		{
			level: AccessUser,
			url:   "/access-user",
		},
		{
			level: AccessUser,
			url:   "/access-user/fixed",
		},
		{
			level: AccessUser,
			url:   "/access-user/invalid",
		},
		{
			level: AccessUser,
			url:   "/access-user/graph/bugs",
		},
		{
			level: AccessUser,
			url:   "/access-user/graph/lifetimes",
		},
		{
			level: AccessUser,
			url:   "/access-user/graph/fuzzing",
		},
		{
			level: AccessUser,
			url:   "/access-user/graph/crashes",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin/fixed",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin/invalid",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin/graph/bugs",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin/graph/lifetimes",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin/graph/fuzzing",
		},
		{
			level: AccessAdmin,
			url:   "/access-admin/graph/crashes",
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
	noteBugAccessLevel := func(extID string, level, nsLevel AccessLevel) {
		bug, _, err := findBugByReportingID(c.ctx, extID)
		c.expectOK(err)
		crash, _, err := findCrashForBug(c.ctx, bug)
		c.expectOK(err)
		bugID := bug.keyHash(c.ctx)
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
				ref:   fmt.Sprint(crash.Log),
				url: fmt.Sprintf("/text?tag=CrashLog&x=%v",
					strconv.FormatUint(uint64(crash.Log), 16)),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.Report),
				url:   fmt.Sprintf("/text?tag=CrashReport&id=%v", crash.Report),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.Report),
				url: fmt.Sprintf("/text?tag=CrashReport&x=%v",
					strconv.FormatUint(uint64(crash.Report), 16)),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproC),
				url:   fmt.Sprintf("/text?tag=ReproC&id=%v", crash.ReproC),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproC),
				url: fmt.Sprintf("/text?tag=ReproC&x=%v",
					strconv.FormatUint(uint64(crash.ReproC), 16)),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproSyz),
				url:   fmt.Sprintf("/text?tag=ReproSyz&id=%v", crash.ReproSyz),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproSyz),
				url: fmt.Sprintf("/text?tag=ReproSyz&x=%v",
					strconv.FormatUint(uint64(crash.ReproSyz), 16)),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproLog),
				url:   fmt.Sprintf("/text?tag=ReproLog&id=%v", crash.ReproLog),
			},
			{
				level: level,
				ref:   fmt.Sprint(crash.ReproLog),
				url: fmt.Sprintf("/text?tag=ReproLog&x=%v",
					strconv.FormatUint(uint64(crash.ReproLog), 16)),
			},
			{
				level: nsLevel,
				ref:   fmt.Sprint(crash.MachineInfo),
				url:   fmt.Sprintf("/text?tag=MachineInfo&id=%v", crash.MachineInfo),
			},
			{
				level: nsLevel,
				ref:   fmt.Sprint(crash.MachineInfo),
				url: fmt.Sprintf("/text?tag=MachineInfo&x=%v",
					strconv.FormatUint(uint64(crash.MachineInfo), 16)),
			},
		}...)
	}

	// noteBuildAccessLevel collects all entities associated with the kernel build buildID.
	noteBuildAccessLevel := func(ns, buildID string) {
		build, err := loadBuild(c.ctx, ns, buildID)
		c.expectOK(err)
		entities = append(entities, entity{
			level: c.config().Namespaces[ns].AccessLevel,
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
		for k, v := range c.config().Namespaces[ns].Clients {
			clientName, clientKey = k, v
		}
		nsLevel := c.config().Namespaces[ns].AccessLevel
		namespaceAccessPrefix := accessLevelPrefix(nsLevel)
		client := c.makeClient(clientName, clientKey, true)
		build := testBuild(1)
		build.KernelConfig = []byte(namespaceAccessPrefix + "build")
		client.UploadBuild(build)
		noteBuildAccessLevel(ns, build.ID)

		for reportingIdx := 0; reportingIdx < 2; reportingIdx++ {
			accessLevel := c.config().Namespaces[ns].Reporting[reportingIdx].AccessLevel
			accessPrefix := accessLevelPrefix(accessLevel)

			crashInvalid := testCrashWithRepro(build, reportingIdx*10+0)
			client.ReportCrash(crashInvalid)
			repInvalid := client.pollBug()
			if reportingIdx != 0 {
				client.updateBug(repInvalid.ID, dashapi.BugStatusUpstream, "")
				repInvalid = client.pollBug()
			}
			client.updateBug(repInvalid.ID, dashapi.BugStatusInvalid, "")
			// Invalid bugs become visible up to the last reporting.
			finalLevel := c.config().Namespaces[ns].
				Reporting[len(c.config().Namespaces[ns].Reporting)-1].AccessLevel
			noteBugAccessLevel(repInvalid.ID, finalLevel, nsLevel)

			crashFixed := testCrashWithRepro(build, reportingIdx*10+0)
			client.ReportCrash(crashFixed)
			repFixed := client.pollBug()
			if reportingIdx != 0 {
				client.updateBug(repFixed.ID, dashapi.BugStatusUpstream, "")
				repFixed = client.pollBug()
			}
			reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
				ID:         repFixed.ID,
				Status:     dashapi.BugStatusOpen,
				FixCommits: []string{ns + "-patch0"},
				ExtID:      accessPrefix + "reporting-ext-id",
				Link:       accessPrefix + "reporting-link",
			})
			c.expectEQ(reply.OK, true)
			buildFixing := testBuild(reportingIdx*10 + 2)
			buildFixing.Manager = build.Manager
			buildFixing.Commits = []string{ns + "-patch0"}
			client.UploadBuild(buildFixing)
			noteBuildAccessLevel(ns, buildFixing.ID)
			// Fixed bugs are also visible up to the last reporting.
			noteBugAccessLevel(repFixed.ID, finalLevel, nsLevel)

			crashOpen := testCrashWithRepro(build, reportingIdx*10+0)
			crashOpen.Log = []byte(accessPrefix + "log")
			crashOpen.Report = []byte(accessPrefix + "report")
			crashOpen.ReproC = []byte(accessPrefix + "repro c")
			crashOpen.ReproSyz = []byte(accessPrefix + "repro syz")
			crashOpen.ReproLog = []byte(accessPrefix + "repro log")
			crashOpen.MachineInfo = []byte(ns + "machine info")
			client.ReportCrash(crashOpen)
			repOpen := client.pollBug()
			if reportingIdx != 0 {
				client.updateBug(repOpen.ID, dashapi.BugStatusUpstream, "")
				repOpen = client.pollBug()
			}
			noteBugAccessLevel(repOpen.ID, accessLevel, nsLevel)

			crashPatched := testCrashWithRepro(build, reportingIdx*10+1)
			client.ReportCrash(crashPatched)
			repPatched := client.pollBug()
			if reportingIdx != 0 {
				client.updateBug(repPatched.ID, dashapi.BugStatusUpstream, "")
				repPatched = client.pollBug()
			}
			reply, _ = client.ReportingUpdate(&dashapi.BugUpdate{
				ID:         repPatched.ID,
				Status:     dashapi.BugStatusOpen,
				FixCommits: []string{ns + "-patch0"},
				ExtID:      accessPrefix + "reporting-ext-id",
				Link:       accessPrefix + "reporting-link",
			})
			c.expectEQ(reply.OK, true)
			// Patched bugs are also visible up to the last reporting.
			noteBugAccessLevel(repPatched.ID, finalLevel, nsLevel)

			crashDup := testCrashWithRepro(build, reportingIdx*10+2)
			client.ReportCrash(crashDup)
			repDup := client.pollBug()
			if reportingIdx != 0 {
				client.updateBug(repDup.ID, dashapi.BugStatusUpstream, "")
				repDup = client.pollBug()
			}
			client.updateBug(repDup.ID, dashapi.BugStatusDup, repOpen.ID)
			noteBugAccessLevel(repDup.ID, accessLevel, nsLevel)
		}
	}

	// checkReferences checks that page contents do not contain
	// references to entities that must not be visible.
	checkReferences := func(t *testing.T, url string, requestLevel AccessLevel, reply []byte) {
		for _, ent := range entities {
			if requestLevel >= ent.level || ent.ref == "" {
				continue
			}
			if bytes.Contains(reply, []byte(ent.ref)) {
				t.Errorf("request %v at level %v contains ref %v at level %v:\n%s",
					url, requestLevel, ent.ref, ent.level, reply)
			}
		}
	}

	// checkPage checks that the page at url is accessible/not accessible as required.
	checkPage := func(t *testing.T, requestLevel, pageLevel AccessLevel, url string) []byte {
		reply, err := c.AuthGET(requestLevel, url)
		if requestLevel >= pageLevel {
			assert.NoError(t, err)
		} else if requestLevel == AccessPublic {
			loginURL, err1 := user.LoginURL(c.ctx, url)
			if err1 != nil {
				t.Fatal(err1)
			}
			assert.NotNil(t, err)
			var httpErr *HTTPError
			assert.True(t, errors.As(err, &httpErr))
			assert.Equal(t, httpErr.Code, http.StatusTemporaryRedirect)
			assert.Equal(t, httpErr.Headers["Location"], []string{loginURL})
		} else {
			expectFailureStatus(t, err, http.StatusForbidden)
		}
		return reply
	}

	// Finally, request all entities at all access levels and
	// check that we see only what we need to see.
	for requestLevel := AccessPublic; requestLevel < AccessAdmin; requestLevel++ {
		for i, ent := range entities {
			if ent.url == "" {
				continue
			}
			if testing.Short() && (requestLevel != AccessPublic || ent.level == AccessPublic) {
				// In the short mode, only test that there's no public access to non-public URLs.
				continue
			}
			ent := ent
			t.Run(fmt.Sprintf("level%d_%d", requestLevel, i), func(t *testing.T) {
				reply := checkPage(t, requestLevel, ent.level, ent.url)
				checkReferences(t, ent.url, requestLevel, reply)
			})
		}
	}
}

const (
	BadAuthDomain = iota
	Regular
	Authenticated
	AuthorizedAccessPublic
	AuthorizedUser
	AuthorizedAdmin
)

func makeUser(t int) *user.User {
	u := &user.User{
		AuthDomain:        "gmail.com",
		Admin:             false,
		FederatedIdentity: "",
		FederatedProvider: "",
	}
	switch t {
	case BadAuthDomain:
		u.Email = "customer@syzkaller.com"
		u.AuthDomain = "public.com"
	case Regular:
		u = nil
	case Authenticated:
		u.Email = "someuser@public.com"
	case AuthorizedAccessPublic:
		u.Email = "checked-email@public.com"
	case AuthorizedUser:
		u.Email = "customer@syzkaller.com"
	case AuthorizedAdmin:
		u.Email ="admin@syzkaller.com"
		u.Admin = true
	}
	return u
}

func TestAuthorization(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// BadAuthDomain gives no access.
	assert.False(t, isAuthorizedUserDomain(c.ctx, makeUser(BadAuthDomain)))
	assert.False(t, isAuthorizedPublicEmail(c.ctx, makeUser(BadAuthDomain)))

	// Authentication gives nothing too.
	assert.False(t, isAuthorizedPublicEmail(c.ctx, makeUser(Regular)))
	assert.False(t, isAuthorizedUserDomain(c.ctx, makeUser(Regular)))

	assert.False(t, isAuthorizedUserDomain(c.ctx, makeUser(Authenticated)))
	assert.False(t, isAuthorizedPublicEmail(c.ctx, makeUser(Authenticated)))

	// Authenticated + allowlisted users access w/o throttling.
	assert.False(t, isAuthorizedUserDomain(c.ctx, makeUser(AuthorizedAccessPublic)))
	assert.True(t, isAuthorizedPublicEmail(c.ctx, makeUser(AuthorizedAccessPublic)))
	assert.True(t, isAuthorized(c.ctx))

	// AccessUser gives evetything except admin rights.
	assert.True(t, isAuthorizedUserDomain(c.ctx, makeUser(AuthorizedUser)))
	assert.True(t, isAuthorizedPublicEmail(c.ctx, makeUser(AuthorizedUser)))
}

func TestAccessLevel(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()
	req, err := c.inst.NewRequest("GET", "", nil)
	assert.NoError(t, err)

	aetest.Login(makeUser(BadAuthDomain), req)
	assert.Equal(t, AccessPublic, accessLevel(c.ctx, req))

	aetest.Login(makeUser(Regular), req)
	assert.Equal(t, AccessPublic, accessLevel(c.ctx, req))

	aetest.Login(makeUser(Authenticated), req)
	assert.Equal(t, AccessPublic, accessLevel(c.ctx, req))

	aetest.Login(makeUser(AuthorizedAccessPublic), req)
	assert.Equal(t, AccessPublic, accessLevel(c.ctx, req))

	aetest.Login(makeUser(AuthorizedUser), req)
	assert.Equal(t, AccessUser, accessLevel(c.ctx, req))

	aetest.Login(makeUser(AuthorizedAdmin), req)
	assert.Equal(t, AccessAdmin, accessLevel(c.ctx, req))

}
