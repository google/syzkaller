// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
)

func TestCachedBugGroups(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublic, keyPublic, true)
	build := testBuild(1)
	client.UploadBuild(build)

	// Bug at the first (AccessUser) stage of reporting.
	crash := testCrash(build, 1)
	crash.Title = "user-visible bug"
	client.ReportCrash(crash)
	client.pollBug()

	// Bug at the second (AccessPublic) stage.
	crash2 := testCrash(build, 2)
	crash2.Title = "public-visible bug"
	client.ReportCrash(crash2)
	client.updateBug(client.pollBug().ID, dashapi.BugStatusUpstream, "")
	client.pollBug()

	// Add a build in a separate namespace (to check it's not mixed in).
	client2 := c.makeClient(clientPublicEmail2, keyPublicEmail2, true)
	build2 := testBuild(2)
	client2.UploadBuild(build2)
	client2.ReportCrash(testCrash(build2, 1))
	client2.pollEmailBug()

	// Output before caching.
	before := map[AccessLevel][]*uiBugGroup{}
	for _, accessLevel := range []AccessLevel{AccessPublic, AccessUser} {
		orig, err := fetchNamespaceBugs(c.ctx, accessLevel, "access-public", nil)
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, orig)
		before[accessLevel] = orig
	}

	// Update cache.
	_, err := c.AuthGET(AccessAdmin, "/cron/minute_cache_update")
	c.expectOK(err)

	// Now query the groups from cache.
	for _, accessLevel := range []AccessLevel{AccessPublic, AccessUser} {
		cached, err := CachedBugGroups(c.ctx, "access-public", accessLevel)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, before[accessLevel], cached)
		// Ensure that the web dashboard page loads after cache is set.
		_, err = c.AuthGET(accessLevel, "/access-public")
		c.expectOK(err)
	}
}

// Ensure we can serve pages with empty cache.
func TestBugListWithoutCache(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	assert.True(t, getNsConfig(c.ctx, "access-public").CacheUIPages)
	for _, accessLevel := range []AccessLevel{AccessPublic, AccessUser, AccessAdmin} {
		_, err := c.AuthGET(accessLevel, "/access-public")
		c.expectOK(err)
	}
}
