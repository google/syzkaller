// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPopulateBuildEnv(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	oldBuild := testBuild(1)
	oldBuild.Manager = specialCCManager
	c.client2.UploadBuild(oldBuild)
	c.client2.ReportCrash(testCrash(oldBuild, 1))

	unreferencedBuild := testBuild(2)
	unreferencedBuild.Manager = "ci-upstream-kasan-gce-root"
	c.client2.UploadBuild(unreferencedBuild)

	c.decommissionManager("test2", specialCCManager, "ci-upstream-kasan-gce-root")

	// Also create a crash on a build with an unknown manager to verify it is skipped without error.
	unknownBuild := testBuild(3)
	unknownBuild.Manager = "unknown-mgr"
	c.client2.UploadBuild(unknownBuild)
	c.client2.ReportCrash(testCrash(unknownBuild, 2))

	_, err := c.GET("/admin?action=populate_build_env")
	require.NoError(t, err)

	dbOldBuild, err := loadBuild(c.ctx, "test2", oldBuild.ID)
	require.NoError(t, err)
	assert.Equal(t, managerBuildEnv["ci-upstream-kasan-gce-root"], dbOldBuild.BuildEnv)

	// unreferencedBuild is not referenced by any open bug, so it should not be backfilled.
	dbUnreferencedBuild, err := loadBuild(c.ctx, "test2", unreferencedBuild.ID)
	require.NoError(t, err)
	assert.Equal(t, BuildEnv{}, dbUnreferencedBuild.BuildEnv)

	dbUnknownBuild, err := loadBuild(c.ctx, "test2", unknownBuild.ID)
	require.NoError(t, err)
	assert.Equal(t, BuildEnv{}, dbUnknownBuild.BuildEnv)
}
