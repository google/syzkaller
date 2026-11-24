// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	db "google.golang.org/appengine/v2/datastore"
)

func TestOldBugTagsConversion(t *testing.T) {
	oldBug := &struct {
		Namespace string
		Title     string
		Tags      BugTags202304
	}{
		Namespace: "some-ns",
		Title:     "some title",
		Tags: BugTags202304{
			Subsystems: []BugTag202304{
				{
					Name:  "first",
					SetBy: "user",
				},
				{
					Name: "second",
				},
			},
		},
	}

	fields, err := db.SaveStruct(oldBug)
	if err != nil {
		t.Fatal(err)
	}

	newBug := &Bug{}
	err = newBug.Load(fields)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, &Bug{
		Namespace: "some-ns",
		Title:     "some title",
		Labels: []BugLabel{
			{
				Value: "first",
				SetBy: "user",
				Label: SubsystemLabel,
			},
			{
				Value: "second",
				Label: SubsystemLabel,
			},
		},
	}, newBug)
}

func TestReportCrashReproTime(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	// Report first crash without repro.
	crash1 := testCrash(build, 1)
	c.client2.ReportCrash(crash1)

	c.advanceTime(24 * time.Hour)
	timeReproSyz := c.mockedTime

	// Report second crash with Syz repro.
	crash2 := testCrash(build, 1)
	crash2.ReproOpts = []byte("opts")
	crash2.ReproSyz = []byte("repro syz")
	c.client2.ReportCrash(crash2)

	c.advanceTime(24 * time.Hour)
	timeReproC := c.mockedTime

	// Report third crash with C repro.
	crash3 := testCrash(build, 1)
	crash3.ReproOpts = []byte("opts")
	crash3.ReproC = []byte("repro c")
	c.client2.ReportCrash(crash3)

	bugs, _, err := loadAllBugs(c.ctx, nil)
	c.expectOK(err)
	c.expectEQ(len(bugs), 1)
	bug := bugs[0]

	// Verify real-time setting of FirstSyzReproTime and FirstCReproTime.
	c.expectEQ(bug.FirstSyzReproTime, timeReproSyz)
	c.expectEQ(bug.FirstCReproTime, timeReproC)
}

func TestUpdateReproLevel(t *testing.T) {
	now := time.Date(2023, 5, 10, 12, 0, 0, 0, time.UTC)
	bug := &Bug{}

	// Updating with no repro should not set times.
	bug.UpdateReproLevel(false, false, now)
	require.True(t, bug.FirstCReproTime.IsZero())
	require.True(t, bug.FirstSyzReproTime.IsZero())

	// Adding Syz repro.
	tSyz := now
	bug.UpdateReproLevel(false, true, tSyz)
	require.True(t, bug.HasSyzRepro)
	require.Equal(t, tSyz, bug.FirstSyzReproTime)

	// Later Syz repro should not overwrite FirstSyzReproTime.
	later := now.Add(24 * time.Hour)
	bug.UpdateReproLevel(false, true, later)
	require.Equal(t, tSyz, bug.FirstSyzReproTime)

	// Adding C repro.
	tC := now.Add(12 * time.Hour)
	bug.UpdateReproLevel(true, false, tC)
	require.True(t, bug.HasCRepro)
	require.Equal(t, tC, bug.FirstCReproTime)
}

func TestBuildEnv(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	env1 := dashapi.BuildEnv{
		VMType:      "gce",
		MachineType: "e2-standard-2",
	}
	build1.BuildEnv = env1
	c.client2.UploadBuild(build1)
	dbBuild1, err := loadBuild(c.ctx, "test2", build1.ID)
	require.NoError(t, err)
	assert.Equal(t, BuildEnv(env1), dbBuild1.BuildEnv)
}

func TestLoadIgnoresUnknownProperties(t *testing.T) {
	t.Run("Bug", func(t *testing.T) {
		props := []db.Property{
			{Name: "Namespace", Value: "test-ns"},
			{Name: "Title", Value: "KASAN: slab-out-of-bounds"},
			{Name: "FutureIntField", Value: int64(2)},
			{Name: "FutureNested.Sub", Value: "val"},
		}
		bug := &Bug{}
		require.NoError(t, bug.Load(props))
		assert.Equal(t, "test-ns", bug.Namespace)
		assert.Equal(t, "KASAN: slab-out-of-bounds", bug.Title)

		badProps := []db.Property{
			{Name: "Title", Value: int64(42)},
		}
		var mismatch *db.ErrFieldMismatch
		require.ErrorAs(t, (&Bug{}).Load(badProps), &mismatch)
	})

	t.Run("Job", func(t *testing.T) {
		orig := &Job{
			Type:      JobTestPatch,
			Namespace: "test-ns",
			Manager:   "ci-kasan",
			BugTitle:  "BUG: test",
		}
		props, err := orig.Save()
		require.NoError(t, err)
		props = append(props,
			db.Property{Name: "FutureAIJobID", Value: "job-123"},
			db.Property{Name: "FutureFlag", Value: true},
		)

		loaded := &Job{}
		require.NoError(t, loaded.Load(props))
		assert.Equal(t, orig, loaded)

		badProps := []db.Property{
			{Name: "Manager", Value: int64(42)},
		}
		var mismatch *db.ErrFieldMismatch
		require.ErrorAs(t, (&Job{}).Load(badProps), &mismatch)
	})
}
