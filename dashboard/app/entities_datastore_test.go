// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

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

func TestPopulateReproTime(t *testing.T) {
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

	// Clear fields and reset StructVersion to simulate legacy bug data before DB update.
	bugKey := bug.key(c.ctx)
	updateSingleBug(c.ctx, bugKey, func(b *Bug) error {
		b.FirstSyzReproTime = time.Time{}
		b.FirstCReproTime = time.Time{}
		b.StructVersion = 1
		return nil
	})

	bugs, _, err = loadAllBugs(c.ctx, nil)
	c.expectOK(err)
	c.expectEQ(bugs[0].FirstSyzReproTime.IsZero(), true)
	c.expectEQ(bugs[0].FirstCReproTime.IsZero(), true)
	c.expectEQ(bugs[0].StructVersion, 1)

	// Trigger admin action to populate repro times.
	_, err = c.AuthGET(AccessAdmin, "/admin?action=populateReproTime")
	c.expectOK(err)

	bugs, _, err = loadAllBugs(c.ctx, nil)
	c.expectOK(err)
	c.expectEQ(bugs[0].FirstSyzReproTime, timeReproSyz)
	c.expectEQ(bugs[0].FirstCReproTime, timeReproC)
	c.expectEQ(bugs[0].StructVersion, bugStructVersion)
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
