// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

// Normal workflow:
//  - upload crash -> need repro
//  - upload syz repro -> still need repro
//  - upload C repro -> don't need repro
func testNeedRepro1(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash, newBug bool) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	resp, _ := c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, true)

	cid := testCrashID(crash1)
	needRepro, _ := c.client.NeedRepro(cid)
	c.expectEQ(needRepro, true)

	// Still need repro for this crash.
	resp, _ = c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, true)
	needRepro, _ = c.client.NeedRepro(cid)
	c.expectEQ(needRepro, true)

	crash2 := new(dashapi.Crash)
	*crash2 = *crash1
	crash2.ReproOpts = []byte("opts")
	crash2.ReproSyz = []byte("repro syz")
	resp, _ = c.client.ReportCrash(crash2)
	c.expectEQ(resp.NeedRepro, true)
	needRepro, _ = c.client.NeedRepro(cid)
	c.expectEQ(needRepro, true)

	crash2.ReproC = []byte("repro C")
	resp, _ = c.client.ReportCrash(crash2)
	c.expectEQ(resp.NeedRepro, false)
	needRepro, _ = c.client.NeedRepro(cid)
	c.expectEQ(needRepro, false)

	resp, _ = c.client.ReportCrash(crash2)
	c.expectEQ(resp.NeedRepro, false)
	if newBug {
		c.client.pollBug()
	}
}

func TestNeedRepro1_normal(t *testing.T)      { testNeedRepro1(t, normalCrash, true) }
func TestNeedRepro1_dup(t *testing.T)         { testNeedRepro1(t, dupCrash, false) }
func TestNeedRepro1_closed(t *testing.T)      { testNeedRepro1(t, closedCrash, true) }
func TestNeedRepro1_closedRepro(t *testing.T) { testNeedRepro1(t, closedWithReproCrash, true) }

// Upload C repro with first crash -> don't need repro.
func testNeedRepro2(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash, newBug bool) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	crash1.ReproOpts = []byte("opts")
	crash1.ReproSyz = []byte("repro syz")
	crash1.ReproC = []byte("repro C")
	resp, _ := c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, false)

	needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, false)
	if newBug {
		c.client.pollBug()
	}
}

func TestNeedRepro2_normal(t *testing.T)      { testNeedRepro2(t, normalCrash, true) }
func TestNeedRepro2_dup(t *testing.T)         { testNeedRepro2(t, dupCrash, false) }
func TestNeedRepro2_closed(t *testing.T)      { testNeedRepro2(t, closedCrash, true) }
func TestNeedRepro2_closedRepro(t *testing.T) { testNeedRepro2(t, closedWithReproCrash, true) }

// Test that after uploading 5 failed repros, app stops requesting repros.
func testNeedRepro3(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	for i := 0; i < maxReproPerBug; i++ {
		resp, _ := c.client.ReportCrash(crash1)
		c.expectEQ(resp.NeedRepro, true)
		needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
		c.expectEQ(needRepro, true)
		c.client.ReportFailedRepro(testCrashID(crash1))
	}

	for i := 0; i < 3; i++ {
		// No more repros today.
		c.advanceTime(time.Hour)
		resp, _ := c.client.ReportCrash(crash1)
		c.expectEQ(resp.NeedRepro, false)
		needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
		c.expectEQ(needRepro, false)

		// Then another repro after a day.
		c.advanceTime(25 * time.Hour)
		for j := 0; j < 2; j++ {
			resp, _ := c.client.ReportCrash(crash1)
			c.expectEQ(resp.NeedRepro, true)
			needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
			c.expectEQ(needRepro, true)
		}
		c.client.ReportFailedRepro(testCrashID(crash1))
	}
}

func TestNeedRepro3_normal(t *testing.T)      { testNeedRepro3(t, normalCrash) }
func TestNeedRepro3_dup(t *testing.T)         { testNeedRepro3(t, dupCrash) }
func TestNeedRepro3_closed(t *testing.T)      { testNeedRepro3(t, closedCrash) }
func TestNeedRepro3_closedRepro(t *testing.T) { testNeedRepro3(t, closedWithReproCrash) }

// Test that after uploading 5 syz repros, app stops requesting repros.
func testNeedRepro4(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash, newBug bool) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	crash1.ReproOpts = []byte("opts")
	crash1.ReproSyz = []byte("repro syz")
	for i := 0; i < maxReproPerBug-1; i++ {
		resp, _ := c.client.ReportCrash(crash1)
		c.expectEQ(resp.NeedRepro, true)
		needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
		c.expectEQ(needRepro, true)
	}

	resp, _ := c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, false)
	needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, false)

	// No more repros even after a day.
	c.advanceTime(25 * time.Hour)
	crash1.ReproOpts = nil
	crash1.ReproSyz = nil

	resp, _ = c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, false)
	needRepro, _ = c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, false)
	if newBug {
		c.client.pollBug()
	}
}

func TestNeedRepro4_normal(t *testing.T)      { testNeedRepro4(t, normalCrash, true) }
func TestNeedRepro4_dup(t *testing.T)         { testNeedRepro4(t, dupCrash, false) }
func TestNeedRepro4_closed(t *testing.T)      { testNeedRepro4(t, closedCrash, true) }
func TestNeedRepro4_closedRepro(t *testing.T) { testNeedRepro4(t, closedWithReproCrash, true) }

func normalCrash(c *Ctx) *dashapi.Crash {
	build := testBuild(1)
	c.client.UploadBuild(build)
	crash := testCrash(build, 1)
	c.client.ReportCrash(crash)
	c.client.pollBug()
	return crash
}

func dupCrash(c *Ctx) *dashapi.Crash {
	build := testBuild(1)
	c.client.UploadBuild(build)
	c.client.ReportCrash(testCrash(build, 1))
	crash2 := testCrash(build, 2)
	c.client.ReportCrash(crash2)
	reports := c.client.pollBugs(2)
	c.client.updateBug(reports[1].ID, dashapi.BugStatusDup, reports[0].ID)
	return crash2
}

func closedCrash(c *Ctx) *dashapi.Crash {
	return closedCrashImpl(c, false)
}

func closedWithReproCrash(c *Ctx) *dashapi.Crash {
	return closedCrashImpl(c, true)
}

func closedCrashImpl(c *Ctx, withRepro bool) *dashapi.Crash {
	build := testBuild(1)
	c.client.UploadBuild(build)

	crash := testCrash(build, 1)
	if withRepro {
		crash.ReproC = []byte("repro C")
	}
	resp, _ := c.client.ReportCrash(crash)
	c.expectEQ(resp.NeedRepro, !withRepro)

	rep := c.client.pollBug()
	c.client.updateBug(rep.ID, dashapi.BugStatusInvalid, "")

	crash.ReproC = nil
	c.client.ReportCrash(crash)
	c.client.pollBug()
	return crash
}
