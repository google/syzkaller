// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
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

func TestSubsystemFilterMain(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	subsystemA, subsystemB := "subsystemA", "subsystemB"

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "first bug"
	c.contextVars[overrideSubsystemsKey] = []string{subsystemA}
	client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	c.contextVars[overrideSubsystemsKey] = []string{subsystemB}
	crash2.Title = "second bug"
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
	reply, err = c.AuthGET(AccessAdmin, "/test1?subsystem="+subsystemA)
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

	subsystemA, subsystemB := "subsystemA", "subsystemB"

	client := c.client
	build := testBuild(1)
	client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "first bug"
	c.contextVars[overrideSubsystemsKey] = []string{subsystemA}
	client.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	c.contextVars[overrideSubsystemsKey] = []string{subsystemB}
	crash2.Title = "second bug"
	client.ReportCrash(crash2)

	// Invalidate all these bugs.
	polledBugs := client.pollBugs(2)
	for _, bug := range polledBugs {
		client.updateBug(bug.ID, dashapi.BugStatusInvalid, "")
	}

	// Verify that the filtering works on the invalid bugs page.
	reply, err := c.AuthGET(AccessAdmin, "/test1/invalid?subsystem="+subsystemB)
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
