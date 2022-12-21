// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
)

func TestStraceEffect(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.publicClient
	build := testBuild(1)
	client.UploadBuild(build)

	// A bug with strace.
	crashStrace := testCrashWithRepro(build, 1)
	crashStrace.Flags = dashapi.CrashUnderStrace
	crashStrace.Report = []byte("with strace")
	client.ReportCrash(crashStrace)
	msg1 := c.pollEmailBug()

	// Invalidate it.
	c.advanceTime(time.Hour * 24)
	c.incomingEmail(msg1.Sender, "#syz invalid")

	// Two bugs without strace.

	c.advanceTime(time.Hour * 24 * 365)
	crash := testCrash(build, 2)
	client.ReportCrash(crash)
	msg2 := client.pollEmailBug()

	crash = testCrash(build, 3)
	client.ReportCrash(crash)
	msg3 := c.pollEmailBug()

	// Invalidate one of them quickly.
	c.advanceTime(time.Hour)
	c.incomingEmail(msg2.Sender, "#syz invalid")

	// And the other one later.
	c.advanceTime(time.Hour * 24 * 101)
	c.incomingEmail(msg3.Sender, "#syz invalid")

	// Query the stats.
	inputs, err := allBugInputs(c.ctx, "access-public-email")
	c.expectOK(err)

	stats := newStraceEffect(100)
	for _, input := range inputs {
		stats.Record(input)
	}

	ret := stats.Collect()
	assert.Equal(t, ret, [][]string{
		{"", "Strace", "No Strace"},
		{"Resolved in 100 days", "100.00% (1/1)", "50.00% (1/2)"},
	}, "invalid strace stats results")
}
