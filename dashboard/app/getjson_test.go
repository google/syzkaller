// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestJSONAPIIntegration(t *testing.T) {
	sampleCrashDescr := []byte(`{
	"version": 1,
	"title": "title1",
	"id": "cb1dbe55dc6daa7e739a0d09a0ae4d5e3e5a10c8",
	"crashes": [
		{
			"title": "title1",
			"kernel-config": "/text?tag=KernelConfig\u0026x=a989f27ebc47e2dc",
			"kernel-source-commit": "1111111111111111111111111111111111111111",
			"syzkaller-git": "https://github.com/google/syzkaller/commits/syzkaller_commit1",
			"syzkaller-commit": "syzkaller_commit1",
			"crash-report-link": "/text?tag=CrashReport\u0026x=12000000000000"
		}
	]
}`,
	)

	sampleCrashWithReproDescr := []byte(`{
	"version": 1,
	"title": "title2",
	"id": "fc00fbc0cddd9a4ef2ae33e40cd21636081466ce",
	"crashes": [
		{
			"title": "title2",
			"syz-reproducer": "/text?tag=ReproSyz\u0026x=13000000000000",
			"c-reproducer": "/text?tag=ReproC\u0026x=17000000000000",
			"kernel-config": "/text?tag=KernelConfig\u0026x=a989f27ebc47e2dc",
			"kernel-source-commit": "1111111111111111111111111111111111111111",
			"syzkaller-git": "https://github.com/google/syzkaller/commits/syzkaller_commit1",
			"syzkaller-commit": "syzkaller_commit1",
			"crash-report-link": "/text?tag=CrashReport\u0026x=15000000000000"
		}
	]
}`,
	)

	sampleOpenBugGroupDescr := []byte(`{
	"version": 1,
	"Bugs": [
		{
			"title": "title1",
			"link": "/bug?extid=decf42d66dced481afc1"
		},
		{
			"title": "title2",
			"link": "/bug?extid=0267d1c87b9ed4eb5def"
		}
	]
}`)

	sampleFixedBugGroupDescr := []byte(`{
	"version": 1,
	"Bugs": null
}`)

	c := NewCtx(t)
	defer c.Close()

	c.makeClient(client1, password1, false)

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)
	bugReport1 := c.client.pollBug()
	checkBugPageJSONIs(c, bugReport1.ID, sampleCrashDescr)

	crash2 := testCrashWithRepro(build, 2)
	c.client.ReportCrash(crash2)
	bugReport2 := c.client.pollBug()
	checkBugPageJSONIs(c, bugReport2.ID, sampleCrashWithReproDescr)

	checkBugGroupPageJSONIs(c, "/test1?json=1", sampleOpenBugGroupDescr)
	checkBugGroupPageJSONIs(c, "/test1/fixed?json=1", sampleFixedBugGroupDescr)
}

func checkBugPageJSONIs(c *Ctx, ID string, expectedContent []byte) {
	url := fmt.Sprintf("/bug?extid=%v&json=1", ID)

	contentType, _ := c.client.ContentType(url)
	c.expectEQ(contentType, "application/json")

	actualContent, _ := c.client.GET(url)
	c.expectEQ(string(actualContent), string(expectedContent))
}

func checkBugGroupPageJSONIs(c *Ctx, url string, expectedContent []byte) {
	contentType, _ := c.client.ContentType(url)
	c.expectEQ(contentType, "application/json")

	actualContent, _ := c.client.GET(url)
	c.expectEQ(string(actualContent), string(expectedContent))
}

func TestJSONAPIFixCommits(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client.UploadBuild(build1)

	crash1 := testCrash(build1, 1)
	c.client.ReportCrash(crash1)
	rep1 := c.client.pollBug()

	// Specify fixing commit for the bug.
	c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         rep1.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix1", "foo: fix2"},
	})

	c.client.UploadCommits([]dashapi.Commit{
		{Hash: "hash1", Title: "foo: fix1"},
	})

	c.client.CommitPoll()

	want := []byte(`{
	"version": 1,
	"title": "title1",
	"id": "cb1dbe55dc6daa7e739a0d09a0ae4d5e3e5a10c8",
	"fix-commits": [
		{
			"title": "foo: fix1",
			"hash": "hash1",
			"repo": "git://syzkaller.org",
			"branch": "branch10"
		},
		{
			"title": "foo: fix2",
			"repo": "git://syzkaller.org",
			"branch": "branch10"
		}
	],
	"crashes": [
		{
			"title": "title1",
			"kernel-config": "/text?tag=KernelConfig\u0026x=a989f27ebc47e2dc",
			"kernel-source-commit": "1111111111111111111111111111111111111111",
			"syzkaller-git": "https://github.com/google/syzkaller/commits/syzkaller_commit1",
			"syzkaller-commit": "syzkaller_commit1",
			"crash-report-link": "/text?tag=CrashReport\u0026x=12000000000000"
		}
	]
}`)
	checkBugGroupPageJSONIs(c, "/bug?extid=decf42d66dced481afc1&json=1", want)
}

func TestJSONAPICauseBisection(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build, _ := addBuildAndCrash(c)
	_, bugKey := c.loadSingleBug()

	addBisectCauseJob(c, build)
	addBisectFixJob(c, build)

	url := fmt.Sprintf("/bug?id=%v&json=1", bugKey.StringID())
	content, err := c.GET(url)
	c.expectEQ(err, nil)
	c.expectEQ(string(content), `{
	"version": 1,
	"title": "title1",
	"id": "70ce63ecb151d563976728208edccc6879191f9f",
	"cause-commit": {
		"title": "kernel: add a bug",
		"hash": "36e65cb4a0448942ec316b24d60446bbd5cc7827",
		"repo": "repo1",
		"branch": "branch1"
	},
	"crashes": [
		{
			"title": "title1",
			"syz-reproducer": "/text?tag=ReproSyz\u0026x=16000000000000",
			"c-reproducer": "/text?tag=ReproC\u0026x=11000000000000",
			"kernel-config": "/text?tag=KernelConfig\u0026x=4d11162a90e18f28",
			"kernel-source-commit": "1111111111111111111111111111111111111111",
			"syzkaller-git": "https://github.com/google/syzkaller/commits/syzkaller_commit1",
			"syzkaller-commit": "syzkaller_commit1",
			"crash-report-link": "/text?tag=CrashReport\u0026x=12000000000000"
		}
	]
}`)
}
