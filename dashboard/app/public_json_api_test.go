// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/api"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestJSONAPIIntegration(t *testing.T) {
	sampleCrashDescr := []byte(`{
	"version": 1,
	"title": "title1",
	"id": "cb1dbe55dc6daa7e739a0d09a0ae4d5e3e5a10c8",
	"status": "reporting1: reported on 2000/01/01 00:01",
	"first-crash": "2000-01-01T00:01:00Z",
	"last-crash": "2000-01-01T00:01:00Z",
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
	"status": "reporting1: reported C repro on 2000/01/01 00:01",
	"first-crash": "2000-01-01T00:01:00Z",
	"last-crash": "2000-01-01T00:01:00Z",
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
	"Bugs": [
		{
			"title": "title2",
			"link": "/bug?extid=0267d1c87b9ed4eb5def",
			"fix-commits": [
				{
					"title": "foo: fix1",
					"repo": "git://syzkaller.org",
					"branch": "branch10"
				},
				{
					"title": "foo: fix2",
					"repo": "git://syzkaller.org",
					"branch": "branch10"
				}
			]
		}
	]
}`)

	c := NewCtx(t)
	defer c.Close()

	c.makeClient(client1, password1, false)

	build := testBuild(1)
	c.client.UploadBuild(build)

	crash1 := testCrash(build, 1)
	c.advanceTime(time.Minute)
	c.client.ReportCrash(crash1)
	bugReport1 := c.client.pollBug()
	checkBugPageJSONIs(c, bugReport1.ID, sampleCrashDescr)

	crash2 := testCrashWithRepro(build, 2)
	c.client.ReportCrash(crash2)
	bugReport2 := c.client.pollBug()
	checkBugPageJSONIs(c, bugReport2.ID, sampleCrashWithReproDescr)

	checkBugGroupPageJSONIs(c, "/test1?json=1", sampleOpenBugGroupDescr)

	c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         bugReport2.ID,
		Status:     dashapi.BugStatusOpen,
		FixCommits: []string{"foo: fix1", "foo: fix2"},
	})

	checkBugGroupPageJSONIs(c, "/test1/fixed?json=1", sampleFixedBugGroupDescr)
}

func checkBugPageJSONIs(c *Ctx, ID string, expectedContent []byte) {
	c.t.Helper()
	url := fmt.Sprintf("/bug?extid=%v&json=1", ID)

	contentType, _ := c.client.ContentType(url)
	c.expectEQ(contentType, "application/json")

	actualContent, _ := c.client.GET(url)
	c.expectEQ(string(actualContent), string(expectedContent))
}

func checkBugGroupPageJSONIs(c *Ctx, url string, expectedContent []byte) {
	c.t.Helper()
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
	c.advanceTime(time.Hour)
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
	"status": "reporting1: reported on 2000/01/01 00:00",
	"first-crash": "2000-01-01T00:00:00Z",
	"last-crash": "2000-01-01T00:00:00Z",
	"fix-time": "2000-01-01T01:00:00Z",
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
	"status": "reporting2: reported C repro on 2000/01/31 00:00",
	"first-crash": "2000-01-01T00:00:00Z",
	"last-crash": "2000-01-01T00:00:00Z",
	"cause-commit": {
		"title": "kernel: add a bug",
		"hash": "36e65cb4a0448942ec316b24d60446bbd5cc7827",
		"repo": "repo1",
		"branch": "branch1",
		"date": "2000-02-09T04:05:06Z"
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

func TestPublicJSONAPI(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublic, keyPublic, true)
	build := testBuild(1)
	client.UploadBuild(build)
	client.ReportCrash(testCrashWithRepro(build, 1))
	rep := client.pollBug()
	client.updateBug(rep.ID, dashapi.BugStatusUpstream, "")
	_ = client.pollBug()

	cli := c.makeAPIClient()
	bugs, err := cli.BugGroups("access-public", api.BugGroupAll)
	c.expectOK(err)
	c.expectEQ(len(bugs), 1)
	c.expectEQ(bugs[0].Title, "title1")

	bug, err := cli.Bug(bugs[0].Link)
	c.expectOK(err)
	c.expectEQ(bug.Title, "title1")

	config, err := cli.Text(bug.Crashes[0].KernelConfigLink)
	c.expectOK(err)
	c.expectEQ(config, []byte("config1"))
}

func TestWriteExtAPICoverageFor(t *testing.T) {
	ctx := setCoverageDBClient(context.Background(), fileFuncLinesDBFixture(t,
		[]*coveragedb.FuncLines{
			{
				FilePath: "/file",
				FuncName: "func_name",
				Lines:    []int64{1, 2, 3, 4},
			},
		},
		[]*coveragedb.FileCoverageWithLineInfo{
			{
				FileCoverageWithDetails: coveragedb.FileCoverageWithDetails{
					Filepath: "/file",
					Commit:   "test-commit",
				},
				LinesInstrumented: []int64{1, 2, 3, 4},
				HitCounts:         []int64{10, 20, 30, 0},
			},
		},
	))

	var buf bytes.Buffer
	err := writeExtAPICoverageFor(ctx, &buf, "test-ns", "test-repo", nil)
	assert.NoError(t, err)
	assert.Equal(t, `{
	"repo": "test-repo",
	"commit": "test-commit",
	"file_path": "/file",
	"functions": [
		{
			"func_name": "func_name",
			"blocks": [
				{
					"hit_count": 10,
					"from_line": 1,
					"from_column": 0,
					"to_line": 1,
					"to_column": -1
				},
				{
					"hit_count": 20,
					"from_line": 2,
					"from_column": 0,
					"to_line": 2,
					"to_column": -1
				},
				{
					"hit_count": 30,
					"from_line": 3,
					"from_column": 0,
					"to_line": 3,
					"to_column": -1
				},
				{
					"from_line": 4,
					"from_column": 0,
					"to_line": 4,
					"to_column": -1
				}
			]
		}
	]
}
`, buf.String())
}

func fileFuncLinesDBFixture(t *testing.T, funcLines []*coveragedb.FuncLines,
	fileCovWithLineInfo []*coveragedb.FileCoverageWithLineInfo) spannerclient.SpannerClient {
	mPartialTran := mocks.NewReadOnlyTransaction(t)
	mPartialTran.On("Query", mock.Anything, mock.Anything).
		Return(newRowIteratorMock(t, funcLines)).Once()

	mFullTran := mocks.NewReadOnlyTransaction(t)
	mFullTran.On("Query", mock.Anything, mock.Anything).
		Return(newRowIteratorMock(t, fileCovWithLineInfo)).Once()

	m := mocks.NewSpannerClient(t)
	m.On("Single").
		Return(mPartialTran).Once()
	m.On("Single").
		Return(mFullTran).Once()
	return m
}
