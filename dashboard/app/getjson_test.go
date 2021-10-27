// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
)

func TestJSONAPIIntegration(t *testing.T) {
	sampleCrashDescr := []byte(`{
	"version": 1,
	"title": "title1",
	"crashes": [
		{
			"kernel-config": "/text?tag=KernelConfig\u0026x=a989f27ebc47e2dc",
			"kernel-source-commit": "1111111111111111111111111111111111111111",
			"syzkaller-git": "https://github.com/google/syzkaller/commits/syzkaller_commit1",
			"syzkaller-commit": "syzkaller_commit1"
		}
	]
}`,
	)

	sampleCrashWithReproDescr := []byte(`{
	"version": 1,
	"title": "title2",
	"crashes": [
		{
			"syz-reproducer": "/text?tag=ReproSyz\u0026x=13000000000000",
			"c-reproducer": "/text?tag=ReproC\u0026x=17000000000000",
			"kernel-config": "/text?tag=KernelConfig\u0026x=a989f27ebc47e2dc",
			"kernel-source-commit": "1111111111111111111111111111111111111111",
			"syzkaller-git": "https://github.com/google/syzkaller/commits/syzkaller_commit1",
			"syzkaller-commit": "syzkaller_commit1"
		}
	]
}`,
	)

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
}

func checkBugPageJSONIs(c *Ctx, ID string, expectedContent []byte) {
	url := fmt.Sprintf("/bug?extid=%v&json=1", ID)

	contentType, _ := c.client.ContentType(url)
	c.expectEQ(contentType, "application/json")

	actualContent, _ := c.client.GET(url)
	c.expectEQ(string(actualContent), string(expectedContent))
}
