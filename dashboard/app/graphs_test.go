// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestManagersGraphs(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build1 := testBuild(1)
	c.client2.UploadBuild(build1)
	build2 := testBuild(2)
	c.client2.UploadBuild(build2)

	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 100,
		PCs:    1000,
		Cover:  2000,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 200,
		PCs:    2000,
		Cover:  4000,
	}))
	c.advanceTime(25 * time.Hour)
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 110,
		PCs:    1100,
		Cover:  2200,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 220,
		PCs:    2200,
		Cover:  4400,
	}))
	c.advanceTime(25 * time.Hour)
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 150,
		PCs:    1500,
		Cover:  2900,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 270,
		PCs:    2700,
		Cover:  5400,
	}))
	c.advanceTime(25 * time.Hour)
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 50,
		PCs:    500,
		Cover:  900,
	}))
	c.expectOK(c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build2.Manager,
		Corpus: 70,
		PCs:    700,
		Cover:  400,
	}))

	for i := 0; i < 3; i++ {
		c.advanceTime(7 * 25 * time.Hour)
		for j := 0; j <= i; j++ {
			crash := testCrash(build1, i*i+j)
			c.client2.ReportCrash(crash)
		}
	}

	for {
		c.advanceTime(7 * 25 * time.Hour)
		_, err := c.GET("/cron/email_poll")
		c.expectOK(err)
		if len(c.emailSink) == 0 {
			break
		}
		for len(c.emailSink) != 0 {
			<-c.emailSink
		}
	}

	reply, err := c.AuthGET(AccessAdmin, "/test2/graph/bugs")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/lifetimes")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/fuzzing")
	c.expectOK(err)
	// TODO: check reply
	_ = reply

	reply, err = c.AuthGET(AccessAdmin, "/test2/graph/crashes")
	c.expectOK(err)
	// TODO: check reply
	_ = reply
}

func managersGraphFixture(t *testing.T) *Ctx {
	c := NewCtx(t)
	t.Cleanup(c.Close)

	build1 := testBuild(1)
	c.client2.UploadBuild(build1)

	c.client2.UploadManagerStats(&dashapi.ManagerStatsReq{
		Name:   build1.Manager,
		Corpus: 100,
		PCs:    1000,
		Cover:  2000,
	})

	return c
}

func TestManagersGraph_FuzzingMetric_OK_OnValidInput(t *testing.T) {
	c := managersGraphFixture(t)
	_, err := c.AuthGET(AccessAdmin, "/test2/graph/fuzzing?Metrics=MaxCorpus")
	c.expectOK(err)
}

func TestManagersGraph_FuzzingMetric_BadRequest_OnMalformedInput(t *testing.T) {
	c := managersGraphFixture(t)
	_, err := c.AuthGET(AccessAdmin, "/test2/graph/fuzzing?Metrics=MaxCorpus'%2F*%22ZYLQ%22*%2F+AND+'0'%3D'0&Months=27")
	c.expectBadReqest(err)
}
