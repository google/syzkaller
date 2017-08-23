// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

// Config used in tests.
var config = GlobalConfig{
	AuthDomain: "@foo.com",
	Clients: map[string]string{
		"reporting": "reportingkeyreportingkeyreportingkey",
	},
	Namespaces: map[string]*Config{
		"test1": &Config{
			Key: "test1keytest1keytest1key",
			Clients: map[string]string{
				client1: key1,
			},
			Reporting: []Reporting{
				{
					Name:       "reporting1",
					DailyLimit: 3,
					Config: &TestConfig{
						Index: 1,
					},
				},
				{
					Name:       "reporting2",
					DailyLimit: 3,
					Config: &TestConfig{
						Index: 2,
					},
				},
			},
		},
		"test2": &Config{
			Key: "test2keytest2keytest2key",
			Clients: map[string]string{
				client2: key2,
			},
			Reporting: []Reporting{
				{
					Name:       "reporting1",
					DailyLimit: 5,
					Config: &EmailConfig{
						Email:      "test@syzkaller.com",
						Moderation: true,
					},
				},
				{
					Name:       "reporting2",
					DailyLimit: 3,
					Config: &EmailConfig{
						Email:           "bugs@syzkaller.com",
						MailMaintainers: true,
					},
				},
			},
		},
	},
}

const (
	client1 = "client1"
	client2 = "client2"
	key1    = "client1keyclient1keyclient1key"
	key2    = "client2keyclient2keyclient2key"
)

type TestConfig struct {
	Index int
}

func (cfg *TestConfig) Type() string {
	return "test"
}

func (cfg *TestConfig) NeedMaintainers() bool {
	return false
}

func (cfg *TestConfig) Validate() error {
	return nil
}

func testBuild(id int) *dashapi.Build {
	return &dashapi.Build{
		Manager:         fmt.Sprintf("manager%v", id),
		ID:              fmt.Sprintf("build%v", id),
		SyzkallerCommit: fmt.Sprintf("syzkaller_commit%v", id),
		CompilerID:      fmt.Sprintf("compiler%v", id),
		KernelRepo:      fmt.Sprintf("repo%v", id),
		KernelBranch:    fmt.Sprintf("branch%v", id),
		KernelCommit:    fmt.Sprintf("kernel_commit%v", id),
		KernelConfig:    []byte(fmt.Sprintf("config%v", id)),
	}
}

func testCrash(build *dashapi.Build, id int) *dashapi.Crash {
	return &dashapi.Crash{
		BuildID: build.ID,
		Title:   fmt.Sprintf("title%v", id),
		Log:     []byte(fmt.Sprintf("log%v", id)),
		Report:  []byte(fmt.Sprintf("report%v", id)),
	}
}

func testCrashID(crash *dashapi.Crash) *dashapi.CrashID {
	return &dashapi.CrashID{
		BuildID: crash.BuildID,
		Title:   crash.Title,
	}
}

func TestApp(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	c.expectOK(c.GET("/"))

	c.expectFail("unknown api method", c.API(client1, key1, "unsupported_method", nil, nil))

	ent := &dashapi.LogEntry{
		Name: "name",
		Text: "text",
	}
	c.expectOK(c.API(client1, key1, "log_error", ent, nil))

	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))
	// Uploading the same build must be OK.
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	// Some bad combinations of client/key.
	c.expectFail("unauthorized request", c.API(client1, "", "upload_build", build, nil))
	c.expectFail("unauthorized request", c.API("unknown", key1, "upload_build", build, nil))
	c.expectFail("unauthorized request", c.API(client1, key2, "upload_build", build, nil))

	crash1 := &dashapi.Crash{
		BuildID:     "build1",
		Title:       "title1",
		Maintainers: []string{`"Foo Bar" <foo@bar.com>`, `bar@foo.com`},
		Log:         []byte("log1"),
		Report:      []byte("report1"),
	}
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	// Test that namespace isolation works.
	c.expectFail("unknown build", c.API(client2, key2, "report_crash", crash1, nil))

	crash2 := &dashapi.Crash{
		BuildID:     "build1",
		Title:       "title2",
		Maintainers: []string{`bar@foo.com`},
		Log:         []byte("log2"),
		Report:      []byte("report2"),
		ReproOpts:   []byte("opts"),
		ReproSyz:    []byte("syz repro"),
		ReproC:      []byte("c repro"),
	}
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	// Provoke purgeOldCrashes.
	for i := 0; i < 30; i++ {
		crash := &dashapi.Crash{
			BuildID:     "build1",
			Title:       "title1",
			Maintainers: []string{`bar@foo.com`},
			Log:         []byte(fmt.Sprintf("log%v", i)),
			Report:      []byte(fmt.Sprintf("report%v", i)),
		}
		c.expectOK(c.API(client1, key1, "report_crash", crash, nil))
	}

	cid := &dashapi.CrashID{
		BuildID: "build1",
		Title:   "title1",
	}
	c.expectOK(c.API(client1, key1, "report_failed_repro", cid, nil))

	pr := &dashapi.PollRequest{
		Type: "test",
	}
	resp := new(dashapi.PollResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))

	cmd := &dashapi.BugUpdate{
		ID:         "id",
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelC,
		DupOf:      "",
	}
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, nil))
}

// Normal workflow:
//  - upload crash -> need repro
//  - upload syz repro -> still need repro
//  - upload C repro -> don't need repro
func testNeedRepro1(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	resp := new(dashapi.ReportCrashResp)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, true)

	cid := testCrashID(crash1)
	needReproResp := new(dashapi.NeedReproResp)
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, true)

	// Still need repro for this crash.
	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, true)
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, true)

	crash2 := new(dashapi.Crash)
	*crash2 = *crash1
	crash2.ReproOpts = []byte("opts")
	crash2.ReproSyz = []byte("repro syz")
	c.expectOK(c.API(client1, key1, "report_crash", crash2, resp))
	c.expectEQ(resp.NeedRepro, true)
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, true)

	crash2.ReproC = []byte("repro C")
	c.expectOK(c.API(client1, key1, "report_crash", crash2, resp))
	c.expectEQ(resp.NeedRepro, false)
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, false)

	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, false)
}

func TestNeedRepro1_normal(t *testing.T)      { testNeedRepro1(t, normalCrash) }
func TestNeedRepro1_dup(t *testing.T)         { testNeedRepro1(t, dupCrash) }
func TestNeedRepro1_closed(t *testing.T)      { testNeedRepro1(t, closedCrash) }
func TestNeedRepro1_closedRepro(t *testing.T) { testNeedRepro1(t, closedWithReproCrash) }

// Upload C repro with first crash -> don't need repro.
func testNeedRepro2(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	crash1.ReproOpts = []byte("opts")
	crash1.ReproSyz = []byte("repro syz")
	crash1.ReproC = []byte("repro C")
	resp := new(dashapi.ReportCrashResp)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, false)

	cid := testCrashID(crash1)
	needReproResp := new(dashapi.NeedReproResp)
	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, false)
}

func TestNeedRepro2_normal(t *testing.T)      { testNeedRepro2(t, normalCrash) }
func TestNeedRepro2_dup(t *testing.T)         { testNeedRepro2(t, dupCrash) }
func TestNeedRepro2_closed(t *testing.T)      { testNeedRepro2(t, closedCrash) }
func TestNeedRepro2_closedRepro(t *testing.T) { testNeedRepro2(t, closedWithReproCrash) }

// Test that after uploading 5 failed repros, app stops requesting repros.
func testNeedRepro3(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	resp := new(dashapi.ReportCrashResp)
	cid := testCrashID(crash1)
	needReproResp := new(dashapi.NeedReproResp)

	for i := 0; i < 5; i++ {
		c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
		c.expectEQ(resp.NeedRepro, true)

		c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
		c.expectEQ(needReproResp.NeedRepro, true)

		c.expectOK(c.API(client1, key1, "report_failed_repro", cid, nil))
	}

	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, false)

	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, false)
}

func TestNeedRepro3_normal(t *testing.T)      { testNeedRepro3(t, normalCrash) }
func TestNeedRepro3_dup(t *testing.T)         { testNeedRepro3(t, dupCrash) }
func TestNeedRepro3_closed(t *testing.T)      { testNeedRepro3(t, closedCrash) }
func TestNeedRepro3_closedRepro(t *testing.T) { testNeedRepro3(t, closedWithReproCrash) }

// Test that after uploading 5 syz repros, app stops requesting repros.
func testNeedRepro4(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	crash1.ReproOpts = []byte("opts")
	crash1.ReproSyz = []byte("repro syz")
	resp := new(dashapi.ReportCrashResp)
	cid := testCrashID(crash1)
	needReproResp := new(dashapi.NeedReproResp)

	for i := 0; i < 4; i++ {
		c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
		c.expectEQ(resp.NeedRepro, true)

		c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
		c.expectEQ(needReproResp.NeedRepro, true)
	}

	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, false)

	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, false)
}

func TestNeedRepro4_normal(t *testing.T)      { testNeedRepro4(t, normalCrash) }
func TestNeedRepro4_dup(t *testing.T)         { testNeedRepro4(t, dupCrash) }
func TestNeedRepro4_closed(t *testing.T)      { testNeedRepro4(t, closedCrash) }
func TestNeedRepro4_closedRepro(t *testing.T) { testNeedRepro4(t, closedWithReproCrash) }

func testNeedRepro5(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
	c := NewCtx(t)
	defer c.Close()

	crash1 := crashCtor(c)
	crash1.ReproOpts = []byte("opts")
	crash1.ReproSyz = []byte("repro syz")
	resp := new(dashapi.ReportCrashResp)
	cid := testCrashID(crash1)
	needReproResp := new(dashapi.NeedReproResp)

	for i := 0; i < 4; i++ {
		c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
		c.expectEQ(resp.NeedRepro, true)

		c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
		c.expectEQ(needReproResp.NeedRepro, true)
	}

	c.expectOK(c.API(client1, key1, "report_crash", crash1, resp))
	c.expectEQ(resp.NeedRepro, false)

	c.expectOK(c.API(client1, key1, "need_repro", cid, needReproResp))
	c.expectEQ(needReproResp.NeedRepro, false)
}

func TestNeedRepro5_normal(t *testing.T)      { testNeedRepro5(t, normalCrash) }
func TestNeedRepro5_dup(t *testing.T)         { testNeedRepro5(t, dupCrash) }
func TestNeedRepro5_closed(t *testing.T)      { testNeedRepro5(t, closedCrash) }
func TestNeedRepro5_closedRepro(t *testing.T) { testNeedRepro5(t, closedWithReproCrash) }

func normalCrash(c *Ctx) *dashapi.Crash {
	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))
	return testCrash(build, 1)
}

func dupCrash(c *Ctx) *dashapi.Crash {
	build := testBuild(1)
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash1 := testCrash(build, 1)
	c.expectOK(c.API(client1, key1, "report_crash", crash1, nil))

	crash2 := testCrash(build, 2)
	c.expectOK(c.API(client1, key1, "report_crash", crash2, nil))

	pr := &dashapi.PollRequest{
		Type: "test",
	}
	resp := new(dashapi.PollResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, resp))
	c.expectEQ(len(resp.Reports), 2)
	rep1 := resp.Reports[0]
	rep2 := resp.Reports[1]
	cmd := &dashapi.BugUpdate{
		ID:     rep2.ID,
		Status: dashapi.BugStatusDup,
		DupOf:  rep1.ID,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

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
	c.expectOK(c.API(client1, key1, "upload_build", build, nil))

	crash := testCrash(build, 1)
	if withRepro {
		crash.ReproC = []byte("repro C")
	}
	resp := new(dashapi.ReportCrashResp)
	c.expectOK(c.API(client1, key1, "report_crash", crash, resp))
	c.expectEQ(resp.NeedRepro, !withRepro)

	pr := &dashapi.PollRequest{
		Type: "test",
	}
	pollResp := new(dashapi.PollResponse)
	c.expectOK(c.API(client1, key1, "reporting_poll", pr, pollResp))
	c.expectEQ(len(pollResp.Reports), 1)
	rep := pollResp.Reports[0]
	cmd := &dashapi.BugUpdate{
		ID:     rep.ID,
		Status: dashapi.BugStatusInvalid,
	}
	reply := new(dashapi.BugUpdateReply)
	c.expectOK(c.API(client1, key1, "reporting_update", cmd, reply))
	c.expectEQ(reply.OK, true)

	crash.ReproC = nil
	return crash
}
