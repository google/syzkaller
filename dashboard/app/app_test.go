// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func init() {
	initMocks()
	installConfig(testConfig)
}

// Config used in tests.
var testConfig = &GlobalConfig{
	AccessLevel: AccessPublic,
	AuthDomain:  "@syzkaller.com",
	Clients: map[string]string{
		"reporting": "reportingkeyreportingkeyreportingkey",
	},
	EmailBlacklist: []string{
		"\"Bar\" <BlackListed@Domain.com>",
	},
	Namespaces: map[string]*Config{
		"test1": &Config{
			AccessLevel: AccessAdmin,
			Key:         "test1keytest1keytest1key",
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
					Filter: func(bug *Bug) FilterResult {
						if strings.HasPrefix(bug.Title, "skip without repro") &&
							bug.ReproLevel != dashapi.ReproLevelNone {
							return FilterSkip
						}
						return FilterReport
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
			AccessLevel: AccessAdmin,
			Key:         "test2keytest2keytest2key",
			Clients: map[string]string{
				client2: key2,
			},
			Managers: map[string]ConfigManager{
				"restricted-manager": {
					RestrictedTestingRepo:   "git://restricted.git/restricted.git",
					RestrictedTestingReason: "you should test only on restricted.git",
				},
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
						Email:              "bugs@syzkaller.com",
						DefaultMaintainers: []string{"default@maintainers.com"},
						MailMaintainers:    true,
					},
				},
			},
		},
		// Namespaces for access level testing.
		"access-admin": &Config{
			AccessLevel: AccessAdmin,
			Key:         "adminkeyadminkeyadminkey",
			Clients: map[string]string{
				clientAdmin: keyAdmin,
			},
			Reporting: []Reporting{
				{
					Name:   "access-admin-reporting1",
					Config: &TestConfig{Index: 1},
				},
				{
					Name:   "access-admin-reporting2",
					Config: &TestConfig{Index: 2},
				},
			},
		},
		"access-user": &Config{
			AccessLevel: AccessUser,
			Key:         "userkeyuserkeyuserkey",
			Clients: map[string]string{
				clientUser: keyUser,
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessAdmin,
					Name:        "access-admin-reporting1",
					Config:      &TestConfig{Index: 1},
				},
				{
					Name:   "access-user-reporting2",
					Config: &TestConfig{Index: 2},
				},
			},
		},
		"access-public": &Config{
			AccessLevel: AccessPublic,
			Key:         "publickeypublickeypublickey",
			Clients: map[string]string{
				clientPublic: keyPublic,
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessUser,
					Name:        "access-user-reporting1",
					Config:      &TestConfig{Index: 1},
				},
				{
					Name:   "access-public-reporting2",
					Config: &TestConfig{Index: 2},
				},
			},
		},
	},
}

const (
	client1      = "client1"
	client2      = "client2"
	key1         = "client1keyclient1keyclient1key"
	key2         = "client2keyclient2keyclient2key"
	clientAdmin  = "client-admin"
	keyAdmin     = "clientadminkeyclientadminkey"
	clientUser   = "client-user"
	keyUser      = "clientuserkeyclientuserkey"
	clientPublic = "client-public"
	keyPublic    = "clientpublickeyclientpublickey"
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
		Manager:           fmt.Sprintf("manager%v", id),
		ID:                fmt.Sprintf("build%v", id),
		SyzkallerCommit:   fmt.Sprintf("syzkaller_commit%v", id),
		CompilerID:        fmt.Sprintf("compiler%v", id),
		KernelRepo:        fmt.Sprintf("repo%v", id),
		KernelBranch:      fmt.Sprintf("branch%v", id),
		KernelCommit:      strings.Repeat(fmt.Sprint(id), 40)[:40],
		KernelCommitTitle: fmt.Sprintf("kernel_commit_title%v", id),
		KernelCommitDate:  buildCommitDate,
		KernelConfig:      []byte(fmt.Sprintf("config%v", id)),
	}
}

var buildCommitDate = time.Date(1, 2, 3, 4, 5, 6, 0, time.UTC)

func testCrash(build *dashapi.Build, id int) *dashapi.Crash {
	return &dashapi.Crash{
		BuildID: build.ID,
		Title:   fmt.Sprintf("title%v", id),
		Log:     []byte(fmt.Sprintf("log%v", id)),
		Report:  []byte(fmt.Sprintf("report%v", id)),
	}
}

func testCrashWithRepro(build *dashapi.Build, id int) *dashapi.Crash {
	crash := testCrash(build, id)
	crash.ReproOpts = []byte(fmt.Sprintf("repro opts %v", id))
	crash.ReproSyz = []byte(fmt.Sprintf("syncfs(%v)", id))
	crash.ReproC = []byte(fmt.Sprintf("int main() { return %v; }", id))
	return crash
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

	apiClient1 := c.makeClient(client1, key1, false)
	apiClient2 := c.makeClient(client2, key2, false)
	c.expectFail("unknown api method", apiClient1.Query("unsupported_method", nil, nil))
	c.client.LogError("name", "msg %s", "arg")

	build := testBuild(1)
	c.client.UploadBuild(build)
	// Uploading the same build must be OK.
	c.client.UploadBuild(build)

	// Some bad combinations of client/key.
	c.expectFail("unauthorized", c.makeClient(client1, "", false).Query("upload_build", build, nil))
	c.expectFail("unauthorized", c.makeClient("unknown", key1, false).Query("upload_build", build, nil))
	c.expectFail("unauthorized", c.makeClient(client1, key2, false).Query("upload_build", build, nil))

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)

	// Test that namespace isolation works.
	c.expectFail("unknown build", apiClient2.Query("report_crash", crash1, nil))

	crash2 := testCrashWithRepro(build, 2)
	c.client.ReportCrash(crash2)

	// Provoke purgeOldCrashes.
	for i := 0; i < 30; i++ {
		crash := testCrash(build, 3)
		crash.Log = []byte(fmt.Sprintf("log%v", i))
		crash.Report = []byte(fmt.Sprintf("report%v", i))
		c.client.ReportCrash(crash)
	}

	cid := &dashapi.CrashID{
		BuildID: "build1",
		Title:   "title1",
	}
	c.client.ReportFailedRepro(cid)

	c.client.ReportingPollBugs("test")

	c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:         "id",
		Status:     dashapi.BugStatusOpen,
		ReproLevel: dashapi.ReproLevelC,
	})
}

// Normal workflow:
//  - upload crash -> need repro
//  - upload syz repro -> still need repro
//  - upload C repro -> don't need repro
func testNeedRepro1(t *testing.T, crashCtor func(c *Ctx) *dashapi.Crash) {
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
	resp, _ := c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, false)

	needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, false)
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
	for i := 0; i < maxReproPerBug; i++ {
		resp, _ := c.client.ReportCrash(crash1)
		c.expectEQ(resp.NeedRepro, true)

		needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
		c.expectEQ(needRepro, true)
		c.client.ReportFailedRepro(testCrashID(crash1))
	}

	resp, _ := c.client.ReportCrash(crash1)
	c.expectEQ(resp.NeedRepro, false)

	needRepro, _ := c.client.NeedRepro(testCrashID(crash1))
	c.expectEQ(needRepro, false)
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
}

func TestNeedRepro4_normal(t *testing.T)      { testNeedRepro4(t, normalCrash) }
func TestNeedRepro4_dup(t *testing.T)         { testNeedRepro4(t, dupCrash) }
func TestNeedRepro4_closed(t *testing.T)      { testNeedRepro4(t, closedCrash) }
func TestNeedRepro4_closedRepro(t *testing.T) { testNeedRepro4(t, closedWithReproCrash) }

func normalCrash(c *Ctx) *dashapi.Crash {
	build := testBuild(1)
	c.client.UploadBuild(build)
	return testCrash(build, 1)
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
	return crash
}
