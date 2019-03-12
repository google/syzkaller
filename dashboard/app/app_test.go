// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

import (
	"fmt"
	"strconv"
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
		"test1": {
			AccessLevel: AccessAdmin,
			Key:         "test1keytest1keytest1key",
			Clients: map[string]string{
				client1: key1,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org",
					Branch: "branch10",
					Alias:  "repo10alias",
					CC:     []string{"maintainers@repo10.org", "bugs@repo10.org"},
				},
				{
					URL:    "git://github.com/google/syzkaller",
					Branch: "master",
					Alias:  "repo10alias",
					CC:     []string{"maintainers@repo10.org", "bugs@repo10.org"},
				},
			},
			Reporting: []Reporting{
				{
					Name:       "reporting1",
					DailyLimit: 3,
					Embargo:    14 * 24 * time.Hour,
					Filter:     skipWithRepro,
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
		"test2": {
			AccessLevel: AccessAdmin,
			Key:         "test2keytest2keytest2key",
			Clients: map[string]string{
				client2: key2,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org",
					Branch: "branch10",
					Alias:  "repo10alias",
					CC:     []string{"maintainers@repo10.org", "bugs@repo10.org"},
				},
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
					Embargo:    14 * 24 * time.Hour,
					Filter:     skipWithRepro,
					Config: &EmailConfig{
						Email: "test@syzkaller.com",
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
				{
					Name:       "reporting3",
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
		"access-admin": {
			AccessLevel: AccessAdmin,
			Key:         "adminkeyadminkeyadminkey",
			Clients: map[string]string{
				clientAdmin: keyAdmin,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/access-admin.git",
					Branch: "access-admin",
					Alias:  "access-admin",
				},
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
		"access-user": {
			AccessLevel: AccessUser,
			Key:         "userkeyuserkeyuserkey",
			Clients: map[string]string{
				clientUser: keyUser,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/access-user.git",
					Branch: "access-user",
					Alias:  "access-user",
				},
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
		"access-public": {
			AccessLevel: AccessPublic,
			Key:         "publickeypublickeypublickey",
			Clients: map[string]string{
				clientPublic: keyPublic,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/access-public.git",
					Branch: "access-public",
					Alias:  "access-public",
				},
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

func skipWithRepro(bug *Bug) FilterResult {
	if strings.HasPrefix(bug.Title, "skip with repro") &&
		bug.ReproLevel != dashapi.ReproLevelNone {
		return FilterSkip
	}
	return FilterReport
}

type TestConfig struct {
	Index int
}

func (cfg *TestConfig) Type() string {
	return "test"
}

func (cfg *TestConfig) Validate() error {
	return nil
}

func testBuild(id int) *dashapi.Build {
	return &dashapi.Build{
		Manager:           fmt.Sprintf("manager%v", id),
		ID:                fmt.Sprintf("build%v", id),
		OS:                "linux",
		Arch:              "amd64",
		VMArch:            "amd64",
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

// Test purging of old crashes for bugs with lots of crashes.
func TestPurgeOldCrashes(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client.UploadBuild(build)

	// First, send 3 crashes that are reported. These need to be preserved regardless.
	crash := testCrash(build, 1)
	crash.ReproOpts = []byte("no repro")
	c.client.ReportCrash(crash)
	rep := c.client.pollBug()

	crash.ReproSyz = []byte("getpid()")
	crash.ReproOpts = []byte("syz repro")
	c.client.ReportCrash(crash)
	c.client.pollBug()

	crash.ReproC = []byte("int main() {}")
	crash.ReproOpts = []byte("C repro")
	c.client.ReportCrash(crash)
	c.client.pollBug()

	// Now report lots of bugs with/without repros. Some of the older ones should be purged.
	const totalReported = 3 * maxCrashes
	for i := 0; i < totalReported; i++ {
		c.advanceTime(2 * time.Hour) // This ensures that crashes are saved.
		crash.ReproSyz = nil
		crash.ReproC = nil
		crash.ReproOpts = []byte(fmt.Sprintf("%v", i))
		c.client.ReportCrash(crash)

		crash.ReproSyz = []byte("syz repro")
		crash.ReproC = []byte("C repro")
		crash.ReproOpts = []byte(fmt.Sprintf("%v", i))
		c.client.ReportCrash(crash)
	}
	bug, _, _ := c.loadBug(rep.ID)
	crashes, _, err := queryCrashesForBug(c.ctx, bug.key(c.ctx), 10*totalReported)
	c.expectOK(err)
	// First, count how many crashes of different types we have.
	// We should get all 3 reported crashes + some with repros and some without repros.
	reported, norepro, repro := 0, 0, 0
	for _, crash := range crashes {
		if !crash.Reported.IsZero() {
			reported++
		} else if crash.ReproSyz == 0 {
			norepro++
		} else {
			repro++
		}
	}
	c.t.Logf("got reported=%v, norepro=%v, repro=%v, maxCrashes=%v",
		reported, norepro, repro, maxCrashes)
	if reported != 3 ||
		norepro < maxCrashes || norepro > maxCrashes+10 ||
		repro < maxCrashes || repro > maxCrashes+10 {
		c.t.Fatalf("bad purged crashes")
	}
	// Then, check that latest crashes were preserved.
	for _, crash := range crashes {
		if !crash.Reported.IsZero() {
			continue
		}
		idx, err := strconv.Atoi(string(crash.ReproOpts))
		c.expectOK(err)
		count := norepro
		if crash.ReproSyz != 0 {
			count = repro
		}
		if idx < totalReported-count {
			c.t.Errorf("preserved bad crash repro=%v: %v", crash.ReproC != 0, idx)
		}
	}
}
