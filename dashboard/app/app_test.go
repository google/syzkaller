// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/syzkaller/sys/targets"
	"google.golang.org/appengine/v2/user"
)

func init() {
	// This is ugly but without this go test hangs with:
	// panic: Metadata fetch failed for 'instance/attributes/gae_backend_version':
	//	Get http://metadata/computeMetadata/v1/instance/attributes/gae_backend_version:
	//	dial tcp: lookup metadata on 127.0.0.1:53: no such host
	// It's unclear what's the proper fix for this.
	os.Setenv("GAE_MODULE_VERSION", "1")
	os.Setenv("GAE_MINOR_VERSION", "1")

	isBrokenAuthDomainInTest = true
	obsoleteWhatWontBeFixBisected = true
	notifyAboutUnsuccessfulBisections = true
	ensureConfigImmutability = true
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
	EmailBlocklist: []string{
		"\"Bar\" <Blocked@Domain.com>",
	},
	Obsoleting: ObsoletingConfig{
		MinPeriod:         80 * 24 * time.Hour,
		MaxPeriod:         100 * 24 * time.Hour,
		NonFinalMinPeriod: 40 * 24 * time.Hour,
		NonFinalMaxPeriod: 60 * 24 * time.Hour,
		ReproRetestPeriod: 100 * 24 * time.Hour,
	},
	DiscussionEmails: []DiscussionEmailConfig{
		{"lore@email.com", dashapi.DiscussionLore},
	},
	DefaultNamespace: "test1",
	Namespaces: map[string]*Config{
		"test1": {
			AccessLevel:           AccessAdmin,
			Key:                   "test1keytest1keytest1key",
			FixBisectionAutoClose: true,
			SimilarityDomain:      testDomain,
			Clients: map[string]string{
				client1: password1,
				"oauth": auth.OauthMagic + "111111122222222",
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org",
					Branch: "branch10",
					Alias:  "repo10alias",
					CC: CCConfig{
						Maintainers: []string{"maintainers@repo10.org", "bugs@repo10.org"},
					},
				},
				{
					URL:    "git://github.com/google/syzkaller",
					Branch: "master",
					Alias:  "repo10alias1",
					CC: CCConfig{
						Maintainers: []string{"maintainers@repo10.org", "bugs@repo10.org"},
					},
				},
				{
					URL:    "git://github.com/google/syzkaller",
					Branch: "old_master",
					Alias:  "repo10alias2",
					NoPoll: true,
				},
			},
			Managers: map[string]ConfigManager{
				"special-obsoleting": {
					ObsoletingMinPeriod: 10 * 24 * time.Hour,
					ObsoletingMaxPeriod: 20 * 24 * time.Hour,
				},
			},
			Reporting: []Reporting{
				{
					Name:       "reporting1",
					DailyLimit: 5,
					Embargo:    14 * 24 * time.Hour,
					Filter:     skipWithRepro,
					Config: &TestConfig{
						Index: 1,
					},
				},
				{
					Name:       "reporting2",
					DailyLimit: 5,
					Config: &TestConfig{
						Index: 2,
					},
				},
			},
			Subsystems: SubsystemsConfig{
				Service: subsystem.MustMakeService(testSubsystems),
			},
		},
		"test2": {
			AccessLevel:      AccessAdmin,
			Key:              "test2keytest2keytest2key",
			SimilarityDomain: testDomain,
			Clients: map[string]string{
				client2: password2,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org",
					Branch: "branch10",
					Alias:  "repo10alias",
					CC: CCConfig{
						Always:           []string{"always@cc.me"},
						Maintainers:      []string{"maintainers@repo10.org", "bugs@repo10.org"},
						BuildMaintainers: []string{"build-maintainers@repo10.org"},
					},
				},
				{
					URL:    "git://syzkaller.org",
					Branch: "branch20",
					Alias:  "repo20",
					CC: CCConfig{
						Maintainers: []string{"maintainers@repo20.org", "bugs@repo20.org"},
					},
				},
			},
			Managers: map[string]ConfigManager{
				noFixBisectionManager: {
					FixBisectionDisabled: true,
				},
				specialCCManager: {
					CC: CCConfig{
						Always:           []string{"always@manager.org"},
						Maintainers:      []string{"maintainers@manager.org"},
						BuildMaintainers: []string{"build-maintainers@manager.org"},
					},
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
					Filter:     skipWithRepro2,
					Config: &EmailConfig{
						Email:              "bugs@syzkaller.com",
						DefaultMaintainers: []string{"default@maintainers.com"},
						SubjectPrefix:      "[syzbot]",
						MailMaintainers:    true,
					},
				},
				{
					Name:       "reporting3",
					DailyLimit: 3,
					Config: &EmailConfig{
						Email:              "bugs2@syzkaller.com",
						DefaultMaintainers: []string{"default2@maintainers.com"},
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
					Name:       "access-admin-reporting1",
					DailyLimit: 1000,
					Config:     &TestConfig{Index: 1},
				},
				{
					Name:       "access-admin-reporting2",
					DailyLimit: 1000,
					Config:     &TestConfig{Index: 2},
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
					DailyLimit:  1000,
					Config:      &TestConfig{Index: 1},
				},
				{
					Name:       "access-user-reporting2",
					DailyLimit: 1000,
					Config:     &TestConfig{Index: 2},
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
					URL:                    "git://syzkaller.org/access-public.git",
					Branch:                 "access-public",
					Alias:                  "access-public",
					DetectMissingBackports: true,
				},
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessUser,
					Name:        "access-user-reporting1",
					DailyLimit:  1000,
					Config:      &TestConfig{Index: 1},
				},
				{
					Name:       "access-public-reporting2",
					DailyLimit: 1000,
					Config:     &TestConfig{Index: 2},
				},
			},
			FindBugOriginTrees: true,
			CacheUIPages:       true,
			RetestRepros:       true,
		},
		"access-public-email": {
			AccessLevel: AccessPublic,
			Key:         "publickeypublickeypublickey",
			Clients: map[string]string{
				clientPublicEmail: keyPublicEmail,
			},
			Managers: map[string]ConfigManager{
				restrictedManager: {
					RestrictedTestingRepo:   "git://restricted.git/restricted.git",
					RestrictedTestingReason: "you should test only on restricted.git",
				},
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/access-public-email.git",
					Branch: "access-public-email",
					Alias:  "access-public-email",
				},
				{
					// Needed for TestTreeOriginLtsBisection().
					URL:    "https://upstream.repo/repo",
					Branch: "upstream-master",
					Alias:  "upstream-master",
				},
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessPublic,
					Name:        "access-public-email-reporting1",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:            "test@syzkaller.com",
						HandleListEmails: true,
						SubjectPrefix:    "[syzbot]",
					},
				},
			},
			RetestRepros: true,
			Subsystems: SubsystemsConfig{
				Service: subsystem.MustMakeService(testSubsystems),
				Redirect: map[string]string{
					"oldSubsystem": "subsystemA",
				},
			},
		},
		// The second namespace reporting to the same mailing list.
		"access-public-email-2": {
			AccessLevel: AccessPublic,
			Key:         "publickeypublickeypublickey",
			Clients: map[string]string{
				clientPublicEmail2: keyPublicEmail2,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/access-public-email2.git",
					Branch: "access-public-email2",
					Alias:  "access-public-email2",
				},
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessPublic,
					Name:        "access-public-email2-reporting1",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:            "test@syzkaller.com",
						HandleListEmails: true,
					},
				},
			},
		},
		"fs-bugs-reporting": {
			AccessLevel: AccessPublic,
			Key:         "fspublickeypublickeypublickey",
			Clients: map[string]string{
				clientPublicFs: keyPublicFs,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/fs-bugs.git",
					Branch: "fs-bugs",
					Alias:  "fs-bugs",
				},
			},
			Reporting: []Reporting{
				{
					Name:       "wait-repro",
					DailyLimit: 1000,
					Filter: func(bug *Bug) FilterResult {
						if canBeVfsBug(bug) &&
							bug.ReproLevel == dashapi.ReproLevelNone {
							return FilterReport
						}
						return FilterSkip
					},
					Config: &TestConfig{Index: 1},
				},
				{
					AccessLevel: AccessPublic,
					Name:        "public",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:              "test@syzkaller.com",
						HandleListEmails:   true,
						DefaultMaintainers: []string{"linux-kernel@vger.kernel.org"},
						MailMaintainers:    true,
						SubjectPrefix:      "[syzbot]",
					},
				},
			},
			Subsystems: SubsystemsConfig{
				Service: subsystem.ListService("linux"),
			},
		},
		"test-decommission": {
			AccessLevel:      AccessAdmin,
			Key:              "testdecommissiontestdecommission",
			SimilarityDomain: testDomain,
			Clients: map[string]string{
				clientTestDecomm: keyTestDecomm,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org",
					Branch: "branch10",
					Alias:  "repo10alias",
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
		"test-mgr-decommission": {
			AccessLevel:      AccessAdmin,
			Key:              "testmgrdecommissiontestmgrdecommission",
			SimilarityDomain: testDomain,
			Clients: map[string]string{
				clientMgrDecommission: keyMgrDecommission,
			},
			Managers: map[string]ConfigManager{
				notYetDecommManger: {},
				delegateToManager:  {},
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org",
					Branch: "branch10",
					Alias:  "repo10alias",
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
					Filter:     skipWithRepro2,
					Config: &EmailConfig{
						Email:              "bugs@syzkaller.com",
						DefaultMaintainers: []string{"default@maintainers.com"},
						SubjectPrefix:      "[syzbot]",
						MailMaintainers:    true,
					},
				},
			},
			RetestRepros: true,
		},
		"subsystem-reminders": {
			AccessLevel: AccessPublic,
			Key:         "subsystemreminderssubsystemreminders",
			Clients: map[string]string{
				clientSubsystemRemind: keySubsystemRemind,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://syzkaller.org/reminders.git",
					Branch: "main",
					Alias:  "main",
				},
			},
			Reporting: []Reporting{
				{
					// Let's emulate public moderation.
					AccessLevel: AccessPublic,
					Name:        "moderation",
					DailyLimit:  1000,
					Filter: func(bug *Bug) FilterResult {
						if strings.Contains(bug.Title, "keep in moderation") {
							return FilterReport
						}
						return FilterSkip
					},
					Config: &TestConfig{Index: 1},
				},
				{
					AccessLevel: AccessPublic,
					Name:        "public",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:              "bugs@syzkaller.com",
						HandleListEmails:   true,
						MailMaintainers:    true,
						DefaultMaintainers: []string{"default@maintainers.com"},
						SubjectPrefix:      "[syzbot]",
					},
				},
			},
			Subsystems: SubsystemsConfig{
				Service: subsystem.MustMakeService(testSubsystems),
				Reminder: &BugListReportingConfig{
					SourceReporting: "public",
					BugsInReport:    6,
					ModerationConfig: &EmailConfig{
						Email:         "moderation@syzkaller.com",
						SubjectPrefix: "[moderation]",
					},
					Config: &EmailConfig{
						Email:           "bugs@syzkaller.com",
						MailMaintainers: true,
						SubjectPrefix:   "[syzbot]",
					},
				},
			},
		},
		"tree-tests": {
			AccessLevel:           AccessPublic,
			FixBisectionAutoClose: true,
			Key:                   "treeteststreeteststreeteststreeteststreeteststreetests",
			Clients: map[string]string{
				clientTreeTests: keyTreeTests,
			},
			Repos: []KernelRepo{
				{
					URL:                    "git://syzkaller.org/test.git",
					Branch:                 "main",
					Alias:                  "main",
					DetectMissingBackports: true,
				},
			},
			Managers: map[string]ConfigManager{
				"better-manager": {
					Priority: 1,
				},
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessAdmin,
					Name:        "non-public",
					DailyLimit:  1000,
					Filter: func(bug *Bug) FilterResult {
						return FilterReport
					},
					Config: &TestConfig{Index: 1},
				},
				{
					AccessLevel: AccessUser,
					Name:        "user",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:         "bugs@syzkaller.com",
						SubjectPrefix: "[syzbot]",
					},
					Labels: map[string]string{
						"origin:downstream": "Bug presence analysis results: the bug reproduces only on the downstream tree.",
					},
				},
			},
			FindBugOriginTrees:     true,
			RetestMissingBackports: true,
		},
	},
}

var testSubsystems = []*subsystem.Subsystem{
	{
		Name:        "subsystemA",
		PathRules:   []subsystem.PathRule{{IncludeRegexp: `a\.c`}},
		Lists:       []string{"subsystemA@list.com"},
		Maintainers: []string{"subsystemA@person.com"},
	},
	{
		Name:        "subsystemB",
		PathRules:   []subsystem.PathRule{{IncludeRegexp: `b\.c`}},
		Lists:       []string{"subsystemB@list.com"},
		Maintainers: []string{"subsystemB@person.com"},
	},
	{
		Name:        "subsystemC",
		PathRules:   []subsystem.PathRule{{IncludeRegexp: `c\.c`}},
		Lists:       []string{"subsystemC@list.com"},
		Maintainers: []string{"subsystemC@person.com"},
		NoReminders: true,
	},
}

const (
	client1               = "client1"
	client2               = "client2"
	password1             = "client1keyclient1keyclient1key"
	password2             = "client2keyclient2keyclient2key"
	clientAdmin           = "client-admin"
	keyAdmin              = "clientadminkeyclientadminkey"
	clientUser            = "client-user"
	keyUser               = "clientuserkeyclientuserkey"
	clientPublic          = "client-public"
	keyPublic             = "clientpublickeyclientpublickey"
	clientPublicEmail     = "client-public-email"
	keyPublicEmail        = "clientpublicemailkeyclientpublicemailkey"
	clientPublicEmail2    = "client-public-email2"
	keyPublicEmail2       = "clientpublicemailkeyclientpublicemailkey2"
	clientPublicFs        = "client-public-fs"
	keyPublicFs           = "keypublicfskeypublicfskeypublicfs"
	clientTestDecomm      = "client-test-decomm"
	keyTestDecomm         = "keyTestDecommkeyTestDecomm"
	clientMgrDecommission = "client-mgr-decommission"
	keyMgrDecommission    = "keyMgrDecommissionkeyMgrDecommission"
	clientSubsystemRemind = "client-subystem-reminders"
	keySubsystemRemind    = "keySubsystemRemindkeySubsystemRemind"
	clientTreeTests       = "clientTreeTestsclientTreeTests"
	keyTreeTests          = "keyTreeTestskeyTreeTestskeyTreeTests"

	restrictedManager     = "restricted-manager"
	noFixBisectionManager = "no-fix-bisection-manager"
	specialCCManager      = "special-cc-manager"
	notYetDecommManger    = "not-yet-decomm-manager"
	delegateToManager     = "delegate-to-manager"

	testDomain = "test"
)

func skipWithRepro(bug *Bug) FilterResult {
	if strings.HasPrefix(bug.Title, "skip with repro") &&
		bug.ReproLevel != dashapi.ReproLevelNone {
		return FilterSkip
	}
	return FilterReport
}

func skipWithRepro2(bug *Bug) FilterResult {
	if strings.HasPrefix(bug.Title, "skip reporting2 with repro") &&
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
		OS:                targets.Linux,
		Arch:              targets.AMD64,
		VMArch:            targets.AMD64,
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
		BuildID:     build.ID,
		Title:       fmt.Sprintf("title%v", id),
		Log:         []byte(fmt.Sprintf("log%v", id)),
		Report:      []byte(fmt.Sprintf("report%v", id)),
		MachineInfo: []byte(fmt.Sprintf("machine info %v", id)),
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

	_, err := c.GET("/test1")
	c.expectOK(err)

	apiClient1 := c.makeClient(client1, password1, false)
	apiClient2 := c.makeClient(client2, password2, false)
	c.expectFail("unknown api method", apiClient1.Query("unsupported_method", nil, nil))
	c.client.LogError("name", "msg %s", "arg")

	build := testBuild(1)
	c.client.UploadBuild(build)
	// Uploading the same build must be OK.
	c.client.UploadBuild(build)

	// Some bad combinations of client/key.
	c.expectFail("unauthorized", c.makeClient(client1, "borked", false).Query("upload_build", build, nil))
	c.expectFail("unauthorized", c.makeClient("unknown", password1, false).Query("upload_build", build, nil))
	c.expectFail("unauthorized", c.makeClient(client1, password2, false).Query("upload_build", build, nil))

	crash1 := testCrash(build, 1)
	c.client.ReportCrash(crash1)
	c.client.pollBug()

	// Test that namespace isolation works.
	c.expectFail("unknown build", apiClient2.Query("report_crash", crash1, nil))

	crash2 := testCrashWithRepro(build, 2)
	c.client.ReportCrash(crash2)
	c.client.pollBug()

	// Provoke purgeOldCrashes.
	const purgeTestIters = 30
	for i := 0; i < purgeTestIters; i++ {
		// Also test how daily counts work.
		if i == purgeTestIters/2 {
			c.advanceTime(48 * time.Hour)
		}
		crash := testCrash(build, 3)
		crash.Log = []byte(fmt.Sprintf("log%v", i))
		crash.Report = []byte(fmt.Sprintf("report%v", i))
		c.client.ReportCrash(crash)
	}
	rep := c.client.pollBug()
	bug, _, _ := c.loadBug(rep.ID)
	c.expectNE(bug, nil)
	c.expectEQ(bug.DailyStats, []BugDailyStats{
		{20000101, purgeTestIters / 2},
		{20000103, purgeTestIters / 2},
	})

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

func TestRedirects(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	checkRedirect(c, AccessUser, "/", "/test1", http.StatusFound) // redirect to default namespace
	checkRedirect(c, AccessAdmin, "/", "/admin", http.StatusFound)
	checkLoginRedirect(c, AccessPublic, "/access-user") // not accessible namespace

	_, err := c.AuthGET(AccessUser, "/access-user")
	c.expectOK(err)
}

func TestResponseStatusCode(t *testing.T) {
	tests := []struct {
		whatURL      string
		wantRespCode int
	}{
		{
			"/text?tag=CrashLog&x=13354bf5700000",
			http.StatusNotFound,
		},
		{
			"/text?tag=CrashReport&x=17a2bedcb00000",
			http.StatusNotFound,
		},
		{
			"/text?tag=ReproSyz&x=107e219b700000",
			http.StatusNotFound,
		},
		{
			"/text?tag=ReproC&x=1762ad64f00000",
			http.StatusNotFound,
		},
		{
			"/text?tag=CrashLog",
			http.StatusBadRequest,
		},
		{
			"/text?tag=CrashReport",
			http.StatusBadRequest,
		},
		{
			"/text?tag=ReproC",
			http.StatusBadRequest,
		},
		{
			"/text?tag=ReproSyz",
			http.StatusBadRequest,
		},
	}

	c := NewCtx(t)
	defer c.Close()

	for _, test := range tests {
		checkResponseStatusCode(c, AccessUser, test.whatURL, test.wantRespCode)
	}
}

func checkLoginRedirect(c *Ctx, accessLevel AccessLevel, url string) {
	to, err := user.LoginURL(c.ctx, url)
	if err != nil {
		c.t.Fatal(err)
	}
	checkRedirect(c, accessLevel, url, to, http.StatusTemporaryRedirect)
}

func checkRedirect(c *Ctx, accessLevel AccessLevel, from, to string, status int) {
	_, err := c.AuthGET(accessLevel, from)
	c.expectNE(err, nil)
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, status)
	c.expectEQ(httpErr.Headers["Location"], []string{to})
}

func checkResponseStatusCode(c *Ctx, accessLevel AccessLevel, url string, status int) {
	_, err := c.AuthGET(accessLevel, url)
	c.expectNE(err, nil)
	var httpErr *HTTPError
	c.expectTrue(errors.As(err, &httpErr))
	c.expectEQ(httpErr.Code, status)
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
	var totalReported = 3 * maxCrashes()
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
		reported, norepro, repro, maxCrashes())
	if reported != 3 ||
		norepro < maxCrashes() || norepro > maxCrashes()+10 ||
		repro < maxCrashes() || repro > maxCrashes()+10 {
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

	firstCrashExists := func() bool {
		_, crashKeys, err := queryCrashesForBug(c.ctx, bug.key(c.ctx), 10*totalReported)
		c.expectOK(err)
		for _, key := range crashKeys {
			if key.IntID() == rep.CrashID {
				return true
			}
		}
		return false
	}

	// A sanity check for the test itself.
	if !firstCrashExists() {
		t.Fatalf("the first reported crash should be present")
	}

	// Unreport the first crash.
	reply, _ := c.client.ReportingUpdate(&dashapi.BugUpdate{
		ID:               rep.ID,
		Status:           dashapi.BugStatusUpdate,
		ReproLevel:       dashapi.ReproLevelC,
		UnreportCrashIDs: []int64{rep.CrashID},
	})
	c.expectEQ(reply.OK, true)

	// Trigger more purge events.
	var moreIterations = maxCrashes()
	for i := 0; i < moreIterations; i++ {
		c.advanceTime(2 * time.Hour) // This ensures that crashes are saved.
		crash.ReproSyz = nil
		crash.ReproC = nil
		crash.ReproOpts = []byte(fmt.Sprintf("%v", i))
		c.client.ReportCrash(crash)
	}
	// Check that the unreported crash was purged.
	if firstCrashExists() {
		t.Fatalf("the unreported crash should have been purged")
	}
}

func TestManagerFailedBuild(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Upload and check first build.
	build := testBuild(1)
	c.client.UploadBuild(build)
	checkManagerBuild(c, build, nil, nil)

	// Upload and check second build.
	build.ID = "id1"
	build.KernelCommit = "kern1"
	build.SyzkallerCommit = "syz1"
	c.client.UploadBuild(build)
	checkManagerBuild(c, build, nil, nil)

	// Upload failed kernel build.
	failedBuild := new(dashapi.Build)
	*failedBuild = *build
	failedBuild.ID = "id2"
	failedBuild.KernelCommit = "kern2"
	failedBuild.KernelCommitTitle = "failed build 1"
	failedBuild.SyzkallerCommit = "syz2"
	c.expectOK(c.client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *failedBuild,
		Crash: dashapi.Crash{
			Title: "failed build 1",
		},
	}))
	checkManagerBuild(c, build, failedBuild, nil)

	// Now the old good build again, nothing should change.
	c.client.UploadBuild(build)
	checkManagerBuild(c, build, failedBuild, nil)

	// New good kernel build, failed build must reset.
	build.ID = "id3"
	build.KernelCommit = "kern3"
	c.client.UploadBuild(build)
	checkManagerBuild(c, build, nil, nil)

	// Now more complex scenario: OK -> failed kernel -> failed kernel+syzkaller -> failed syzkaller -> OK.
	failedBuild.ID = "id4"
	failedBuild.KernelCommit = "kern4"
	failedBuild.KernelCommitTitle = "failed build 4"
	failedBuild.SyzkallerCommit = "syz4"
	c.expectOK(c.client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *failedBuild,
		Crash: dashapi.Crash{
			Title: "failed build 4",
		},
	}))
	checkManagerBuild(c, build, failedBuild, nil)

	failedBuild2 := new(dashapi.Build)
	*failedBuild2 = *failedBuild
	failedBuild2.ID = "id5"
	failedBuild2.KernelCommit = ""
	failedBuild2.KernelCommitTitle = "failed build 5"
	failedBuild2.SyzkallerCommit = "syz5"
	c.expectOK(c.client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *failedBuild2,
		Crash: dashapi.Crash{
			Title: "failed build 5",
		},
	}))
	checkManagerBuild(c, build, failedBuild, failedBuild2)

	build.ID = "id6"
	build.KernelCommit = "kern6"
	c.client.UploadBuild(build)
	checkManagerBuild(c, build, nil, failedBuild2)

	build.ID = "id7"
	build.KernelCommit = "kern6"
	build.SyzkallerCommit = "syz7"
	c.client.UploadBuild(build)
	checkManagerBuild(c, build, nil, nil)
}

func checkManagerBuild(c *Ctx, build, failedKernelBuild, failedSyzBuild *dashapi.Build) {
	mgr, dbBuild := c.loadManager("test1", build.Manager)
	c.expectEQ(mgr.CurrentBuild, build.ID)
	compareBuilds(c, dbBuild, build)
	checkBuildBug(c, mgr.FailedBuildBug, failedKernelBuild)
	checkBuildBug(c, mgr.FailedSyzBuildBug, failedSyzBuild)
}

func checkBuildBug(c *Ctx, hash string, build *dashapi.Build) {
	if build == nil {
		c.expectEQ(hash, "")
		return
	}
	c.expectNE(hash, "")
	bug, _, dbBuild := c.loadBugByHash(hash)
	c.expectEQ(bug.Title, build.KernelCommitTitle)
	compareBuilds(c, dbBuild, build)
}

func compareBuilds(c *Ctx, dbBuild *Build, build *dashapi.Build) {
	c.expectEQ(dbBuild.ID, build.ID)
	c.expectEQ(dbBuild.KernelCommit, build.KernelCommit)
	c.expectEQ(dbBuild.SyzkallerCommit, build.SyzkallerCommit)
}

func TestLinkifyReport(t *testing.T) {
	input := `
 tipc_topsrv_stop net/tipc/topsrv.c:694 [inline]
 tipc_topsrv_exit_net+0x149/0x340 net/tipc/topsrv.c:715
kernel BUG at fs/ext4/inode.c:2753!
pkg/sentry/fsimpl/fuse/fusefs.go:278 +0x384
 kvm_vcpu_release+0x4d/0x70 arch/x86/kvm/../../../virt/kvm/kvm_main.c:3713
	arch/x86/entry/entry_64.S:298
[<81751700>] (show_stack) from [<8176d3e0>] (dump_stack_lvl+0x48/0x54 lib/dump_stack.c:106)
`
	// nolint: lll
	output := `
 tipc_topsrv_stop <a href='https://github.com/google/syzkaller/blob/111222/net/tipc/topsrv.c#L694'>net/tipc/topsrv.c:694</a> [inline]
 tipc_topsrv_exit_net+0x149/0x340 <a href='https://github.com/google/syzkaller/blob/111222/net/tipc/topsrv.c#L715'>net/tipc/topsrv.c:715</a>
kernel BUG at <a href='https://github.com/google/syzkaller/blob/111222/fs/ext4/inode.c#L2753'>fs/ext4/inode.c:2753</a>!
<a href='https://github.com/google/syzkaller/blob/111222/pkg/sentry/fsimpl/fuse/fusefs.go#L278'>pkg/sentry/fsimpl/fuse/fusefs.go:278</a> +0x384
 kvm_vcpu_release+0x4d/0x70 <a href='https://github.com/google/syzkaller/blob/111222/arch/x86/kvm/../../../virt/kvm/kvm_main.c#L3713'>arch/x86/kvm/../../../virt/kvm/kvm_main.c:3713</a>
	<a href='https://github.com/google/syzkaller/blob/111222/arch/x86/entry/entry_64.S#L298'>arch/x86/entry/entry_64.S:298</a>
[&lt;81751700&gt;] (show_stack) from [&lt;8176d3e0&gt;] (dump_stack_lvl+0x48/0x54 <a href='https://github.com/google/syzkaller/blob/111222/lib/dump_stack.c#L106'>lib/dump_stack.c:106</a>)
`
	got := linkifyReport([]byte(input), "https://github.com/google/syzkaller", "111222")
	if diff := cmp.Diff(output, string(got)); diff != "" {
		t.Fatal(diff)
	}
}
