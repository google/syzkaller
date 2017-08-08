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
					DailyLimit: 3,
					Config:     &TestConfig{},
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

	repro := &dashapi.FailedRepro{
		Manager: "manager1",
		BuildID: "build1",
		Title:   "title1",
	}
	c.expectOK(c.API(client1, key1, "report_failed_repro", repro, nil))

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
