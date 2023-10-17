// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
)

func TestClientSecretOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "secr1t",
		},
	}, "user", "secr1t", "")
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientOauthOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "OauthSubject:public",
		},
	}, "user", "", "OauthSubject:public")
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientSecretFail(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "secr1t",
		},
	}, "user", "wrong", "")
	if err != ErrAccess || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientSecretMissing(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{},
	}, "user", "ignored", "")
	if err != ErrAccess || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientNamespaceOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Namespaces: map[string]*Config{
			"ns1": {
				Clients: map[string]string{
					"user": "secr1t",
				},
			},
		},
	}, "user", "secr1t", "")
	if err != nil || got != "ns1" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestContinueFuzzing(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	manager := "next-fuzzing"
	// First emulate a failing build.
	ret, err := client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *testManagerBuild(1, manager),
		Crash: dashapi.Crash{
			Title: "failed build",
		},
	})
	c.expectOK(err)
	assert.False(t, ret.ContinueFuzzing)

	// Then a successful build.
	client.UploadBuild(testManagerBuild(2, manager))

	// The limit is 3 days, so assume we failed a build in 2 days.
	c.advanceTime(2 * 24 * time.Hour)
	ret, err = client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *testManagerBuild(3, manager),
		Crash: dashapi.Crash{
			Title: "failed build",
		},
	})
	c.expectOK(err)
	assert.True(t, ret.ContinueFuzzing) // Fuzzing should continue.

	// In 2 days, we tried once more and still failed.
	c.advanceTime(2 * 24 * time.Hour)
	ret, err = client.ReportBuildError(&dashapi.BuildErrorReq{
		Build: *testManagerBuild(4, manager),
		Crash: dashapi.Crash{
			Title: "failed build",
		},
	})
	c.expectOK(err)
	assert.False(t, ret.ContinueFuzzing) // No more fuzzing.
}

// If there's no limit for the manager, fuzzing continues forever.
func TestAlwaysContinueFuzzing(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	client := c.client
	manager := "some-manager"

	// First a successful build.
	client.UploadBuild(testManagerBuild(1, manager))

	// Then a few failures.
	for i := 0; i < 3; i++ {
		c.advanceTime(7 * 24 * time.Hour)
		ret, err := client.ReportBuildError(&dashapi.BuildErrorReq{
			Build: *testManagerBuild(2+i, manager),
			Crash: dashapi.Crash{
				Title: "failed build",
			},
		})
		c.expectOK(err)
		// But we continue fuzzing.
		assert.True(t, ret.ContinueFuzzing)
	}
}
