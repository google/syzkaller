// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeriesProcessor(t *testing.T) {
	emails := []string{
		`Date: Sun, 7 May 2017 19:54:00 -0700
Message-ID: <123>
Subject: test subject
From: Bob <bob@example.com>
To: A <a@a.com>
Cc: B <b@b.com>, C <b@b.com>

first body`,
		`Date: Sun, 7 May 2017 19:55:00 -0700
Message-ID: <234>
Subject: test subject2
From: Bob <bob@example.com>
To: A <a@a.com>
Cc: D <d@d.com>

second body`,
	}
	bodies := []string{"first body", "second body"}

	sp := seriesProcessor{}
	for i, raw := range emails {
		body, err := sp.Process([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, []byte(bodies[i]), body)
	}
	assert.Equal(t, []string{
		"a@a.com", "b@b.com",
		"bob@example.com", "d@d.com",
	}, sp.Emails())
}
