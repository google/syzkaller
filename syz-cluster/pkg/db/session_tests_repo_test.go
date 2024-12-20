// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSessionTestRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionsRepository(client)
	seriesRepo := NewSeriesRepository(client)
	testsRepo := NewSessionTestRepository(client)
	buildRepo := NewBuildRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	session := &Session{CreatedAt: time.Now()}
	err = sessionRepo.InsertSession(ctx, series, session)
	assert.NoError(t, err)

	build1 := &Build{TreeName: "mainline", Arch: "amd64", CommitHash: "abcd", Status: "success"}
	err = buildRepo.Insert(ctx, build1)
	assert.NoError(t, err)
	build2 := &Build{TreeName: "mainline", Arch: "amd64", CommitHash: "efgh", Status: "success"}
	err = buildRepo.Insert(ctx, build2)
	assert.NoError(t, err)

	// Add several tests.
	for i := 0; i < 2; i++ {
		test := &SessionTest{
			SessionID:      session.ID,
			TestName:       fmt.Sprintf("test %d", i),
			BaseBuildID:    build1.ID,
			PatchedBuildID: build2.ID,
			Result:         TestPassed,
		}
		err = testsRepo.Insert(ctx, test)
		assert.NoError(t, err)
	}

	list, err := testsRepo.BySession(ctx, session.ID)
	assert.NoError(t, err)
	assert.Len(t, list, 2)
}
