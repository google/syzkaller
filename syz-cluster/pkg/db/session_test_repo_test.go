// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"fmt"
	"testing"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestSessionTestRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	sessionRepo := NewSessionRepository(client)
	seriesRepo := NewSeriesRepository(client)
	testsRepo := NewSessionTestRepository(client)
	buildRepo := NewBuildRepository(client)

	series := &Series{ExtID: "some-series"}
	err := seriesRepo.Insert(ctx, series, nil)
	assert.NoError(t, err)

	session := &Session{SeriesID: series.ID}
	err = sessionRepo.Insert(ctx, session)
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
			BaseBuildID:    spanner.NullString{StringVal: build1.ID, Valid: true},
			PatchedBuildID: spanner.NullString{StringVal: build2.ID, Valid: true},
			Result:         api.TestPassed,
		}
		err = testsRepo.InsertOrUpdate(ctx, test)
		assert.NoError(t, err)
	}

	list, err := testsRepo.BySession(ctx, session.ID)
	assert.NoError(t, err)
	assert.Len(t, list, 2)
	for _, test := range list {
		assert.NotNil(t, test.BaseBuild)
		assert.NotNil(t, test.PatchedBuild)
	}
}
