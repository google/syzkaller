// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

// It's a bit too long for a unit test, but it captures the whole main scenario of operation.
func TestProcessor(t *testing.T) {
	workflows := newMockedWorkflows()
	processor, client, ctx := prepareProcessorTest(t, workflows)

	// Start the loop.
	var wg sync.WaitGroup
	ctx2, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		processor.Loop(ctx2)
		wg.Done()
	}()

	// Add some series.
	var allSeries []*api.Series
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("series-%d", i)
		allSeries = append(allSeries, &api.Series{
			ExtID: id,
			Title: id,
		})
	}
	for _, series := range allSeries[0:5] {
		controller.UploadTestSeries(t, ctx, client, series)
	}

	// Let some workflows finish.
	for i := 0; i < 2; i++ {
		workflows.finish <- struct{}{}
	}

	awaitFinishedSessions(t, processor.seriesRepo, 2)

	// Restart the loop.
	cancel()
	wg.Wait()

	ctx3, cancel := context.WithCancel(ctx)
	wg.Add(1)
	defer wg.Wait()
	go func() {
		processor.Loop(ctx3)
		wg.Done()
	}()

	// Add some more series.
	for _, series := range allSeries[5:10] {
		controller.UploadTestSeries(t, ctx, client, series)
	}

	// Finish all of them.
	for i := 0; i < 8; i++ {
		workflows.finish <- struct{}{}
	}

	awaitFinishedSessions(t, processor.seriesRepo, 10)
	cancel()
}

func awaitFinishedSessions(t *testing.T, seriesRepo *db.SeriesRepository, wantFinished int) {
	t.Logf("awaiting %d finished sessions", wantFinished)
	deadline := time.Second * 2
	interval := time.Second / 10
	for i := 0; i < int(deadline/interval); i++ {
		time.Sleep(interval)

		list, err := seriesRepo.ListLatest(context.Background(), time.Time{}, 0)
		assert.NoError(t, err)
		withFinishedSeries := 0
		for _, item := range list {
			if item.Session == nil {
				continue
			}
			if item.Session.FinishedAt.IsNull() {
				continue
			}
			withFinishedSeries++
		}
		t.Logf("have %d finished", withFinishedSeries)
		if withFinishedSeries == wantFinished {
			return
		}
	}
	t.Fatalf("never reached %d finished series", wantFinished)
}

type mockedWorkflows struct {
	workflow.MockService
	finish  chan struct{}
	created map[string]struct{}
}

func newMockedWorkflows() *mockedWorkflows {
	obj := mockedWorkflows{
		finish:  make(chan struct{}),
		created: make(map[string]struct{}),
	}
	obj.PollDelayValue = time.Millisecond
	obj.OnStart = func(id string) error {
		obj.created[id] = struct{}{}
		return nil
	}
	obj.OnStatus = func(id string) (workflow.Status, []byte, error) {
		_, ok := obj.created[id]
		if !ok {
			return workflow.StatusNotFound, nil, nil
		}
		finished := false
		select {
		case <-obj.finish:
			finished = true
		default:
		}
		if finished {
			return workflow.StatusFinished, nil, nil
		}
		return workflow.StatusRunning, nil, nil
	}
	return &obj
}

func prepareProcessorTest(t *testing.T, workflows workflow.Service) (*SeriesProcessor,
	*api.Client, context.Context) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)
	return &SeriesProcessor{
		seriesRepo:      db.NewSeriesRepository(env.Spanner),
		sessionRepo:     db.NewSessionRepository(env.Spanner),
		workflows:       workflows,
		dbPollInterval:  time.Second / 10,
		parallelWorkers: 2,
	}, client, ctx
}
