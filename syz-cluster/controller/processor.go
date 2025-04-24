// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/workflow"
	"golang.org/x/sync/errgroup"
)

type SeriesProcessor struct {
	blobStorage       blob.Storage
	seriesRepo        *db.SeriesRepository
	sessionRepo       *db.SessionRepository
	sessionTestRepo   *db.SessionTestRepository
	workflows         workflow.Service
	dbPollInterval    time.Duration
	parallelWorkflows int
}

func NewSeriesProcessor(env *app.AppEnvironment, cfg *app.AppConfig) *SeriesProcessor {
	workflows, err := workflow.NewArgoService()
	if err != nil {
		app.Fatalf("failed to initialize workflows: %v", err)
	}
	return &SeriesProcessor{
		blobStorage:       env.BlobStorage,
		seriesRepo:        db.NewSeriesRepository(env.Spanner),
		sessionRepo:       db.NewSessionRepository(env.Spanner),
		sessionTestRepo:   db.NewSessionTestRepository(env.Spanner),
		dbPollInterval:    time.Minute,
		workflows:         workflows,
		parallelWorkflows: cfg.ParallelWorkflows,
	}
}

func (sp *SeriesProcessor) Loop(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	ch := make(chan *db.Session, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sp.seriesRunner(ctx, ch)
	}()
	// First pick up the previously running sessions.
	activeSessions, err := sp.sessionRepo.ListRunning(ctx)
	if err != nil {
		return err
	}
	log.Printf("queried %d unfinished sessions", len(activeSessions))
	for _, session := range activeSessions {
		ch <- session
	}
	// Then, monitor the DB for the new series.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sp.streamSeries(ctx, ch)
		close(ch)
	}()
	return nil
}

func (sp *SeriesProcessor) streamSeries(ctx context.Context, ch chan<- *db.Session) {
	var next *db.NextSession
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(sp.dbPollInterval):
		}
		if len(ch) > 0 {
			// There are still series to be picked, no need to query the DB.
			continue
		}
		var err error
		var list []*db.Session
		list, next, err = sp.sessionRepo.ListWaiting(ctx, next, cap(ch))
		if err != nil {
			app.Errorf("failed to query series: %v", err)
			continue
		}
		for _, session := range list {
			ch <- session
		}
	}
}

func (sp *SeriesProcessor) seriesRunner(ctx context.Context, ch <-chan *db.Session) {
	var eg errgroup.Group
	defer eg.Wait()

	eg.SetLimit(sp.parallelWorkflows)
	for {
		var session *db.Session
		select {
		case session = <-ch:
			if session == nil {
				return
			}
		case <-ctx.Done():
			return
		}
		log.Printf("scheduled session %q for series %q", session.ID, session.SeriesID)
		eg.Go(func() error {
			log.Printf("started processing session %q", session.ID)
			sp.handleSession(ctx, session)
			log.Printf("finished processing session %q", session.ID)
			return nil
		})
	}
}

func (sp *SeriesProcessor) handleSession(ctx context.Context, session *db.Session) {
	// TODO: set some sane deadline or just track indefinitely?
	pollPeriod := sp.workflows.PollPeriod()
	for {
		select {
		case <-time.After(pollPeriod):
		case <-ctx.Done():
			return
		}
		status, workflowLog, err := sp.workflows.Status(session.ID)
		if err != nil {
			app.Errorf("failed to query workflow %q status: %v", session.ID, err)
			continue
		}
		if workflowLog != nil {
			err := sp.updateSessionLog(ctx, session, workflowLog)
			if err != nil {
				app.Errorf("failed to update session log: %v", err)
			}
		}
		switch status {
		case workflow.StatusNotFound:
			log.Printf("scheduling a workflow for %q", session.ID)
			err := sp.sessionRepo.Start(ctx, session.ID)
			if err == db.ErrSessionAlreadyStarted {
				// It may happen if the service was restarted right between the moment we updated the DB
				// and actually started the workflow.
				log.Printf("session %q was already marked as started, but there's no actual workflow", session.ID)
			} else if err != nil {
				app.Errorf("failed to mark session started: %v", err)
				break
			}
			err = sp.workflows.Start(session.ID)
			if err != nil {
				app.Errorf("failed to start a workflow: %v", err)
			}
		case workflow.StatusFinished, workflow.StatusFailed:
			log.Printf("workflow for %q completed, mark the session finished", session.ID)
			err := sp.stopRunningTests(ctx, session.ID)
			if err != nil {
				app.Errorf("failed to check running tests for %s: %v", session.ID, err)
			}
			// TODO: StatusFailed needs a different handling.
			err = sp.sessionRepo.Update(ctx, session.ID, func(session *db.Session) error {
				session.SetFinishedAt(time.Now())
				return nil
			})
			if err == nil {
				// Nothing to do here anymore.
				return
			}
			// Let's hope the error was transient.
			app.Errorf("failed to update session %q: %v", session.ID, err)
		case workflow.StatusRunning:
			// Let's keep on tracking.
			continue
		default:
			panic("unexpected workflow status: " + status)
		}
	}
}

// The session steps are expected to report that they are finished themselves.
// If the workflow was aborted for some external reason (or the session step crashed/timed out),
// the step may remain forever in the "Running" state.
// Go through such steps and mark them as finished (with an error).
func (sp *SeriesProcessor) stopRunningTests(ctx context.Context, sessionID string) error {
	tests, err := sp.sessionTestRepo.BySessionRaw(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to query session steps: %w", err)
	}
	for _, test := range tests {
		if test.Result != api.TestRunning {
			continue
		}
		log.Printf("session %q is finished, but the test %q is running: marking it stopped",
			sessionID, test.TestName)
		err = sp.sessionTestRepo.InsertOrUpdate(ctx, test, func(entity *db.SessionTest) {
			if entity.Result == api.TestRunning {
				entity.Result = api.TestError
			}
		})
		if err != nil {
			return fmt.Errorf("failed to update the step %q: %w", test.TestName, err)
		}
	}
	return nil
}

func (sp *SeriesProcessor) updateSessionLog(ctx context.Context, session *db.Session, log []byte) error {
	return sp.sessionRepo.Update(ctx, session.ID, func(session *db.Session) error {
		if session.LogURI == "" {
			path, err := sp.blobStorage.Store(bytes.NewReader(log))
			if err != nil {
				return fmt.Errorf("failed to save the log: %w", err)
			}
			session.LogURI = path
		} else {
			err := sp.blobStorage.Update(session.LogURI, bytes.NewReader(log))
			if err != nil {
				return fmt.Errorf("failed to update the log %q: %w", session.LogURI, err)
			}
		}
		return nil
	})
}
