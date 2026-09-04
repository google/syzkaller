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
)

type SeriesProcessor struct {
	blobStorage       blob.Storage
	seriesRepo        *db.SeriesRepository
	sessionRepo       *db.SessionRepository
	sessionTestRepo   *db.SessionTestRepository
	workflows         workflow.Service
	dbPollInterval    time.Duration
	parallelWorkflows int

	// activeSessions tracks sessions currently queued in memory or running in worker goroutines.
	// We track active sessions in memory because session.StartedAt in the database is only set
	// right before the workflow is actually started. Tracking active sessions in memory prevents
	// streamSeries from re-querying and re-dispatching waiting sessions before their StartedAt
	// timestamp is committed to the database.
	activeSessions sync.Map
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

	ch := make(chan *db.Session)
	for range sp.parallelWorkflows {
		wg.Go(func() {
			sp.seriesRunner(ctx, ch)
		})
	}
	// First pick up the previously running sessions.
	runningSessions, err := sp.sessionRepo.ListRunning(ctx)
	if err != nil {
		return err
	}
	log.Printf("queried %d unfinished sessions", len(runningSessions))
	for _, session := range runningSessions {
		select {
		case ch <- session:
			sp.activeSessions.Store(session.ID, struct{}{})
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Then, monitor the DB for the new series.
	wg.Go(func() {
		sp.streamSeries(ctx, ch)
		close(ch)
	})
	return nil
}

func (sp *SeriesProcessor) streamSeries(ctx context.Context, ch chan<- *db.Session) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(sp.dbPollInterval):
		}
		// Query waiting sessions up to the parallel workflow capacity.
		list, err := sp.sessionRepo.ListWaiting(ctx, sp.parallelWorkflows)
		if err != nil {
			if ctx.Err() == nil {
				app.Errorf("failed to query series: %v", err)
			}
			continue
		}
		for _, session := range list {
			if _, ok := sp.activeSessions.Load(session.ID); ok {
				continue
			}
			select {
			case ch <- session:
				sp.activeSessions.Store(session.ID, struct{}{})
			case <-ctx.Done():
				return
			}
		}
	}
}

func (sp *SeriesProcessor) seriesRunner(ctx context.Context, ch <-chan *db.Session) {
	for {
		select {
		case session, ok := <-ch:
			if !ok {
				return
			}
			log.Printf("started processing session %q", session.ID)
			sp.handleSession(ctx, session)
			log.Printf("finished processing session %q", session.ID)
		case <-ctx.Done():
			return
		}
	}
}

func (sp *SeriesProcessor) handleSession(ctx context.Context, session *db.Session) {
	defer sp.activeSessions.Delete(session.ID)
	// TODO: set some sane deadline or just track indefinitely?
	pollPeriod := sp.workflows.PollPeriod()
	for {
		status, workflowLog, err := sp.workflows.Status(session.ID)
		if err != nil {
			app.Errorf("failed to query workflow %q status: %v", session.ID, err)
		} else {
			if len(workflowLog) > 0 {
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
				log.Printf("workflow for %q completed (status=%q), mark the session finished", session.ID, status)
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
			default:
				panic("unexpected workflow status: " + status)
			}
		}

		select {
		case <-time.After(pollPeriod):
		case <-ctx.Done():
			return
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
	logURI, err := sp.blobStorage.Write(bytes.NewReader(log), "Session", session.ID, "log")
	if err != nil {
		return fmt.Errorf("failed to save the log: %w", err)
	}
	return sp.sessionRepo.Update(ctx, session.ID, func(session *db.Session) error {
		session.LogURI = logURI
		return nil
	})
}
