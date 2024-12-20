// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/workflow"
	"golang.org/x/sync/errgroup"
)

type SeriesProcessor struct {
	seriesRepo     *db.SeriesRepository
	sessionsRepo   *db.SessionsRepository
	workflows      workflow.Service
	dbPollInterval time.Duration
}

func NewSeriesProcessor(env *app.AppEnvironment) *SeriesProcessor {
	workflows, err := workflow.NewArgoService()
	if err != nil {
		app.Fatalf("failed to initialize workflows: %v", err)
	}
	return &SeriesProcessor{
		seriesRepo:     db.NewSeriesRepository(env.Spanner),
		sessionsRepo:   db.NewSessionsRepository(env.Spanner),
		dbPollInterval: time.Minute,
		workflows:      workflows,
	}
}

// Do not run more than this number of sessions in parallel.
// TODO: it'd be different for dev and prod, make it configurable.
const parallelWorkers = 1

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
	activeSessions, err := sp.sessionsRepo.ListRunning(ctx)
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(sp.dbPollInterval):
			break
		}
		if len(ch) > 0 {
			// There are still series to be picked, no need to query the DB.
			continue
		}
		list, err := sp.seriesRepo.ListWithoutSession(ctx, cap(ch))
		if err != nil {
			app.Errorf("failed to query series: %v", err)
			continue
		}
		// Note: it seems that we here actively rely on Spanner's external consistency.
		// E.g. once we add new Session, we expect to no longer see the series in
		// the returned list.
		for _, series := range list {
			session, err := sp.createSession(ctx, series)
			if err != nil {
				app.Errorf("failed to create session for %q: %v", series.ID, err)
				continue
			}
			ch <- session
		}
	}
}

func (sp *SeriesProcessor) seriesRunner(ctx context.Context, ch <-chan *db.Session) {
	var eg errgroup.Group
	defer eg.Wait()

	eg.SetLimit(parallelWorkers)
	for {
		var session *db.Session
		select {
		case session = <-ch:
			break
		case <-ctx.Done():
			return
		}
		log.Printf("starting session %q for series %q", session.ID, session.SeriesID)
		eg.Go(func() error {
			sp.handleSession(ctx, session)
			log.Printf("finished processing session %q", session.ID)
			return nil
		})
	}
}

func (sp *SeriesProcessor) createSession(ctx context.Context, series *db.Series) (*db.Session, error) {
	session := &db.Session{
		CreatedAt: time.Now(),
	}
	err := sp.sessionsRepo.InsertSession(ctx, series, session)
	if err != nil {
		return nil, err
	}
	return session, err
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
		status, err := sp.workflows.Status(session.ID)
		if err != nil {
			app.Errorf("failed to query workflow %q status: %v", session.ID, err)
			continue
		}
		switch status {
		case workflow.StatusNotFound:
			err := sp.workflows.Start(session.ID, session.SeriesID)
			if err != nil {
				app.Errorf("failed to start a workflow: %v", err)
			}
		case workflow.StatusFinished, workflow.StatusFailed:
			// TODO: StatusFailed needs a different handling.
			err := sp.sessionsRepo.Update(ctx, session.ID, func(session *db.Session) error {
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
