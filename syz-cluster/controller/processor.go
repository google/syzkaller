// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/workflow"
	"golang.org/x/sync/errgroup"
)

type SeriesProcessor struct {
	blobStorage     blob.Storage
	seriesRepo      *db.SeriesRepository
	sessionRepo     *db.SessionRepository
	workflows       workflow.Service
	dbPollInterval  time.Duration
	parallelWorkers int
}

func NewSeriesProcessor(env *app.AppEnvironment) *SeriesProcessor {
	workflows, err := workflow.NewArgoService()
	if err != nil {
		app.Fatalf("failed to initialize workflows: %v", err)
	}
	parallelWorkers := 1
	if val := os.Getenv("PARALLEL_WORKERS"); val != "" {
		var err error
		parallelWorkers, err = strconv.Atoi(val)
		if err != nil || parallelWorkers < 1 {
			app.Fatalf("invalid PARALLEL_WORKERS value")
		}
	}
	return &SeriesProcessor{
		blobStorage:     env.BlobStorage,
		seriesRepo:      db.NewSeriesRepository(env.Spanner),
		sessionRepo:     db.NewSessionRepository(env.Spanner),
		dbPollInterval:  time.Minute,
		workflows:       workflows,
		parallelWorkers: parallelWorkers,
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

	eg.SetLimit(sp.parallelWorkers)
	for {
		var session *db.Session
		select {
		case session = <-ch:
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

func (sp *SeriesProcessor) createSession(ctx context.Context, series *db.Series) (*db.Session, error) {
	session := &db.Session{
		CreatedAt: time.Now(),
	}
	err := sp.sessionRepo.Insert(ctx, series, session)
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
		status, log, err := sp.workflows.Status(session.ID)
		if err != nil {
			app.Errorf("failed to query workflow %q status: %v", session.ID, err)
			continue
		}
		if log != nil {
			err := sp.updateSessionLog(ctx, session, log)
			if err != nil {
				app.Errorf("failed to update session log: %v", err)
			}
		}
		switch status {
		case workflow.StatusNotFound:
			err := sp.workflows.Start(session.ID)
			if err != nil {
				app.Errorf("failed to start a workflow: %v", err)
			}
		case workflow.StatusFinished, workflow.StatusFailed:
			// TODO: StatusFailed needs a different handling.
			err := sp.sessionRepo.Update(ctx, session.ID, func(session *db.Session) error {
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
