// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	db "google.golang.org/appengine/v2/datastore"
)

// Automatic bisection jobs are paced for old bugs, so that the backlog of old bugs is processed
// gradually rather than all at once: at most one such job is created per hour in each namespace
// for each of the workflows. Jobs for new bugs are neither paced nor counted.
// The limit is not strict: the check is not atomic, so concurrent polls may rarely exceed it.
const (
	aiBacklogBugAge    = 24 * time.Hour
	aiBacklogJobPeriod = time.Hour
)

// AIBacklogJob holds the time the last paced job of a workflow was created in a namespace.
// The key name is "namespace|workflow".
type AIBacklogJob struct {
	Created time.Time `datastore:",noindex"`
}

// aiBacklogPacer decides whether automatic jobs can be created for old bugs of a namespace.
type aiBacklogPacer struct {
	ns string
	// Paced workflows that can't get a job for an old bug now.
	blocked map[ai.WorkflowType]bool
}

func newAIBacklogPacer(ctx context.Context, ns string, reqWorkflows []dashapi.AIWorkflow) (*aiBacklogPacer, error) {
	p := &aiBacklogPacer{ns: ns, blocked: make(map[ai.WorkflowType]bool)}
	for _, req := range reqWorkflows {
		if !p.paces(req.Type) {
			continue
		}
		last := new(AIBacklogJob)
		if err := db.Get(ctx, p.key(ctx, req.Type), last); err != nil && err != db.ErrNoSuchEntity {
			return nil, fmt.Errorf("failed to get the last %v backlog job: %w", req.Type, err)
		}
		p.blocked[req.Type] = timeSince(ctx, last.Created) < aiBacklogJobPeriod
	}
	return p, nil
}

// paces says whether jobs of the workflow are paced for old bugs.
func (p *aiBacklogPacer) paces(typ ai.WorkflowType) bool {
	return typ == ai.WorkflowBisectCause || typ == ai.WorkflowBisectFix
}

// allowed says whether a job of the workflow can be created for the bug now.
func (p *aiBacklogPacer) allowed(ctx context.Context, bug *Bug, typ ai.WorkflowType) bool {
	return !p.blocked[typ] || timeSince(ctx, bug.FirstTime) < aiBacklogBugAge
}

// reserve says whether a job of the workflow can be created for the bug now, and records the job
// if it's paced. The record stays even if the job is not created after all (e.g. if the bug was
// concurrently updated), this only delays the next paced job.
func (p *aiBacklogPacer) reserve(ctx context.Context, bug *Bug, typ ai.WorkflowType) (bool, error) {
	if !p.paces(typ) || timeSince(ctx, bug.FirstTime) < aiBacklogBugAge {
		return true, nil
	}
	if p.blocked[typ] {
		return false, nil
	}
	p.blocked[typ] = true
	if _, err := db.Put(ctx, p.key(ctx, typ), &AIBacklogJob{Created: timeNow(ctx)}); err != nil {
		return false, fmt.Errorf("failed to record the %v backlog job: %w", typ, err)
	}
	return true, nil
}

func (p *aiBacklogPacer) key(ctx context.Context, typ ai.WorkflowType) *db.Key {
	return db.NewKey(ctx, "AIBacklogJob", p.ns+"|"+string(typ), 0, nil)
}
