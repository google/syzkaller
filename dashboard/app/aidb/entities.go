// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/aflow/ai"
)

const (
	ActionJobReview = "JobReview"
)

type JobReviewDetails struct {
	Correct bool
}

type Workflow struct {
	Name       string
	Type       ai.WorkflowType
	LastActive time.Time
}

type Job struct {
	ID        string
	Type      ai.WorkflowType
	Workflow  string
	Namespace string
	BugID     spanner.NullString // set if the job related to some bug
	// Arbitrary description/link shown in the UI list of jobs.
	Description  string
	Link         string
	Created      time.Time
	Started      spanner.NullTime
	Finished     spanner.NullTime
	CodeRevision string // syzkaller revision, filled when the job is started
	Error        string // for finished jobs
	Args         spanner.NullJSON
	Results      spanner.NullJSON
	Correct      spanner.NullBool
}

type TrajectorySpan struct {
	JobID string
	// The following fields correspond one-to-one to trajectory.Span fields (add field comments there).
	Seq                  int64
	Nesting              int64
	Type                 string
	Name                 string
	Model                string
	Started              time.Time
	Finished             spanner.NullTime
	Error                spanner.NullString
	Args                 spanner.NullJSON
	Results              spanner.NullJSON
	Instruction          spanner.NullString
	Prompt               spanner.NullString
	Reply                spanner.NullString
	Thoughts             spanner.NullString
	InputTokens          spanner.NullInt64
	OutputTokens         spanner.NullInt64
	OutputThoughtsTokens spanner.NullInt64
}

type Journal struct {
	ID      string
	JobID   spanner.NullString
	Date    time.Time
	User    string
	Action  string
	Details spanner.NullJSON
}
