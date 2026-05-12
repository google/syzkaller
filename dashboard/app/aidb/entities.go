// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/email/lore"
)

const (
	ActionJobReview = "JobReview" // Outdated. Use ActionApprove/ActionReject.
	ActionApprove   = "Approve"
	ActionReject    = "Reject"
)

const (
	WorkflowAll             = "ALL"
	WorkflowNeedsModeration = "NEEDS MODERATION"
)

type JobReviewDetails struct {
	Correct bool
}

type ActiveWorkflow struct {
	Name       string
	Type       ai.WorkflowType
	LastActive time.Time
}

type Workflow struct {
	AgentName string
	Name      string
	Type      ai.WorkflowType
}

type Agent struct {
	AgentName  string
	LastActive time.Time
}

type Job struct {
	ID        string
	Type      ai.WorkflowType
	Workflow  string
	Namespace string
	BugID     spanner.NullString // set if the job related to some bug
	// Arbitrary description/link shown in the UI list of jobs.
	Description       string
	Link              string
	Created           time.Time
	Started           spanner.NullTime
	Finished          spanner.NullTime
	CodeRevision      string // syzkaller revision, filled when the job is started
	Error             string // for finished jobs
	AgentName         spanner.NullString
	Args              spanner.NullJSON
	Results           spanner.NullJSON
	Correct           spanner.NullBool
	Aborted           bool
	ParentReportingID spanner.NullString
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
	ID          string
	JobID       spanner.NullString
	Date        time.Time
	User        string
	Action      string
	Details     spanner.NullJSON
	SourceExtID spanner.NullString
	Source      spanner.NullString
	ReportingID spanner.NullString
}

type JobReporting struct {
	ID           string
	JobID        string
	Stage        string
	Source       string
	ReportedAt   spanner.NullTime
	UpstreamedAt spanner.NullTime
	UpstreamedBy spanner.NullString
	ExtID        spanner.NullString
	Version      spanner.NullInt64
	CreatedAt    time.Time
}

func (r *JobReporting) ExternalLink() string {
	if !r.ExtID.Valid || r.ExtID.StringVal == "" {
		return ""
	}
	if r.Source == string(dashapi.AIJobSourceLore) {
		return lore.LinkToThread(r.ExtID.StringVal)
	}
	return ""
}

type JobComment struct {
	ID          string
	ReportingID string
	ExtID       string
	Subject     string
	Author      string
	BodyURI     string
	Date        time.Time
	OwnEmail    bool
	Processed   bool
}
