// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"encoding/json"
	"fmt"
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
	ActionUnreject  = "Unreject"
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
	ID            string
	Type          ai.WorkflowType
	Workflow      string
	Namespace     string
	BugID         spanner.NullString // set if the job related to some bug
	ExternalBugID spanner.NullString // set if manually provided via UI
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
	Error       spanner.NullString
	SourceExtID spanner.NullString
	Source      spanner.NullString
	ReportingID spanner.NullString
}

type JobReporting struct {
	ID           string
	JobID        string
	Stage        string
	Source       string
	InReplyTo    string
	ReportedAt   spanner.NullTime
	UpstreamedAt spanner.NullTime
	UpstreamedBy spanner.NullString
	ExtID        spanner.NullString
	Version      spanner.NullInt64
	ExtraCcList  []string
	CreatedAt    time.Time
	// Overrides holds PatchMetadata updated by reply-only patch-iteration jobs
	// (that did not produce a new patch version) on top of the job results.
	// Job.Results are never modified after the job is finished.
	Overrides spanner.NullJSON
}

// PatchMetadata is the part of the patching/patch-iteration job results that reviewers
// can update without a new patch version being generated.
type PatchMetadata struct {
	Recipients  []ai.Recipient `json:",omitempty"`
	ReviewedBy  []string       `json:",omitempty"`
	AckedBy     []string       `json:",omitempty"`
	TestedBy    []string       `json:",omitempty"`
	ReportedBy  []string       `json:",omitempty"`
	SuggestedBy []string       `json:",omitempty"`
}

// PatchMetadata returns the current patch metadata for the reporting: the overrides if they were set,
// or the original job results otherwise.
func (r *JobReporting) PatchMetadata(job *Job) (*PatchMetadata, error) {
	src := job.Results
	if r.Overrides.Valid {
		src = r.Overrides
	}
	meta, err := parsePatchMetadata(src)
	if err != nil {
		return nil, fmt.Errorf("reporting %v: %w", r.ID, err)
	}
	return meta, nil
}

// ApplyTo replaces the recipients and tags in the patch.
func (m *PatchMetadata) ApplyTo(res *ai.PatchingOutputs) {
	res.Recipients = m.Recipients
	res.ReviewedBy = m.ReviewedBy
	res.AckedBy = m.AckedBy
	res.TestedBy = m.TestedBy
	res.ReportedBy = m.ReportedBy
	res.SuggestedBy = m.SuggestedBy
}

// parsePatchMetadata extracts PatchMetadata from job results or reporting overrides.
func parsePatchMetadata(src spanner.NullJSON) (*PatchMetadata, error) {
	meta := new(PatchMetadata)
	if !src.Valid || src.Value == nil {
		return meta, nil
	}
	data, err := json.Marshal(src.Value)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, fmt.Errorf("failed to parse patch metadata: %w", err)
	}
	return meta, nil
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
	ID           string
	ReportingID  string
	ExtID        string
	Subject      spanner.NullString
	Author       string
	BodyURI      string
	Date         time.Time
	OwnEmail     bool
	Processed    bool
	VerifiedDKIM bool
}
