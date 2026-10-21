// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"slices"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/email"
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
	// To/Cc changes requested by reviewers in patch iteration: written by RecordCcChanges,
	// applied by CurrentRecipients on top of the recipients of the patch and ExtraCcList, so a removed address
	// stays removed even if it's Cc'd again on the discussion (only a reviewer's request can add it back).
	AddedCcList   []string
	RemovedCcList []string
}

// RecordCcChanges records To/Cc changes requested by reviewers.
// The latest request for an address takes precedence, so an address is never present in both lists.
func (r *JobReporting) RecordCcChanges(added, removed []string) {
	r.AddedCcList = email.SubtractEmailLists(email.MergeEmailLists(r.AddedCcList, added), removed)
	r.RemovedCcList = email.SubtractEmailLists(email.MergeEmailLists(r.RemovedCcList, removed), added)
}

// CurrentRecipients returns the current recipients of the patch: patchRecipients
// with the To/Cc changes requested by reviewers applied.
func (r *JobReporting) CurrentRecipients(patchRecipients []ai.Recipient) []ai.Recipient {
	var res []ai.Recipient
	for _, rec := range patchRecipients {
		if !slices.ContainsFunc(r.RemovedCcList, func(addr string) bool { return email.EmailsMatch(rec.Email, addr) }) {
			res = append(res, rec)
		}
	}
	return appendCcRecipients(res, r.AddedCcList)
}

// appendCcRecipients appends the addresses that are not yet among the recipients as Cc recipients.
func appendCcRecipients(recipients []ai.Recipient, addrs []string) []ai.Recipient {
	for _, addr := range addrs {
		if !slices.ContainsFunc(recipients, func(rec ai.Recipient) bool { return email.EmailsMatch(rec.Email, addr) }) {
			recipients = append(recipients, ai.Recipient{Email: addr})
		}
	}
	return recipients
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
