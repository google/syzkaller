// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dashapi

import (
	"errors"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

type AIJobPollReq struct {
	AgentName    string
	CodeRevision string // git commit of the syz-agent server
	Workflows    []AIWorkflow
}

type AIWorkflow struct {
	Type ai.WorkflowType
	Name string
}

type AIJobPollResp struct {
	ID       string
	Workflow string
	Args     map[string]any
}

type AIJobDoneReq struct {
	ID      string
	Error   string
	Results map[string]any
}

type AITrajectoryReq struct {
	AgentName string
	JobID     string
	Span      *trajectory.Span
}

func (dash *Dashboard) AIJobPoll(req *AIJobPollReq) (*AIJobPollResp, error) {
	resp := new(AIJobPollResp)
	if err := dash.Query("ai_job_poll", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (dash *Dashboard) AIJobDone(req *AIJobDoneReq) error {
	return dash.Query("ai_job_done", req, nil)
}

func (dash *Dashboard) AITrajectoryLog(req *AITrajectoryReq) error {
	return dash.Query("ai_trajectory_log", req, nil)
}

// SendExternalCommandReq represents a request to report a patch action externally (upstream or reject).
type SendExternalCommandReq struct {
	Source       string
	RootExtID    string
	MessageExtID string
	Author       string
	// Only one must be set.
	Upstream *UpstreamCommand `json:",omitempty"`
	Reject   *RejectCommand   `json:",omitempty"`
}

type UpstreamCommand struct {
}

type RejectCommand struct {
	Reason string
}

type SendExternalCommandResp struct {
	Error string
}

// PollExternalReportReq represents a request to poll for pending reports to be sent externally.
type PollExternalReportReq struct {
	Source string // e.g., "lore"
}

type PollExternalReportResp struct {
	Result *ReportPollResult
}

type ReportPollResult struct {
	ID          string // JobReporting ID
	CanUpstream bool
	To          []string
	Cc          []string
	Patch       *NewReportResult `json:",omitempty"`
	Replies     []*ReplyResult   `json:",omitempty"`
}

type NewReportResult struct {
	Subject    string
	Body       string
	Version    int
	GitDiff    string
	To         []string
	Cc         []string
	BaseCommit string
	BaseTree   string
}

type ReplyResult struct {
	Quote      string
	Body       string
	ReplyExtID string
}

// ConfirmPublishedReq represents a request to confirm that a report has been published externally.
type ConfirmPublishedReq struct {
	ReportID       string
	PublishedExtID string
}

var ErrReportNotFound = errors.New("report not found")

func (dash *Dashboard) AIReportCommand(req *SendExternalCommandReq) (*SendExternalCommandResp, error) {
	resp := new(SendExternalCommandResp)
	if err := dash.Query("ai_report_command", req, resp); err != nil {
		return nil, err
	}
	if resp.Error == ErrReportNotFound.Error() {
		return nil, ErrReportNotFound
	}
	return resp, nil
}

func (dash *Dashboard) AIPollReport(req *PollExternalReportReq) (*PollExternalReportResp, error) {
	resp := new(PollExternalReportResp)
	if err := dash.Query("ai_poll_report", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (dash *Dashboard) AIConfirmReport(req *ConfirmPublishedReq) error {
	return dash.Query("ai_confirm_report", req, nil)
}
