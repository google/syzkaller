// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dashapi

import (
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
)

type AIJobPollReq struct {
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
	JobID string
	Span  *trajectory.Span
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
