// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/syzkaller/dashboard/dashapi"
	"google.golang.org/appengine/v2/log"
)

// Interface with external reporting systems.
// The external system is meant to poll for new bugs with apiReportingPoll,
// and report back bug status updates with apiReportingUpdate.

func apiReportingPollBugs(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	if stop, err := emergentlyStopped(c); err != nil || stop {
		return &dashapi.PollBugsResponse{}, err
	}
	req := new(dashapi.PollBugsRequest)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	reports := reportingPollBugs(c, req.Type)
	resp := &dashapi.PollBugsResponse{
		Reports: reports,
	}
	jobs, err := pollCompletedJobs(c, req.Type)
	if err != nil {
		log.Errorf(c, "failed to poll jobs(bugs): %v", err)
	}
	resp.Reports = append(resp.Reports, jobs...)
	return resp, nil
}

func apiReportingPollNotifications(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	if stop, err := emergentlyStopped(c); err != nil || stop {
		return &dashapi.PollNotificationsResponse{}, err
	}
	req := new(dashapi.PollNotificationsRequest)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	notifs := reportingPollNotifications(c, req.Type)
	resp := &dashapi.PollNotificationsResponse{
		Notifications: notifs,
	}
	return resp, nil
}

func apiReportingPollClosed(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	if stop, err := emergentlyStopped(c); err != nil || stop {
		return &dashapi.PollClosedResponse{}, err
	}
	req := new(dashapi.PollClosedRequest)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	ids, err := reportingPollClosed(c, req.IDs)
	if err != nil {
		return nil, err
	}
	resp := &dashapi.PollClosedResponse{
		IDs: ids,
	}
	return resp, nil
}

func apiReportingUpdate(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.BugUpdate)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	if req.JobID != "" {
		resp := &dashapi.BugUpdateReply{
			OK:    true,
			Error: false,
		}
		if err := jobReported(c, req.JobID); err != nil {
			log.Errorf(c, "failed to mark job reported: %v", err)
			resp.Text = err.Error()
			resp.Error = true
		}
		return resp, nil
	}
	ok, reason, err := incomingCommand(c, req)
	return &dashapi.BugUpdateReply{
		OK:    ok,
		Error: err != nil,
		Text:  reason,
	}, nil
}

func apiNewTestJob(c context.Context, r *http.Request, payload []byte) (interface{}, error) {
	req := new(dashapi.TestPatchRequest)
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	resp := &dashapi.TestPatchReply{}
	err := handleExternalTestRequest(c, req)
	if err != nil {
		resp.ErrorText = err.Error()
		var badTest *BadTestRequestError
		if !errors.As(err, &badTest) {
			// Log errors that are not related to the invalid input.
			log.Errorf(c, "external patch posting error: %v", err)
		}
	}
	return resp, nil
}
