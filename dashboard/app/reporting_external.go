// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"

	"github.com/google/syzkaller/dashboard/dashapi"
	"google.golang.org/appengine/v2/log"
)

// Interface with external reporting systems.
// The external system is meant to poll for new bugs with apiReportingPoll,
// and report back bug status updates with apiReportingUpdate.

func apiReportingPollBugs(ctx context.Context, req *dashapi.PollBugsRequest) (any, error) {
	if stop, err := emergentlyStopped(ctx); err != nil || stop {
		return &dashapi.PollBugsResponse{}, err
	}
	reports := reportingPollBugs(ctx, req.Type)
	resp := &dashapi.PollBugsResponse{
		Reports: reports,
	}
	jobs, err := pollCompletedJobs(ctx, req.Type)
	if err != nil {
		log.Errorf(ctx, "failed to poll jobs(bugs): %v", err)
	}
	resp.Reports = append(resp.Reports, jobs...)
	return resp, nil
}

func apiReportingPollNotifications(ctx context.Context, req *dashapi.PollNotificationsRequest) (
	any, error) {
	if stop, err := emergentlyStopped(ctx); err != nil || stop {
		return &dashapi.PollNotificationsResponse{}, err
	}
	notifs := reportingPollNotifications(ctx, req.Type)
	resp := &dashapi.PollNotificationsResponse{
		Notifications: notifs,
	}
	return resp, nil
}

func apiReportingPollClosed(ctx context.Context, req *dashapi.PollClosedRequest) (any, error) {
	if stop, err := emergentlyStopped(ctx); err != nil || stop {
		return &dashapi.PollClosedResponse{}, err
	}
	ids, err := reportingPollClosed(ctx, req.IDs)
	if err != nil {
		return nil, err
	}
	resp := &dashapi.PollClosedResponse{
		IDs: ids,
	}
	return resp, nil
}

func apiReportingUpdate(ctx context.Context, req *dashapi.BugUpdate) (any, error) {
	if req.JobID != "" {
		resp := &dashapi.BugUpdateReply{
			OK:    true,
			Error: false,
		}
		if err := jobReported(ctx, req.JobID); err != nil {
			log.Errorf(ctx, "failed to mark job reported: %v", err)
			resp.Text = err.Error()
			resp.Error = true
		}
		return resp, nil
	}
	ok, reason, err := incomingCommand(ctx, req)
	return &dashapi.BugUpdateReply{
		OK:    ok,
		Error: err != nil,
		Text:  reason,
	}, nil
}

func apiNewTestJob(ctx context.Context, req *dashapi.TestPatchRequest) (any, error) {
	resp := &dashapi.TestPatchReply{}
	err := handleExternalTestRequest(ctx, req)
	if err != nil {
		resp.ErrorText = err.Error()
		var badTest *BadTestRequestError
		if !errors.As(err, &badTest) {
			// Log errors that are not related to the invalid input.
			log.Errorf(ctx, "external patch posting error: %v", err)
		}
	}
	return resp, nil
}
