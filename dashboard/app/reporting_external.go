// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
)

// Interface with external reporting systems.
// The external system is meant to poll for new bugs with apiReportingPoll,
// and report back bug status updates with apiReportingUpdate.

type ExternalConfig struct {
	ID string
}

func (cfg *ExternalConfig) Type() string {
	return cfg.ID
}

func apiReportingPoll(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.PollRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	reports := reportingPoll(c, req.Type)
	resp := &dashapi.PollResponse{
		Reports: reports,
	}
	return resp, nil
}

func apiReportingUpdate(c context.Context, ns string, r *http.Request) (interface{}, error) {
	req := new(dashapi.BugUpdate)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	ok, reason, err := incomingCommand(c, req)
	return &dashapi.BugUpdateReply{
		OK:    ok,
		Error: err != nil,
		Text:  reason,
	}, nil
}
