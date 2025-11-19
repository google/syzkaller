// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"google.golang.org/appengine/v2/log"
)

type uiAIPage struct {
	Header    *uiHeader
	Workflows []*aidb.Workflow
}

func handleAIPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	workflows, err := aidb.LoadWorkflows(ctx)
	if err != nil {
		return err
	}
	page := &uiAIPage{
		Header:    hdr,
		Workflows: workflows,
	}
	return serveTemplate(w, "ai.html", page)
}

func apiAIJobPoll(ctx context.Context, req *dashapi.AIJobPollReq) (any, error) {
	if err := aidb.UpdateWorkflows(ctx, req.Workflows); err != nil {
		log.Errorf(ctx, "storeAIWorkflows: %v", err)
	}
	resp := &dashapi.AIJobPollResp{}
	return resp, nil
}

func apiAIJobDone(ctx context.Context, req *dashapi.AIJobDoneReq) (any, error) {
	return nil, nil
}

func apiAIJournal(ctx context.Context, req *dashapi.AIJournalReq) (any, error) {
	return nil, nil
}

func aiWorkflowCreate(ctx context.Context, workflow string, bug *Bug) error {
	switch typ := aidb.WorkflowType(strings.Split(workflow, "-")[0]); typ {
	case aidb.WorkflowPatching:
		return aiPatchingWorkflowCreate(ctx, workflow, bug)
	default:
		return fmt.Errorf("unknown workflow type %q", typ)
	}
}

func aiPatchingWorkflowCreate(ctx context.Context, workflow string, bug *Bug) error {
	crash, _, err := findCrashForBug(ctx, bug)
	if err != nil {
		return err
	}
	if crash.ReproSyz == 0 {
		return fmt.Errorf("the bug does not have a reproducer")
	}
	return aidb.CreatePatchingJob(ctx, workflow, &aidb.PatchingJob{
		ReproOpts: crash.ReproOpts,
		ReproSyz:  crash.ReproSyz,
		ReproC:    crash.ReproC,
		//KernelConfig: c
		//SyzkallerCommit: crash.
	})
}
