// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"google.golang.org/appengine/v2/log"
)

const SourceWebUI = "web ui"

func apiAIReportCommand(ctx context.Context, req *dashapi.SendExternalCommandReq) (any, error) {
	var resp *dashapi.SendExternalCommandResp
	var err error
	if req.Upstream != nil {
		resp, err = handleUpstreamCommand(ctx, req)
	} else if req.Reject != nil {
		resp, err = handleRejectCommand(ctx, req)
	} else if req.Comment != nil {
		resp, err = handleCommentCommand(ctx, req)
	} else {
		return nil, fmt.Errorf("unknown command")
	}

	if err != nil {
		var cannotUpstreamErr *aidb.ErrCannotUpstream
		if errors.As(err, &cannotUpstreamErr) {
			return &dashapi.SendExternalCommandResp{Error: cannotUpstreamErr.Reason}, nil
		}
		if errors.Is(err, dashapi.ErrReportNotFound) {
			return &dashapi.SendExternalCommandResp{Error: dashapi.ErrReportNotFound.Error()}, nil
		}
		return nil, err
	}
	return resp, nil
}

func handleUpstreamCommand(ctx context.Context, req *dashapi.SendExternalCommandReq,
) (*dashapi.SendExternalCommandResp, error) {
	reporting, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	err = processUpstreamSubcommand(ctx, job, reporting, req)
	if err != nil {
		return nil, err
	}

	return &dashapi.SendExternalCommandResp{}, nil
}

func processUpstreamSubcommand(ctx context.Context, job *aidb.Job,
	currentReporting *aidb.JobReporting, req *dashapi.SendExternalCommandReq) error {
	nsCfg := getNsConfig(ctx, job.Namespace)
	if nsCfg.AI == nil || len(nsCfg.AI.Stages) == 0 {
		return aidb.UpstreamReportCommand(ctx, aidb.UpstreamReportArgs{
			Job:           job,
			CommandSource: string(req.Source),
			CommandExtID:  req.MessageExtID,
			User:          req.Author,
		})
	}

	currentStage := ""
	if currentReporting != nil {
		currentStage = currentReporting.Stage
	}

	nextStageCfg, err := determineNextStage(ctx, nsCfg.AI, job, currentStage)
	if err != nil {
		return err
	}
	nextStage := nextStageCfg.Name

	return aidb.UpstreamReportCommand(ctx, aidb.UpstreamReportArgs{
		Job: job,
		Reporting: &aidb.JobReporting{
			Stage:        nextStage,
			Source:       nextStageCfg.ServingIntegration,
			UpstreamedAt: spanner.NullTime{Time: aidb.TimeNow(ctx), Valid: true},
		},
		NoParallel:    nextStageCfg.NoParallelReports,
		CommandSource: string(req.Source),
		CommandExtID:  req.MessageExtID,
		User:          req.Author,
		Reason:        "",
	})
}

func determineNextStage(ctx context.Context, cfg *AIConfig, job *aidb.Job,
	currentStage string) (*AIPatchStageConfig, error) {
	reportings, err := aidb.LoadJobReportings(ctx, job.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load job reportings: %w", err)
	}
	reported := make(map[string]bool)
	for _, r := range reportings {
		reported[r.Stage] = true
	}
	currentIndex := -1
	if currentStage != "" {
		currentIndex = cfg.StageIndexByName(currentStage)
		if currentIndex == -1 {
			return nil, &aidb.ErrCannotUpstream{Reason: fmt.Sprintf("current stage %s not found in config", currentStage)}
		}
	}

	// Check if any stage after currentStage has already been reported.
	for i := currentIndex + 1; i < len(cfg.Stages); i++ {
		if reported[cfg.Stages[i].Name] {
			return nil, &aidb.ErrCannotUpstream{
				Reason: fmt.Sprintf("cannot proceed to next stage, a later stage %s was already reported", cfg.Stages[i].Name),
			}
		}
	}

	if currentIndex+1 >= len(cfg.Stages) {
		return nil, &aidb.ErrCannotUpstream{Reason: "no valid next stage found, all stages reported"}
	}

	return &cfg.Stages[currentIndex+1], nil
}

func handleRejectCommand(ctx context.Context, req *dashapi.SendExternalCommandReq,
) (*dashapi.SendExternalCommandResp, error) {
	_, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	reason := ""
	if req.Reject != nil {
		reason = req.Reject.Reason
	}

	err = aidb.RejectReportCommand(ctx, aidb.RejectReportArgs{
		Job:           job,
		CommandSource: string(req.Source),
		CommandExtID:  req.MessageExtID,
		User:          req.Author,
		Reason:        reason,
	})
	if err != nil {
		return nil, err
	}

	return &dashapi.SendExternalCommandResp{}, nil
}

func apiAIPollReport(ctx context.Context, req *dashapi.PollExternalReportReq) (any, error) {
	reportings, err := aidb.LoadPendingJobReportingBySource(ctx, string(req.Source))
	if err != nil {
		return nil, fmt.Errorf("failed to load pending reportings: %w", err)
	}
	for _, r := range reportings {
		job, err := aidb.LoadJob(ctx, r.JobID)
		if err != nil {
			return nil, fmt.Errorf("failed to load job %v: %w", r.JobID, err)
		}
		nsCfg := getNsConfig(ctx, job.Namespace)
		if nsCfg.AI == nil {
			log.Errorf(ctx, "ai is disabled for namespace %s, yet job %v has reportings", job.Namespace, job.ID)
			continue
		}
		idx := nsCfg.AI.StageIndexByName(r.Stage)
		if idx == -1 {
			// TODO: this could only happen if the config changed between the reporting creation
			// and now. In this case, we should probably just delete / reject this reporting.
			log.Errorf(ctx, "ai job reporting stage %s not found in config (id %v)", r.Stage, r.ID)
			continue
		}
		stageCfg := &nsCfg.AI.Stages[idx]
		if job.Type != ai.WorkflowPatching {
			log.Errorf(ctx, "unsupported job type for external reporting: %s (job %v)", job.Type, job.ID)
			return nil, fmt.Errorf("unsupported job type: %s", job.Type)
		}
		patchResult, err := makeNewReportResult(job)
		if err != nil {
			return nil, err
		}
		to := []string{stageCfg.MailingList}
		var cc []string
		if stageCfg.MergePatchCc {
			to = append(to, patchResult.To...)
			cc = append(cc, patchResult.Cc...)
		}
		return &dashapi.PollExternalReportResp{
			Result: &dashapi.ReportPollResult{
				ID:          r.ID,
				CanUpstream: idx < len(nsCfg.AI.Stages)-1,
				To:          to,
				Cc:          cc,
				Patch:       patchResult,
			},
		}, nil
	}
	return &dashapi.PollExternalReportResp{}, nil
}

func makeNewReportResult(job *aidb.Job) (*dashapi.NewReportResult, error) {
	res, err := castJobResults[ai.PatchingOutputs](job)
	if err != nil {
		return nil, fmt.Errorf("failed to cast job results: %w", err)
	}
	if res.PatchDescription == "" {
		return nil, fmt.Errorf("patch generation result can't be empty")
	}
	lines := strings.Split(res.PatchDescription, "\n")
	if lines[0] == "" {
		return nil, fmt.Errorf("title line can't be empty")
	}
	subject := lines[0]
	var to, cc []string
	for _, rec := range res.Recipients {
		if rec.To {
			to = append(to, rec.Email)
		} else {
			cc = append(cc, rec.Email)
		}
	}
	return &dashapi.NewReportResult{
		Subject:    subject,
		Body:       res.PatchDescription,
		GitDiff:    res.PatchDiff,
		BaseCommit: res.KernelCommit,
		BaseTree:   res.KernelRepo,
		Version:    1, // TODO: track and increase it.
		To:         to,
		Cc:         cc,
	}, nil
}

func apiAIConfirmReport(ctx context.Context, req *dashapi.ConfirmPublishedReq) (any, error) {
	if err := aidb.JobReportingPublished(ctx, req.ReportID, req.PublishedExtID); err != nil {
		return nil, fmt.Errorf("failed to mark published: %w", err)
	}
	return nil, nil
}

func lookupJobByExtReq(ctx context.Context, req *dashapi.SendExternalCommandReq) (
	*aidb.JobReporting, *aidb.Job, error) {
	extID := req.RootExtID
	if extID == "" {
		return nil, nil, fmt.Errorf("RootExtID must be provided")
	}

	reporting, err := aidb.LoadJobReportingByExtID(ctx, extID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup job reporting: %w", err)
	}
	if reporting == nil {
		return nil, nil, dashapi.ErrReportNotFound
	}

	job, err := aidb.LoadJob(ctx, reporting.JobID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load job: %w", err)
	}
	if job == nil {
		return nil, nil, fmt.Errorf("job %v not found", reporting.ID)
	}
	return reporting, job, nil
}

func handleCommentCommand(ctx context.Context, req *dashapi.SendExternalCommandReq,
) (*dashapi.SendExternalCommandResp, error) {
	reporting, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	textID, err := putText(ctx, job.Namespace, textJobComment, []byte(req.Comment.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to store comment body: %w", err)
	}

	err = aidb.SaveJobComment(ctx, &aidb.JobComment{
		ReportingID: reporting.ID,
		ExtID:       req.MessageExtID,
		Author:      req.Author,
		BodyURI:     fmt.Sprintf("text://%v", textID),
		Date:        aidb.TimeNow(ctx),
	})
	if err != nil {
		return nil, err
	}

	return &dashapi.SendExternalCommandResp{}, nil
}
