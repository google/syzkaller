// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"slices"
	"strings"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"google.golang.org/appengine/v2/log"
)

const SourceWebUI = "web ui"

func apiAIReportCommand(ctx context.Context, req *dashapi.SendExternalCommandReq) (any, error) {
	if req.Source != "" && req.MessageExtID != "" {
		processed, err := aidb.IsCommandProcessed(ctx, string(req.Source), req.MessageExtID)
		if err != nil {
			return nil, err
		}
		if processed {
			return &dashapi.SendExternalCommandResp{}, nil // Idempotent no-op.
		}
	}

	var resp *dashapi.SendExternalCommandResp
	var err error
	if req.Upstream != nil {
		resp, err = handleUpstreamCommand(ctx, req)
	} else if req.Reject != nil {
		resp, err = handleRejectCommand(ctx, req)
	} else if req.Unreject != nil {
		resp, err = handleUnrejectCommand(ctx, req)
	} else if req.Comment != nil {
		resp, err = handleCommentCommand(ctx, req)
	} else {
		return nil, fmt.Errorf("unknown command")
	}

	if err != nil {
		if errors.Is(err, dashapi.ErrReportNotFound) {
			return &dashapi.SendExternalCommandResp{Error: dashapi.ErrReportNotFound.Error()}, nil
		}
		return nil, err
	}
	return resp, nil
}

// nolint: dupl
func handleUpstreamCommand(ctx context.Context, req *dashapi.SendExternalCommandReq,
) (*dashapi.SendExternalCommandResp, error) {
	reporting, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	err = processUpstreamSubcommand(ctx, job, reporting, req)
	if err != nil {
		var cannotUpstreamErr *aidb.ErrCannotUpstream
		if errors.As(err, &cannotUpstreamErr) {
			// We log logical rejection errors to the Journal so that IsCommandProcessed
			// returns true on subsequent retries (e.g., if lore-relay restarts). This prevents
			// lore-relay from sending duplicate "Command failed" emails to the user.
			if req.Source != "" && req.MessageExtID != "" {
				_ = aidb.LogCommandError(ctx, aidb.LogCommandErrorArgs{
					JobID:         job.ID,
					ReportingID:   reporting.ID,
					CommandSource: string(req.Source),
					CommandExtID:  req.MessageExtID,
					User:          req.Author,
					Action:        aidb.ActionApprove,
					Error:         cannotUpstreamErr.Reason,
				})
			}
			return &dashapi.SendExternalCommandResp{Error: cannotUpstreamErr.Reason}, nil
		}
		return nil, err
	}

	return &dashapi.SendExternalCommandResp{}, nil
}

func formatUpstreamedBy(name, email string) string {
	if name != "" {
		return fmt.Sprintf("%s <%s>", name, email)
	}
	return email
}

func processUpstreamSubcommand(ctx context.Context, job *aidb.Job,
	currentReporting *aidb.JobReporting, req *dashapi.SendExternalCommandReq) error {
	if err := checkJobUpstreamable(job); err != nil {
		return err
	}

	upstreamedBy := formatUpstreamedBy(req.AuthorName, req.Author)

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
			UpstreamedBy: spanner.NullString{StringVal: upstreamedBy, Valid: upstreamedBy != ""},
			Version:      spanner.NullInt64{Int64: 1, Valid: true},
		},
		NoParallel:    nextStageCfg.NoParallelReports,
		CommandSource: string(req.Source),
		CommandExtID:  req.MessageExtID,
		User:          req.Author,
		Reason:        "",
	})
}

func aiJobUsesReportingStages(ctx context.Context, job *aidb.Job) bool {
	nsCfg := getNsConfig(ctx, job.Namespace)
	if nsCfg.AI == nil || len(nsCfg.AI.Stages) == 0 {
		return false
	}
	return job.Type == ai.WorkflowPatching || job.Type == ai.WorkflowPatchIteration
}

func checkJobUpstreamable(job *aidb.Job) error {
	if job.Type != ai.WorkflowPatching && job.Type != ai.WorkflowPatchIteration {
		return &aidb.ErrCannotUpstream{Reason: fmt.Sprintf("cannot upstream job of type %v", job.Type)}
	}
	// Prevent upstreaming if the job didn't actually produce a patch (e.g. reply-only iteration).
	if job.Results.Valid {
		if res, ok := job.Results.Value.(map[string]any); ok {
			diff, _ := res["PatchDiff"].(string)
			if diff == "" {
				return &aidb.ErrCannotUpstream{Reason: "Cannot upstream a job that did not produce a patch."}
			}
		}
	}
	return nil
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

// nolint: dupl
func handleRejectCommand(ctx context.Context,
	req *dashapi.SendExternalCommandReq) (*dashapi.SendExternalCommandResp, error) {
	reporting, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	reason := ""
	if req.Reject != nil {
		reason = req.Reject.Reason
	}

	err = aidb.RejectReportCommand(ctx, aidb.RejectReportArgs{
		Job:           job,
		ReportingID:   reporting.ID,
		CommandSource: string(req.Source),
		CommandExtID:  req.MessageExtID,
		User:          req.Author,
		Reason:        reason,
	})
	if err != nil {
		var cannotRejectErr *aidb.ErrCannotReject
		if errors.As(err, &cannotRejectErr) {
			if req.Source != "" && req.MessageExtID != "" {
				_ = aidb.LogCommandError(ctx, aidb.LogCommandErrorArgs{
					JobID:         job.ID,
					ReportingID:   reporting.ID,
					CommandSource: string(req.Source),
					CommandExtID:  req.MessageExtID,
					User:          req.Author,
					Action:        aidb.ActionReject,
					Error:         cannotRejectErr.Reason,
				})
			}
			return &dashapi.SendExternalCommandResp{Error: cannotRejectErr.Reason}, nil
		}
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
		if job.Type != ai.WorkflowPatching && job.Type != ai.WorkflowPatchIteration {
			log.Errorf(ctx, "unsupported job type for external reporting: %s (job %v)", job.Type, job.ID)
			return nil, fmt.Errorf("unsupported job type: %s", job.Type)
		}

		version := 1
		if r.Version.Valid {
			version = int(r.Version.Int64)
		}

		result := &dashapi.ReportPollResult{
			ID: r.ID,
		}

		var authors []string
		if r.UpstreamedBy.Valid && r.UpstreamedBy.StringVal != "" {
			authors = append(authors, r.UpstreamedBy.StringVal)
		}

		switch job.Type {
		case ai.WorkflowPatching:
			res, err := castJobResults[ai.PatchingOutputs](job)
			if err != nil {
				return nil, fmt.Errorf("failed to cast job results: %w", err)
			}
			result.Patch, err = makeNewReportResult(ctx, job, &res, version, authors)
			if err != nil {
				return nil, err
			}
		case ai.WorkflowPatchIteration:
			err = populateIterationReportResult(ctx, job, version, r.Stage, result, authors)
			if err != nil {
				return nil, err
			}
		}

		if result.Patch != nil {
			var links []string
			var closes []string
			if job.BugID.Valid {
				link, reporter := jobBugInfo(ctx, job.BugID)
				closes = append(closes, link)
				if reporter != "" && !slices.Contains(result.Patch.ReportedBy, reporter) {
					result.Patch.ReportedBy = append([]string{reporter}, result.Patch.ReportedBy...)
				}
			}
			links = append(links, fmt.Sprintf("%s/ai_job?id=%s", appURL(ctx), job.ID))
			result.Patch.Links = links
			result.Patch.Closes = closes
		}

		result.To = []string{stageCfg.MailingList}
		if stageCfg.MergePatchCc && result.Patch != nil {
			result.To = append(result.To, result.Patch.To...)
			result.Cc = append(result.Cc, result.Patch.Cc...)
		}

		result.CanUpstream = idx < len(nsCfg.AI.Stages)-1
		if result.Patch == nil {
			result.CanUpstream = false
		}

		return &dashapi.PollExternalReportResp{
			Result: result,
		}, nil
	}
	return &dashapi.PollExternalReportResp{}, nil
}

func makeNewReportResult(ctx context.Context, job *aidb.Job, res *ai.PatchingOutputs,
	version int, authors []string) (*dashapi.NewReportResult, error) {
	if res.PatchDescription == "" {
		return nil, fmt.Errorf("patch generation result can't be empty")
	}

	subject, body, _ := strings.Cut(res.PatchDescription, "\n")
	subject = strings.TrimSpace(subject)
	body = strings.Trim(body, "\n\r")

	if subject == "" {
		return nil, fmt.Errorf("title line can't be empty")
	}

	trajectory, err := aidb.LoadTrajectory(ctx, job.ID)
	if err != nil {
		return nil, err
	}
	models := make(map[string]bool)
	for _, span := range trajectory {
		if span.Model != "" {
			models[span.Model] = true
		}
	}
	var to, cc []string
	for _, rec := range res.Recipients {
		addr := mail.Address{Name: rec.Name, Address: rec.Email}
		if rec.To {
			to = append(to, addr.String())
		} else {
			cc = append(cc, addr.String())
		}
	}

	return &dashapi.NewReportResult{
		Subject:    subject,
		Body:       body,
		GitDiff:    res.PatchDiff,
		BaseCommit: res.KernelCommit,
		BaseTree:   res.KernelRepo,
		Version:    version,
		To:         to,
		Cc:         cc,
		Tools:      slices.Collect(maps.Keys(models)),
		Authors:    authors,
		Fixes:      res.Fixes,
		ReviewedBy: res.ReviewedBy,
		AckedBy:    res.AckedBy,
		TestedBy:   res.TestedBy,
		ReportedBy: res.ReportedBy,
	}, nil
}

func populateIterationReportResult(ctx context.Context, job *aidb.Job, version int,
	currentStage string, result *dashapi.ReportPollResult, authors []string) error {
	res, err := castJobResults[ai.PatchIterationOutputs](job)
	if err != nil {
		return fmt.Errorf("failed to cast job results: %w", err)
	}

	if res.PatchDiff != "" {
		result.Patch, err = makeNewReportResult(ctx, job, &ai.PatchingOutputs{
			KernelRepo:       res.KernelRepo,
			KernelBranch:     res.KernelBranch,
			KernelCommit:     res.KernelCommit,
			PatchDescription: res.PatchDescription,
			PatchDiff:        res.PatchDiff,
			Recipients:       res.Recipients,
			Fixes:            res.Fixes,
			ReviewedBy:       res.ReviewedBy,
			AckedBy:          res.AckedBy,
			TestedBy:         res.TestedBy,
			ReportedBy:       res.ReportedBy,
		}, version, authors)
		if err != nil {
			return err
		}
		result.Patch.Changelog = collectChangelog(ctx, job.ID, currentStage)
	} else if len(res.Replies) > 0 {
		var comments []*aidb.JobComment
		if job.ParentReportingID.Valid {
			comments, _ = aidb.LoadJobCommentsByReporting(ctx, job.ParentReportingID.StringVal)
		}

		for _, r := range res.Replies {
			author := ""
			for _, c := range comments {
				if c.ExtID == r.ReplyTo {
					author = c.Author
					if result.ThreadSubject == "" && c.Subject.Valid && c.Subject.StringVal != "" {
						result.ThreadSubject = c.Subject.StringVal
					}
					break
				}
			}
			result.Replies = append(result.Replies, &dashapi.ReplyResult{
				Quote:       r.Quote,
				Body:        r.Text,
				ReplyExtID:  r.ReplyTo,
				ReplyAuthor: author,
			})
		}
	}
	return nil
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

// nolint: dupl
func handleUnrejectCommand(ctx context.Context,
	req *dashapi.SendExternalCommandReq) (*dashapi.SendExternalCommandResp, error) {
	reporting, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	err = aidb.UnrejectReportCommand(ctx, aidb.UnrejectReportArgs{
		Job:           job,
		ReportingID:   reporting.ID,
		CommandSource: string(req.Source),
		CommandExtID:  req.MessageExtID,
		User:          req.Author,
	})
	if err != nil {
		var cannotUnrejectErr *aidb.ErrCannotUnreject
		if errors.As(err, &cannotUnrejectErr) {
			if req.Source != "" && req.MessageExtID != "" {
				_ = aidb.LogCommandError(ctx, aidb.LogCommandErrorArgs{
					JobID:         job.ID,
					ReportingID:   reporting.ID,
					CommandSource: string(req.Source),
					CommandExtID:  req.MessageExtID,
					User:          req.Author,
					Action:        aidb.ActionUnreject,
					Error:         cannotUnrejectErr.Reason,
				})
			}
			return &dashapi.SendExternalCommandResp{Error: cannotUnrejectErr.Reason}, nil
		}
		return nil, err
	}

	return &dashapi.SendExternalCommandResp{}, nil
}

func handleCommentCommand(ctx context.Context,
	req *dashapi.SendExternalCommandReq) (*dashapi.SendExternalCommandResp, error) {
	reporting, job, err := lookupJobByExtReq(ctx, req)
	if err != nil {
		return nil, err
	}

	textID, err := putText(ctx, job.Namespace, textJobComment, []byte(req.Comment.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to store comment body: %w", err)
	}

	err = aidb.SaveJobComment(ctx, &aidb.JobComment{
		ReportingID:  reporting.ID,
		ExtID:        req.MessageExtID,
		Subject:      spanner.NullString{StringVal: req.Comment.Subject, Valid: req.Comment.Subject != ""},
		Author:       req.Author,
		BodyURI:      fmt.Sprintf("text://%v", textID),
		Date:         aidb.TimeNow(ctx),
		OwnEmail:     req.OwnEmail,
		Processed:    req.OwnEmail,
		VerifiedDKIM: req.DKIM,
	})
	if err != nil && !errors.Is(err, aidb.ErrDuplicateComment) {
		return nil, err
	}

	return &dashapi.SendExternalCommandResp{}, nil
}
