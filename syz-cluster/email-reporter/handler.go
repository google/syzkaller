// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/email/sender"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
	"github.com/google/syzkaller/syz-cluster/pkg/report"
)

var (
	ErrOwnEmail      = errors.New("email is from ourselves")
	ErrUnknownReport = errors.New("cannot identify report")
)

type Handler struct {
	reporter       string
	reporterClient *api.ReporterClient
	apiClient      *api.Client
	emailConfig    *app.EmailConfig
	sender         emailclient.Sender
}

func (h *Handler) PollReportsLoop(ctx context.Context, pollPeriod time.Duration) {
	defer log.Printf("reporter server polling aborted")
	log.Printf("reporter server polling started")

	for {
		_, err := h.PollAndReport(ctx)
		if err != nil {
			app.Errorf("%v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollPeriod):
		}
	}
}

func (h *Handler) PollAndReport(ctx context.Context) (*api.SessionReport, error) {
	reply, err := h.reporterClient.GetNextReport(ctx, h.reporter)
	if err != nil {
		return nil, fmt.Errorf("failed to poll the next report: %w", err)
	} else if reply == nil || reply.Report == nil {
		return nil, nil
	}
	report := reply.Report
	log.Printf("report %q is to be sent", report.ID)
	if err := h.report(ctx, report); err != nil {
		// TODO: consider retrying if the error happened before we attempted
		// to actually send the message.
		return nil, fmt.Errorf("failed to report %q: %w", report.ID, err)
	}
	return report, nil
}

func (h *Handler) report(ctx context.Context, rep *api.SessionReport) error {
	// Start by confirming the report - it's better to not send an email at all than to send it multiple times.
	err := h.reporterClient.ConfirmReport(ctx, rep.ID)
	if err != nil {
		return fmt.Errorf("failed to confirm: %w", err)
	}

	// Construct and send the message.
	body, err := report.Render(rep, h.emailConfig)
	if err != nil {
		// This should never be happening..
		return fmt.Errorf("failed to render the template: %w", err)
	}
	toSend := &sender.Email{
		Subject: "Re: " + rep.Series.Title, // TODO: use the original rather than the stripped title.
		To:      rep.Series.Cc,
		Body:    body,
		Cc:      []string{h.emailConfig.ArchiveList},
		BugID:   rep.ID,
	}
	if rep.Moderation {
		toSend.To = []string{h.emailConfig.ModerationList}
		toSend.Subject = "[moderation/CI] " + toSend.Subject
	} else {
		if h.emailConfig.Name != "" {
			toSend.Subject = fmt.Sprintf("[%s] %s", h.emailConfig.Name, toSend.Subject)
		}
		// We assume that email reporting is used for series received over emails.
		toSend.InReplyTo = rep.InReplyTo
		toSend.To = rep.Cc
		toSend.Cc = append(toSend.Cc, h.emailConfig.ReportCC...)
	}
	msgID, err := h.sender(ctx, toSend)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}
	// Senders may not always know the MessageID of the newly sent messages (that's the case of dashapi).
	if msgID != "" {
		// Record MessageID so that we could later trace user replies back to it.
		_, err = h.reporterClient.RecordReply(ctx, &api.RecordReplyReq{
			// TODO: for Lore emails, set Link = lore.Link(msgID).
			MessageID: msgID,
			Time:      time.Now(),
			ReportID:  rep.ID,
			Reporter:  h.reporter,
		})
		if err != nil {
			return fmt.Errorf("failed to record the reply for %s: %w",
				msgID, err)
		}
	}
	return nil
}

// IncomingEmail assumes that the related report ID is already extracted and resides in msg.BugIDs.
func (h *Handler) IncomingEmail(ctx context.Context, msg *email.Email) error {
	if len(msg.BugIDs) == 0 {
		// Unrelated email.
		return ErrUnknownReport
	}
	if msg.OwnEmail && !strings.HasPrefix(msg.Subject, email.ForwardedPrefix) {
		// We normally ignore our own emails, with the exception of the emails forwarded from the dashboard.
		return ErrOwnEmail
	}
	reportID := msg.BugIDs[0]

	var reply string
	for _, command := range msg.Commands {
		var err error
		switch command.Command {
		case email.CmdUpstream:
			// Reply nothing on success.
			err = h.reporterClient.UpstreamReport(ctx, reportID, &api.UpstreamReportReq{
				User: msg.Author,
			})
		case email.CmdInvalid:
			// Reply nothing on success.
			err = h.reporterClient.InvalidateReport(ctx, reportID)
		case email.CmdFix, email.CmdUnFix, email.CmdDup, email.CmdUnDup,
			email.CmdUnCC, email.CmdSet, email.CmdUnset,
			email.CmdRegenerate:
			reply = fmt.Sprintf("syzbot-ci does not support `%s` command", command.Str)
		case email.CmdTest:
			if command.Args != "" {
				reply = "syzbot-ci does not support `#syz test` with arguments."
			} else if msg.Patch == "" {
				reply = "Please attach the patch to act upon."
			} else {
				// Do not make noise by replying that we have started the job,
				// we'll come back to the user once it's finished.
				_, err = h.apiClient.SubmitJob(ctx, &api.SubmitJobRequest{
					Type:      api.JobPatchTest,
					ReportID:  reportID,
					Reporter:  h.reporter,
					User:      msg.Author,
					ExtID:     msg.MessageID,
					Cc:        append([]string{msg.Author}, msg.Cc...),
					PatchData: []byte(msg.Patch),
				})
			}
		default:
			reply = "Unknown command"
		}
		if err != nil {
			reply = fmt.Sprintf("Failed to process the command. Contact %s.",
				h.emailConfig.SupportEmail)
		}
	}

	if reply == "" {
		return nil
	}
	_, err := h.sender(ctx, &sender.Email{
		To:        []string{msg.Author},
		Cc:        msg.Cc,
		Subject:   "Re: " + msg.Subject,
		InReplyTo: msg.MessageID,
		Body:      []byte(email.FormReply(msg, reply)),
	})
	return err
}

func (h *Handler) ProcessPolledEmail(ctx context.Context, polled *lore.PolledEmail) error {
	parsed := polled.Email
	reportID := h.stripContextPrefix(parsed.Email)
	// Record reply for idempotency.
	res, err := h.reporterClient.RecordReply(ctx, &api.RecordReplyReq{
		MessageID:     parsed.MessageID,
		ReportID:      reportID,
		RootMessageID: polled.RootMessageID,
		Reporter:      h.reporter,
		Time:          parsed.Date,
	})
	if err != nil {
		return fmt.Errorf("failed to record reply: %w", err)
	}
	if res.ReportID == "" {
		if len(parsed.BugIDs) == 0 {
			return ErrUnknownReport
		}
	} else if !res.New {
		log.Printf("email %q: already seen, skipping", parsed.MessageID)
		return nil
	} else {
		parsed.BugIDs = []string{res.ReportID}
	}
	return h.IncomingEmail(ctx, parsed.Email)
}

func (h *Handler) stripContextPrefix(msg *email.Email) string {
	if h.emailConfig.Dashapi == nil || h.emailConfig.Dashapi.ContextPrefix == "" {
		return ""
	}
	prefix := h.emailConfig.Dashapi.ContextPrefix
	var reportID string
	for i, id := range msg.BugIDs {
		if strings.HasPrefix(id, prefix) {
			trimmed := strings.TrimPrefix(id, prefix)
			msg.BugIDs[i] = trimmed
			if reportID == "" {
				reportID = trimmed
			}
		}
	}
	return reportID
}
