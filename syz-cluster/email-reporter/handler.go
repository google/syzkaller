// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/email"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
	"github.com/google/syzkaller/syz-cluster/pkg/report"
)

type Handler struct {
	reporter    string
	apiClient   *api.ReporterClient
	emailConfig *app.EmailConfig
	sender      emailclient.Sender
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
	reply, err := h.apiClient.GetNextReport(ctx, h.reporter)
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
	err := h.apiClient.ConfirmReport(ctx, rep.ID)
	if err != nil {
		return fmt.Errorf("failed to confirm: %w", err)
	}

	// Construct and send the message.
	body, err := report.Render(rep, h.emailConfig)
	if err != nil {
		// This should never be happening..
		return fmt.Errorf("failed to render the template: %w", err)
	}
	toSend := &emailclient.Email{
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
		toSend.InReplyTo = rep.Series.ExtID
		toSend.To = rep.Series.Cc
		toSend.Cc = append(toSend.Cc, h.emailConfig.ReportCC...)
	}
	msgID, err := h.sender(ctx, toSend)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}
	// Senders may not always know the MessageID of the newly sent messages (that's the case of dashapi).
	if msgID != "" {
		// Record MessageID so that we could later trace user replies back to it.
		_, err = h.apiClient.RecordReply(ctx, &api.RecordReplyReq{
			// TODO: for Lore emails, set Link = lore.Link(msgID).
			MessageID: msgID,
			Time:      time.Now(),
			ReportID:  rep.ID,
			Reporter:  h.reporter,
		})
		if err != nil {
			return fmt.Errorf("failed to record the reply: %w", err)
		}
	}
	return nil
}

// IncomingEmail assumes that the related report ID is already extracted and resides in msg.BugIDs.
func (h *Handler) IncomingEmail(ctx context.Context, msg *email.Email) error {
	if len(msg.BugIDs) == 0 {
		// Unrelated email.
		return nil
	}
	if msg.OwnEmail && !strings.HasPrefix(msg.Subject, email.ForwardedPrefix) {
		// We normally ignore our own emails, with the exception of the emails forwarded from the dashboard.
		return nil
	}
	reportID := msg.BugIDs[0]

	var reply string
	for _, command := range msg.Commands {
		var err error
		switch command.Command {
		case email.CmdUpstream:
			// Reply nothing on success.
			err = h.apiClient.UpstreamReport(ctx, reportID, &api.UpstreamReportReq{
				User: msg.Author,
			})
		case email.CmdInvalid:
			// Reply nothing on success.
			err = h.apiClient.InvalidateReport(ctx, reportID)
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
	_, err := h.sender(ctx, &emailclient.Email{
		To:        []string{msg.Author},
		Cc:        msg.Cc,
		Subject:   "Re: " + msg.Subject,
		InReplyTo: msg.MessageID,
		Body:      []byte(email.FormReply(msg, reply)),
	})
	return err
}
