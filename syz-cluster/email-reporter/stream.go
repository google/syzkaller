// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

type LKMLEmailStream struct {
	cfg            *app.EmailConfig
	ownEmails      []string
	reporterName   string
	repoFolder     string
	client         *api.ReporterClient
	newMessages    chan *lore.Email
	lastCommitDate time.Time
	lastCommit     string
}

func NewLKMLEmailStream(repoFolder string, client *api.ReporterClient,
	cfg *app.EmailConfig, writeTo chan *lore.Email) *LKMLEmailStream {
	var ownEmails []string
	if cfg.Dashapi != nil {
		ownEmails = append(ownEmails, cfg.Dashapi.From)
	}
	if cfg.SMTP != nil {
		ownEmails = append(ownEmails, cfg.SMTP.From)
	}
	return &LKMLEmailStream{
		cfg:          cfg,
		ownEmails:    ownEmails,
		reporterName: api.LKMLReporter,
		repoFolder:   repoFolder,
		client:       client,
		newMessages:  writeTo,
	}
}

const (
	// Don't consider older replies.
	relevantPeriod = 7 * 24 * time.Hour
)

func (s *LKMLEmailStream) Loop(ctx context.Context, pollPeriod time.Duration) error {
	defer log.Printf("lore archive polling aborted")
	log.Printf("lore archive %s polling started", s.cfg.LoreArchiveURL)

	last, err := s.client.LastReply(ctx, s.reporterName)
	if err != nil {
		return fmt.Errorf("failed to query the last reply: %w", err)
	}
	// We assume that the archive mostly consists of relevant emails, so after the restart
	// we just start with the last saved message's date.
	s.lastCommitDate = time.Now().Add(-relevantPeriod)
	if last != nil && last.Time.After(s.lastCommitDate) {
		s.lastCommitDate = last.Time
	}
	for {
		err := s.fetchMessages(ctx)
		if err != nil {
			// Occasional errors are fine.
			log.Printf("failed to poll the lore archive messages: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollPeriod):
		}
	}
}

func (s *LKMLEmailStream) fetchMessages(ctx context.Context) error {
	gitRepo := vcs.NewLKMLRepo(s.repoFolder)
	_, err := gitRepo.Poll(s.cfg.LoreArchiveURL, "master")
	if err != nil {
		return err
	}
	var messages []lore.EmailReader
	if s.lastCommit != "" {
		// If it's not the first iteration, it's better to rely on the last commit hash.
		messages, err = lore.ReadArchive(gitRepo, s.lastCommit, time.Time{})
	} else {
		messages, err = lore.ReadArchive(gitRepo, "", s.lastCommitDate)
	}
	if err != nil {
		return err
	}
	// From oldest to newest.
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		parsed, err := msg.Parse(s.ownEmails, nil)
		if err != nil || parsed == nil {
			log.Printf("failed to parse the email from hash %q: %v", msg.Hash, err)
			continue
		}
		if msg.CommitDate.After(s.lastCommitDate) {
			s.lastCommitDate = msg.CommitDate
		}
		s.lastCommit = msg.Hash

		// We cannot fully trust the date specified in the message itself, so let's sanitize it
		// using the commit date. It will at least help us prevent weird client.lastReply() responses.
		messageDate := parsed.Date
		if messageDate.After(msg.CommitDate) {
			messageDate = msg.CommitDate
		}
		resp, err := s.client.RecordReply(ctx, &api.RecordReplyReq{
			MessageID: parsed.MessageID,
			ReportID:  s.extractMessageID(parsed),
			InReplyTo: parsed.InReplyTo,
			Reporter:  s.reporterName,
			Time:      messageDate,
		})
		if err != nil || resp == nil {
			// TODO: retry?
			app.Errorf("failed to report email %q: %v", parsed.MessageID, err)
			continue
		} else if resp.ReportID != "" {
			if !resp.New {
				continue
			}
			parsed.BugIDs = []string{resp.ReportID}
		}
		select {
		case s.newMessages <- parsed:
		case <-ctx.Done():
		}
	}
	return nil
}

// If the message was sent via the dashapi sender, the report ID wil be a part of the email address.
func (s *LKMLEmailStream) extractMessageID(msg *lore.Email) string {
	if s.cfg.Dashapi == nil {
		// The mode is not configured.
		return ""
	}
	for _, id := range msg.BugIDs {
		if strings.HasPrefix(id, s.cfg.Dashapi.ContextPrefix) {
			return strings.TrimPrefix(id, s.cfg.Dashapi.ContextPrefix)
		}
	}
	return ""
}
