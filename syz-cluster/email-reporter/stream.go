// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

type LKMLEmailStream struct {
	reporterName   string
	repoURL        string
	repoFolder     string
	client         *api.ReporterClient
	newMessages    chan *email.Email
	lastCommitDate time.Time
	lastCommit     string
}

func NewLKMLEmailStream(repoFolder, repoURL string, client *api.ReporterClient,
	writeTo chan *email.Email) *LKMLEmailStream {
	return &LKMLEmailStream{
		reporterName: api.LKMLReporter,
		repoURL:      repoURL,
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
	_, err := gitRepo.Poll(s.repoURL, "master")
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
		parsed, err := msg.Parse(nil, nil)
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
