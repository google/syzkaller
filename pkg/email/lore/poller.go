// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// The approach uses an in-memory graph of ancestors (Message-ID -> In-Reply-To)
// to resolve the root of any email thread. This is acceptable as long as the
// archive size is reasonable and fits in memory.
package lore

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
)

type PollerConfig struct {
	RepoDir   string
	URL       string
	Tracer    debugtracer.DebugTracer
	OwnEmails []string
	now       func() time.Time // for testing
}

type PolledEmail struct {
	Email         *Email
	RootMessageID string
}

type Poller struct {
	cfg         PollerConfig
	repo        vcs.Repo
	ancestors   map[string]string // Message-ID -> In-Reply-To.
	lastCommit  string
	initialized bool
}

func NewPoller(cfg PollerConfig) (*Poller, error) {
	if cfg.Tracer == nil {
		cfg.Tracer = &debugtracer.NullTracer{}
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.RepoDir == "" {
		return nil, fmt.Errorf("RepoDir must be specified")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("URL must be specified")
	}
	return &Poller{
		cfg:       cfg,
		ancestors: make(map[string]string),
	}, nil
}

func (p *Poller) Poll(ctx context.Context, out chan<- *PolledEmail) error {
	if !p.initialized {
		if err := p.initialize(ctx); err != nil {
			return err
		}
		p.initialized = true
	}
	_, err := p.repo.Poll(p.cfg.URL, "master")
	if err != nil {
		return fmt.Errorf("git poll failed: %w", err)
	}
	var messages []EmailReader
	if p.lastCommit != "" {
		messages, err = ReadArchive(p.repo, p.lastCommit, time.Time{})
	} else {
		since := p.cfg.now().Add(-24 * time.Hour)
		messages, err = ReadArchive(p.repo, "", since)
	}
	if err != nil {
		return fmt.Errorf("failed to read archive: %w", err)
	}
	for _, er := range slices.Backward(messages) {
		parsed, err := er.Parse(p.cfg.OwnEmails, nil)
		if err != nil {
			p.cfg.Tracer.Logf("failed to parse email %s: %v", er.Hash, err)
			continue
		}
		// We cannot fully trust the date specified in the message itself, so let's sanitize it
		// using the commit date.
		if parsed.Date.After(er.CommitDate) {
			parsed.Date = er.CommitDate
		}
		if parsed.MessageID == "" {
			p.cfg.Tracer.Logf("ignoring email without Message-ID %s", er.Hash)
			continue
		}
		p.ancestors[parsed.MessageID] = parsed.InReplyTo
		if err := p.push(ctx, parsed, parsed.MessageID, out); err != nil {
			return err
		}
		p.lastCommit = er.Hash
	}
	return nil
}

func (p *Poller) initialize(ctx context.Context) error {
	p.repo = vcs.NewLKMLRepo(p.cfg.RepoDir)
	p.cfg.Tracer.Logf("initialize: polling %s branch master", p.cfg.URL)
	_, err := p.repo.Poll(p.cfg.URL, "master")
	if err != nil {
		return fmt.Errorf("initial git poll failed: %w", err)
	}
	messages, err := ReadArchive(p.repo, "", time.Time{})
	if err != nil {
		return fmt.Errorf("failed to read archive for initialization: %w", err)
	}
	for _, er := range messages {
		body, err := er.Read()
		if err != nil {
			return fmt.Errorf("failed to read email %s: %w", er.Hash, err)
		}
		msg, err := mail.ReadMessage(bytes.NewReader(body))
		if err != nil {
			p.cfg.Tracer.Logf("failed to parse email headers %s: %v", er.Hash, err)
			continue
		}
		msgID := msg.Header.Get("Message-ID")
		if msgID == "" {
			continue
		}
		inReplyTo := email.ExtractInReplyTo(msg.Header)
		p.ancestors[msgID] = inReplyTo
	}
	return nil
}

func (p *Poller) push(ctx context.Context, email *Email, msgID string, out chan<- *PolledEmail) error {
	root := p.resolveRoot(msgID)
	if root == "" {
		return nil // Skip loops.
	}
	select {
	case out <- &PolledEmail{
		Email:         email,
		RootMessageID: root,
	}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Poller) resolveRoot(msgID string) string {
	visited := make(map[string]bool)
	current := msgID
	for {
		parent, ok := p.ancestors[current]
		if !ok || parent == "" {
			return current
		}
		if visited[parent] {
			return "" // Loop detected.
		}
		visited[current] = true
		current = parent
	}
}

func (p *Poller) Loop(ctx context.Context, pollPeriod time.Duration, out chan<- *PolledEmail) error {
	ticker := time.NewTicker(pollPeriod)
	defer ticker.Stop()
	for {
		if err := p.Poll(ctx, out); err != nil {
			p.cfg.Tracer.Logf("poller error: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
