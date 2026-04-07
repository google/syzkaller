// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lorerelay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/email/sender"
	"golang.org/x/sync/errgroup"
)

// DashboardClient defines the subset of dashapi.Dashboard required by the relay.
type DashboardClient interface {
	AIReportCommand(req *dashapi.SendExternalCommandReq) (*dashapi.SendExternalCommandResp, error)
	AIPollReport(req *dashapi.PollExternalReportReq) (*dashapi.PollExternalReportResp, error)
	AIConfirmReport(req *dashapi.ConfirmPublishedReq) error
}

// Config holds configuration for the Lore Relay.
type Config struct {
	// DashboardPollInterval is how often to poll the Dashboard for new reports.
	DashboardPollInterval time.Duration `yaml:"dashboard_poll_interval"`
	// LorePollInterval is how often to poll Lore archive.
	LorePollInterval time.Duration `yaml:"lore_poll_interval"`
	// DocsLink is the link to the documentation.
	DocsLink string `yaml:"docs_link"`
	// Tracer is used for debug logging.
	Tracer debugtracer.DebugTracer `yaml:"-"`
	// LoreArchive is an optional mailing list that will be added to Cc on all sent emails.
	LoreArchive string `yaml:"lore_archive"`
}

// Relay orchestrates the flow between Lore and Dashboard.
type Relay struct {
	cfg         *Config
	dash        DashboardClient
	poller      *lore.Poller
	emailSender sender.Sender
	emailChan   chan *lore.PolledEmail
	backoffs    []time.Duration
}

// NewRelay creates a new Relay instance.
func NewRelay(cfg *Config, dash DashboardClient, poller *lore.Poller,
	emailSender sender.Sender) *Relay {
	if cfg.Tracer == nil {
		cfg.Tracer = &debugtracer.NullTracer{}
	}
	if cfg.DashboardPollInterval == 0 {
		cfg.DashboardPollInterval = 30 * time.Second
	}
	if cfg.LorePollInterval == 0 {
		cfg.LorePollInterval = 5 * time.Minute
	}
	emailChan := make(chan *lore.PolledEmail, 16)
	return &Relay{
		cfg:         cfg,
		dash:        dash,
		poller:      poller,
		emailSender: emailSender,
		emailChan:   emailChan,
		backoffs:    []time.Duration{5 * time.Second, 30 * time.Second, 60 * time.Second},
	}
}

// Run starts the relay loop.
func (r *Relay) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		r.cfg.Tracer.Logf("starting lore poller loop")
		return r.poller.Loop(ctx, r.cfg.LorePollInterval, r.emailChan)
	})
	g.Go(func() error {
		r.cfg.Tracer.Logf("starting dashboard poller loop")
		return r.pollDashboard(ctx)
	})
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case polled := <-r.emailChan:
				if err := r.HandleIncomingEmail(ctx, polled); err != nil {
					log.Printf("failed to handle incoming email: %v", err)
				}
			}
		}
	})

	return g.Wait()
}

func (r *Relay) pollDashboard(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.DashboardPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.PollDashboardOnce(ctx); err != nil {
				log.Printf("failed to poll dashboard: %v", err)
			}
		}
	}
}

// PollDashboardOnce performs a single poll of the dashboard.
// Exported for testing.
func (r *Relay) PollDashboardOnce(ctx context.Context) error {
	r.cfg.Tracer.Logf("polling dashboard for reports")
	resp, err := r.dash.AIPollReport(&dashapi.PollExternalReportReq{Source: "lore"})
	if err != nil {
		return err
	}
	if resp.Result == nil {
		return nil
	}
	body, err := RenderBody(r.cfg, resp.Result)
	if err != nil {
		return err
	}
	subject := GenerateSubject(resp.Result)
	cc := slices.Clone(resp.Result.Cc)
	if r.cfg.LoreArchive != "" {
		cc = append(cc, r.cfg.LoreArchive)
	}
	email := &sender.Email{
		To:      resp.Result.To,
		Cc:      cc,
		Subject: subject,
		Body:    []byte(body),
	}
	r.cfg.Tracer.Logf("sending email: %s", subject)
	msgID, err := r.emailSender.Send(ctx, email)
	if err != nil {
		return err
	}
	return r.dash.AIConfirmReport(&dashapi.ConfirmPublishedReq{
		ReportID:       resp.Result.ID,
		PublishedExtID: msgID,
	})
}

// PollLoreOnce polls the lore archive once and processes all received emails.
func (r *Relay) PollLoreOnce(ctx context.Context) error {
	if err := r.poller.Poll(ctx, r.emailChan); err != nil {
		return err
	}
	for {
		select {
		case polled := <-r.emailChan:
			if err := r.HandleIncomingEmail(ctx, polled); err != nil {
				log.Printf("failed to handle incoming email: %v", err)
			}
		default:
			return nil
		}
	}
}

func (r *Relay) HandleIncomingEmail(ctx context.Context, polled *lore.PolledEmail) error {
	r.cfg.Tracer.Logf("handling incoming email from %s", polled.Email.Author)
	reqs := extractCommands(polled)
	if len(reqs) == 0 {
		return nil
	}
	if len(reqs) > 1 {
		return r.replyError(ctx, polled, "multiple commands in a single message are not supported")
	}
	var resp *dashapi.SendExternalCommandResp
	var err error
	backoffs := r.backoffs
	for i := 0; ; i++ {
		resp, err = r.dash.AIReportCommand(reqs[0])
		if err == nil {
			break
		}
		if errors.Is(err, dashapi.ErrReportNotFound) {
			return nil // Stay silent.
		}
		if i >= len(backoffs) {
			return fmt.Errorf("API call failed after %d retries: %w", len(backoffs), err)
		}
		r.cfg.Tracer.Logf("API call failed: %v, retrying in %v", err, backoffs[i])
		select {
		case <-time.After(backoffs[i]):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if resp.Error != "" {
		return r.replyError(ctx, polled, resp.Error)
	}
	return nil
}

func (r *Relay) replyError(ctx context.Context, polled *lore.PolledEmail, errorMsg string) error {
	subj := polled.Email.Subject
	if !strings.HasPrefix(strings.ToLower(subj), "re:") {
		subj = "Re: " + subj
	}
	email := &sender.Email{
		To:        []string{polled.Email.Author},
		Subject:   subj,
		InReplyTo: polled.Email.MessageID,
		Body:      []byte(email.FormReply(polled.Email.Email, fmt.Sprintf("Command failed:\n\n%s\n", errorMsg))),
	}
	_, err := r.emailSender.Send(ctx, email)
	return err
}
