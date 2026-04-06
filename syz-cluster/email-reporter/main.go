// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// NOTE: This app assumes that only one copy of it is runnning at the same time.

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
	"golang.org/x/sync/errgroup"
)

// TODO: add extra sanity checks that would prevent flooding the mailing lists:
// - this pod may crash and be restarted by K8S: this complicates accounting,
// - the send operation might return an error, yet an email would be actually sent: back off on errors?

const (
	// How often to check whether there are new emails to be sent.
	senderPollPeriod = 30 * time.Second
	// How often to check whether there are new incoming emails.
	fetcherPollPeriod = 2 * time.Minute
)

func main() {
	ctx := context.Background()
	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to load config: %v", err)
	}
	if cfg.EmailReporting == nil {
		app.Fatalf("reporting is not configured: %v", err)
	}
	sender, err := emailclient.MakeSender(ctx, cfg.EmailReporting)
	if err != nil {
		app.Fatalf("failed to create a sender: %s", err)
	}
	reporterClient := app.DefaultReporterClient()
	handler := &Handler{
		reporter:       api.LKMLReporter,
		reporterClient: reporterClient,
		apiClient:      app.DefaultClient(),
		emailConfig:    cfg.EmailReporting,
		sender:         sender,
	}
	msgCh := make(chan *lore.PolledEmail, 16)
	eg, loopCtx := errgroup.WithContext(ctx)
	if cfg.EmailReporting.LoreArchiveURL != "" {
		poller, err := MakeLorePoller("/lore-repo/checkout", cfg.EmailReporting, msgCh)
		if err != nil {
			app.Fatalf("failed to create poller: %v", err)
		}
		eg.Go(func() error {
			err := poller.Loop(loopCtx, fetcherPollPeriod, msgCh)
			if err == context.Canceled {
				return nil
			}
			return err
		})
	}
	eg.Go(func() error {
		return runConsumerLoop(loopCtx, msgCh, handler)
	})
	eg.Go(func() error {
		handler.PollReportsLoop(loopCtx, senderPollPeriod)
		return nil
	})
	if err = eg.Wait(); err != nil {
		app.Errorf("failed: %s", err)
	}
}

func runConsumerLoop(ctx context.Context, msgCh <-chan *lore.PolledEmail, handler *Handler) error {
	for {
		select {
		case polled := <-msgCh:
			err := handler.ProcessPolledEmail(ctx, polled)
			if err != nil && !errors.Is(err, ErrOwnEmail) && !errors.Is(err, ErrUnknownReport) {
				app.Errorf("failed to process email: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func MakeLorePoller(repoDir string, emailCfg *app.EmailConfig, msgCh chan *lore.PolledEmail) (*lore.Poller, error) {
	var ownEmails []string
	if emailCfg.Dashapi != nil {
		ownEmails = append(ownEmails, emailCfg.Dashapi.From)
	}
	if emailCfg.SMTP != nil {
		ownEmails = append(ownEmails, emailCfg.SMTP.From)
	}
	return lore.NewPoller(lore.PollerConfig{
		RepoDir:   repoDir,
		URL:       emailCfg.LoreArchiveURL,
		OwnEmails: ownEmails,
		Tracer:    &debugtracer.GenericTracer{TraceWriter: os.Stdout, WithTime: true},
	})
}
