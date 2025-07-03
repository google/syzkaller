// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// NOTE: This app assumes that only one copy of it is runnning at the same time.

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
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
	sender, err := makeSender(ctx, cfg.EmailReporting)
	if err != nil {
		app.Fatalf("failed to create a sender: %s", err)
	}
	reporterClient := app.DefaultReporterClient()
	handler := &Handler{
		reporter:    api.LKMLReporter,
		apiClient:   reporterClient,
		emailConfig: cfg.EmailReporting,
		sender:      sender,
	}
	msgCh := make(chan *email.Email, 16)
	eg, loopCtx := errgroup.WithContext(ctx)
	if cfg.EmailReporting.LoreArchiveURL != "" {
		fetcher := NewLKMLEmailStream("/lore-repo",
			cfg.EmailReporting.LoreArchiveURL, reporterClient, msgCh)
		eg.Go(func() error { return fetcher.Loop(loopCtx, fetcherPollPeriod) })
	}
	eg.Go(func() error {
		for {
			var newEmail *email.Email
			select {
			case newEmail = <-msgCh:
			case <-loopCtx.Done():
				return nil
			}
			log.Printf("received email %q", newEmail.MessageID)
			err := handler.IncomingEmail(loopCtx, newEmail)
			if err != nil {
				// Note that we just print an error and go on instead of retrying.
				// Some retrying may be reasonable, but it also comes with a risk of flooding
				// the mailing lists.
				app.Errorf("email %q: failed to process: %v", newEmail.MessageID, err)
			}
		}
	})
	eg.Go(func() error {
		handler.PollReportsLoop(loopCtx, senderPollPeriod)
		return nil
	})
	eg.Wait()
}

func makeSender(ctx context.Context, cfg *app.EmailConfig) (SendEmailCb, error) {
	if cfg.Sender == app.SenderSMTP {
		sender, err := newSMTPSender(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return sender.Send, nil
	} else if cfg.Sender == app.SenderDashapi {
		return makeDashapiSender(cfg)
	}
	return nil, fmt.Errorf("unsupported sender type: %q", cfg.Sender)
}

type EmailToSend struct {
	To        []string
	Cc        []string
	Subject   string
	InReplyTo string
	Body      []byte
	BugID     string // In case it's to be included into Sender.
}

func (item *EmailToSend) recipients() []string {
	var ret []string
	ret = append(ret, item.To...)
	ret = append(ret, item.Cc...)
	return unique(ret)
}

func unique(list []string) []string {
	var ret []string
	seen := map[string]struct{}{}
	for _, str := range list {
		if _, ok := seen[str]; ok {
			continue
		}
		seen[str] = struct{}{}
		ret = append(ret, str)
	}
	return ret
}
