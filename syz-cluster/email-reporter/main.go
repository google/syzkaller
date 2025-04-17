// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// NOTE: This app assumes that only one copy of it is runnning at the same time.

package main

import (
	"context"
	"log"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

// TODO: add extra sanity checks that would prevent flooding the mailing lists:
// - this pod may crash and be restarted by K8S: this complicates accounting,
// - the send operation might return an error, yet an email would be actually sent: back off on errors?

// How often to check whether there are new emails to be sent.
const pollPeriod = 30 * time.Second

func main() {
	ctx := context.Background()
	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to load config: %v", err)
	}
	if cfg.EmailReporting == nil {
		app.Fatalf("reporting is not configured: %v", err)
	}
	sender := &smtpSender{}
	handler := &Handler{
		apiClient:   app.DefaultReporterClient(),
		emailConfig: cfg.EmailReporting,
		sender:      sender.Send,
	}
	emailStream := NewLoreEmailStreamer()
	ch := make(chan *email.Email, 16)
	go func() {
		for newEmail := range ch {
			log.Printf("received email %q", newEmail.MessageID)
			err := handler.IncomingEmail(ctx, newEmail)
			if err != nil {
				// Note that we just print an error and go on instead of retrying.
				// Some retrying may be reasonable, but it also comes with a risk of flooding
				// the mailing lists.
				app.Errorf("email %q: failed to process: %v", newEmail.MessageID, err)
			}
		}
	}()
	go handler.PollReportsLoop(ctx, pollPeriod)
	go emailStream.Loop(ctx, ch)
}
