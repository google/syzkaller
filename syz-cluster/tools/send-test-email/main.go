// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/emailclient"
)

func main() {
	ctx := context.Background()
	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to load config: %v", err)
	}
	emailConfig := cfg.EmailReporting
	if emailConfig == nil {
		app.Fatalf("reporting is not configured: %v", err)
	}
	sender, err := emailclient.MakeSender(ctx, emailConfig)
	if err != nil {
		app.Fatalf("failed to create a sender: %s", err)
	}
	sender(ctx, &emailclient.Email{
		Subject: "test email subject",
		To:      []string{emailConfig.ModerationList},
		Body:    []byte("an test email sent from syz-cluster"),
	})
}
