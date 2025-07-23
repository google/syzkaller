// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package emailclient

import (
	"context"
	"fmt"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

type Email struct {
	To        []string
	Cc        []string
	Subject   string
	InReplyTo string
	Body      []byte
	BugID     string // In case it's to be included into Sender.
}

func (item *Email) recipients() []string {
	var ret []string
	ret = append(ret, item.To...)
	ret = append(ret, item.Cc...)
	return unique(ret)
}

type Sender func(context.Context, *Email) (string, error)

func MakeSender(ctx context.Context, cfg *app.EmailConfig) (Sender, error) {
	switch cfg.Sender {
	case app.SenderSMTP:
		sender, err := newSMTPSender(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return sender.Send, nil
	case app.SenderDashapi:
		return makeDashapiSender(cfg)
	}
	return nil, fmt.Errorf("unsupported sender type: %q", cfg.Sender)
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

func TestEmailConfig() *app.EmailConfig {
	return &app.EmailConfig{
		Name:           "name",
		DocsLink:       "docs",
		ModerationList: "moderation@list.com",
		ReportCC:       []string{"reported@list.com"},
		ArchiveList:    "archive@list.com",
		Sender:         app.SenderSMTP,
		SMTP: &app.SMTPConfig{
			From: "a@b.com",
		},
	}
}
