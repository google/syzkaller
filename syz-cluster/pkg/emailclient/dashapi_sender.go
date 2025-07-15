// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package emailclient

import (
	"context"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"net/mail"
)

func makeDashapiSender(cfg *app.EmailConfig) (Sender, error) {
	dash, err := dashapi.New(cfg.Dashapi.Client, cfg.Dashapi.Addr, "")
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, item *Email) (string, error) {
		sender := (&mail.Address{
			Name:    cfg.Name,
			Address: cfg.Dashapi.From,
		}).String()
		if item.BugID != "" {
			var err error
			sender, err = email.AddAddrContext(sender, cfg.Dashapi.ContextPrefix+item.BugID)
			if err != nil {
				return "", err
			}
		}
		return "", dash.SendEmail(&dashapi.SendEmailReq{
			Sender:    sender,
			To:        item.To,
			Cc:        item.Cc,
			Subject:   cfg.SubjectPrefix + item.Subject,
			InReplyTo: item.InReplyTo,
			Body:      string(item.Body),
		})
	}, nil
}
