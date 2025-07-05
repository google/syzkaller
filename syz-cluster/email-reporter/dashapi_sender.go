// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

func makeDashapiSender(cfg *app.EmailConfig) (SendEmailCb, error) {
	dash, err := dashapi.New(cfg.Dashapi.Client, cfg.Dashapi.Addr, "")
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, item *EmailToSend) (string, error) {
		sender := cfg.Dashapi.From
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
