// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sender

import (
	"context"
	"net/mail"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
)

// DashapiConfig holds configuration for the Dashapi sender.
type DashapiConfig struct {
	Client        string
	Addr          string
	From          mail.Address
	ContextPrefix string
	SubjectPrefix string
}

type dashapiSender struct {
	cfg  DashapiConfig
	dash *dashapi.Dashboard
}

// NewDashapiSender creates a new Dashapi sender.
func NewDashapiSender(cfg DashapiConfig) (Sender, error) {
	dash, err := dashapi.New(cfg.Client, cfg.Addr, "")
	if err != nil {
		return nil, err
	}
	return &dashapiSender{cfg: cfg, dash: dash}, nil
}

// Send sends an email via Dashapi.
func (s *dashapiSender) Send(ctx context.Context, item *Email) (string, error) {
	senderAddr := s.cfg.From.String()
	if item.BugID != "" {
		var err error
		senderAddr, err = email.AddAddrContext(senderAddr, s.cfg.ContextPrefix+item.BugID)
		if err != nil {
			return "", err
		}
	}
	return "", s.dash.SendEmail(&dashapi.SendEmailReq{
		Sender:    senderAddr,
		To:        item.To,
		Cc:        item.Cc,
		Subject:   s.cfg.SubjectPrefix + item.Subject,
		InReplyTo: item.InReplyTo,
		Body:      string(item.Body),
	})
}
