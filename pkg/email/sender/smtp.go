// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sender

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"net/smtp"
	"slices"
	"strings"

	"github.com/google/uuid"
)

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     mail.Address
}

type smtpSender struct {
	cfg SMTPConfig
}

func NewSMTPSender(cfg SMTPConfig) Sender {
	return &smtpSender{cfg: cfg}
}

func (s *smtpSender) Send(ctx context.Context, item *Email) (string, error) {
	msgID := fmt.Sprintf("<%s@%s>", uuid.NewString(), s.cfg.Host)
	msg := s.rawEmail(item, msgID)
	auth := smtp.PlainAuth("", s.cfg.User, s.cfg.Password, s.cfg.Host)
	smtpAddr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	// Create a slice of recipients (To + Cc) without duplicates.
	recipients := slices.Concat(item.To, item.Cc)
	slices.Sort(recipients)
	recipients = slices.Compact(recipients)
	err := smtp.SendMail(smtpAddr, auth, s.cfg.From.Address, recipients, msg)
	if err != nil {
		return "", err
	}
	return msgID, nil
}

func (s *smtpSender) rawEmail(item *Email, id string) []byte {
	var msg bytes.Buffer

	fmt.Fprintf(&msg, "From: %s\r\n", s.cfg.From.String())
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(item.To, ", "))
	if len(item.Cc) > 0 {
		fmt.Fprintf(&msg, "Cc: %s\r\n", strings.Join(item.Cc, ", "))
	}
	fmt.Fprintf(&msg, "Subject: %s\r\n", item.Subject)
	if item.InReplyTo != "" {
		inReplyTo := item.InReplyTo
		if inReplyTo[0] != '<' {
			inReplyTo = "<" + inReplyTo + ">"
		}
		fmt.Fprintf(&msg, "In-Reply-To: %s\r\n", inReplyTo)
	}
	if id != "" {
		if id[0] != '<' {
			id = "<" + id + ">"
		}
		fmt.Fprintf(&msg, "Message-ID: %s\r\n", id)
	}
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.Write(item.Body)
	return msg.Bytes()
}
