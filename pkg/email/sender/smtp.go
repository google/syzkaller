// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"mime"
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

	for _, addr := range recipients {
		if _, err := mail.ParseAddress(addr); err != nil {
			return "", fmt.Errorf("invalid recipient address %q: %w", addr, err)
		}
	}

	if s.cfg.Port == 465 {
		// Implicit TLS.
		tlsconfig := &tls.Config{
			ServerName: s.cfg.Host,
		}
		dialer := &tls.Dialer{Config: tlsconfig}
		conn, err := dialer.DialContext(ctx, "tcp", smtpAddr)
		if err != nil {
			return "", fmt.Errorf("tls.Dial failed: %w", err)
		}
		client, err := smtp.NewClient(conn, s.cfg.Host)
		if err != nil {
			return "", fmt.Errorf("smtp.NewClient failed: %w", err)
		}
		defer client.Close()
		if err = client.Auth(auth); err != nil {
			return "", fmt.Errorf("client.Auth failed: %w", err)
		}
		if err = client.Mail(s.cfg.From.Address); err != nil {
			return "", fmt.Errorf("client.Mail failed: %w", err)
		}
		for _, addr := range recipients {
			if err = client.Rcpt(addr); err != nil {
				return "", fmt.Errorf("client.Rcpt failed for %v: %w", addr, err)
			}
		}
		w, err := client.Data()
		if err != nil {
			return "", fmt.Errorf("client.Data failed: %w", err)
		}
		_, writeErr := w.Write(msg)
		closeErr := w.Close()
		if writeErr != nil {
			return "", fmt.Errorf("failed to write message body: %w", writeErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("failed to close data writer: %w", closeErr)
		}
		client.Quit()
	} else {
		err := smtp.SendMail(smtpAddr, auth, s.cfg.From.Address, recipients, msg)
		if err != nil {
			return "", err
		}
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
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", item.Subject))
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
