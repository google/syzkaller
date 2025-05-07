// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/uuid"
)

type smtpSender struct {
	cfg         *app.EmailConfig
	projectName string // needed for querying credentials
}

func newSender(ctx context.Context, cfg *app.EmailConfig) (*smtpSender, error) {
	project, err := gce.ProjectName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query project name: %w", err)
	}
	return &smtpSender{
		cfg:         cfg,
		projectName: project,
	}, nil
}

// Send constructs a raw email from EmailToSend and sends it over SMTP.
func (sender *smtpSender) Send(ctx context.Context, item *EmailToSend) (string, error) {
	creds, err := sender.queryCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to query credentials: %w", err)
	}
	msgID := fmt.Sprintf("<%s@%s>", uuid.NewString(), creds.host)
	msg := rawEmail(sender.cfg, item, msgID)
	auth := smtp.PlainAuth("", creds.host, creds.password, creds.host)
	smtpAddr := fmt.Sprintf("%s:%d", creds.host, creds.port)
	return msgID, smtp.SendMail(smtpAddr, auth, sender.cfg.Sender, item.recipients(), msg)
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

func rawEmail(cfg *app.EmailConfig, item *EmailToSend, id string) []byte {
	var msg bytes.Buffer

	fmt.Fprintf(&msg, "From: %s <%s>\r\n", cfg.Name, cfg.Sender)
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

const (
	SecretSMTPHost     string = "smtp_host"
	SecretSMTPPort     string = "smtp_port"
	SecretSMTPUser     string = "smtp_user"
	SecretSMTPPassword string = "smtp_password"
)

type smtpCredentials struct {
	host     string
	port     int
	user     string
	password string
}

func (sender *smtpSender) queryCredentials(ctx context.Context) (smtpCredentials, error) {
	values := map[string]string{}
	for _, key := range []string{
		SecretSMTPHost, SecretSMTPPort, SecretSMTPUser, SecretSMTPPassword,
	} {
		var err error
		values[key], err = sender.querySecret(ctx, key)
		if err != nil {
			return smtpCredentials{}, err
		}
	}
	port, err := strconv.Atoi(values[SecretSMTPPort])
	if err != nil {
		return smtpCredentials{}, fmt.Errorf("failed to parse SMTP port: not a valid integer")
	}
	return smtpCredentials{
		host:     values[SecretSMTPHost],
		port:     port,
		user:     values[SecretSMTPUser],
		password: values[SecretSMTPPassword],
	}, nil
}

func (sender *smtpSender) querySecret(ctx context.Context, key string) (string, error) {
	const retries = 3
	var err error
	for i := 0; i < retries; i++ {
		var val []byte
		val, err := gce.LatestGcpSecret(ctx, sender.projectName, key)
		if err == nil {
			return string(val), nil
		}
	}
	return "", fmt.Errorf("failed to query %v: %w", key, err)
}
