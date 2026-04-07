// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package emailclient

import (
	"context"
	"fmt"
	"net/mail"
	"strconv"

	"github.com/google/syzkaller/pkg/email/sender"
	"github.com/google/syzkaller/pkg/gcpsecret"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

// Sender is the function type used by syz-cluster to send emails.
type Sender func(context.Context, *sender.Email) (string, error)

// MakeSender creates a Sender based on the configuration.
func MakeSender(ctx context.Context, cfg *app.EmailConfig) (Sender, error) {
	switch cfg.Sender {
	case app.SenderSMTP:
		s, err := newSMTPSender(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return s.Send, nil
	case app.SenderDashapi:
		s, err := sender.NewDashapiSender(sender.DashapiConfig{
			Client: cfg.Dashapi.Client,
			Addr:   cfg.Dashapi.Addr,
			From: mail.Address{
				Name:    cfg.Name,
				Address: cfg.Dashapi.From,
			},
			ContextPrefix: cfg.Dashapi.ContextPrefix,
			SubjectPrefix: cfg.SubjectPrefix,
		})
		if err != nil {
			return nil, err
		}
		return s.Send, nil
	}
	return nil, fmt.Errorf("unsupported sender type: %q", cfg.Sender)
}

func newSMTPSender(ctx context.Context, cfg *app.EmailConfig) (sender.Sender, error) {
	project, err := gcpsecret.ProjectName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query project name: %w", err)
	}

	creds, err := queryCredentials(ctx, project)
	if err != nil {
		return nil, err
	}

	smtpCfg := sender.SMTPConfig{
		Host:     creds.host,
		Port:     creds.port,
		User:     creds.user,
		Password: creds.password,
		From: mail.Address{
			Name:    cfg.Name,
			Address: cfg.SMTP.From,
		},
	}

	return sender.NewSMTPSender(smtpCfg), nil
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

func queryCredentials(ctx context.Context, projectName string) (smtpCredentials, error) {
	values := map[string]string{}
	for _, key := range []string{
		SecretSMTPHost, SecretSMTPPort, SecretSMTPUser, SecretSMTPPassword,
	} {
		var err error
		values[key], err = querySecret(ctx, projectName, key)
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

func querySecret(ctx context.Context, projectName, key string) (string, error) {
	const retries = 3
	var err error
	for range retries {
		var val []byte
		val, err = gcpsecret.LatestGcpSecret(ctx, projectName, key)
		if err == nil {
			return string(val), nil
		}
	}
	return "", fmt.Errorf("failed to query %v: %w", key, err)
}

// TestEmailConfig returns a standard configuration for testing.
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
		Dashapi: &app.DashapiConfig{
			From:          "bot@syzbot.com",
			ContextPrefix: "ci_",
		},
	}
}
