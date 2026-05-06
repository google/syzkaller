// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/gcpsecret"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DashboardAddr         string        `yaml:"dashboard_addr"`
	DashboardClient       string        `yaml:"dashboard_client"`
	DashboardKey          string        `yaml:"dashboard_key"`
	LoreURL               string        `yaml:"lore_url"`
	OwnEmails             []string      `yaml:"own_emails"`
	DashboardPollInterval time.Duration `yaml:"dashboard_poll_interval"`
	LorePollInterval      time.Duration `yaml:"lore_poll_interval"`
	DocsLink              string        `yaml:"docs_link"`
	LoreArchive           string        `yaml:"lore_archive"`
	SMTP                  SMTPConfig    `yaml:"smtp"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

func loadConfig(configFile string) (*Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{
		DashboardPollInterval: 30 * time.Second,
		LorePollInterval:      5 * time.Minute,
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	resolvedDashKey, err := gcpsecret.Resolve(context.Background(), cfg.DashboardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DashboardKey: %w", err)
	}
	cfg.DashboardKey = resolvedDashKey

	resolvedSMTPHost, err := gcpsecret.Resolve(context.Background(), cfg.SMTP.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SMTP Host: %w", err)
	}
	cfg.SMTP.Host = resolvedSMTPHost

	resolvedSMTPUser, err := gcpsecret.Resolve(context.Background(), cfg.SMTP.User)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SMTP User: %w", err)
	}
	cfg.SMTP.User = resolvedSMTPUser

	resolvedSMTPPort, err := gcpsecret.Resolve(context.Background(), cfg.SMTP.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SMTP Port: %w", err)
	}
	cfg.SMTP.Port = resolvedSMTPPort
	resolvedSMTPPassword, err := gcpsecret.Resolve(context.Background(), cfg.SMTP.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SMTP Password: %w", err)
	}
	cfg.SMTP.Password = resolvedSMTPPassword
	return cfg, nil
}

func (cfg *Config) ParseFrom() (mail.Address, error) {
	addr, err := mail.ParseAddress(cfg.SMTP.From)
	if err != nil {
		return mail.Address{}, fmt.Errorf("failed to parse SMTP From address: %w", err)
	}
	return *addr, nil
}
