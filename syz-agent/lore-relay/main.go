// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/email/sender"
	lorerelay "github.com/google/syzkaller/pkg/lore-relay"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	var (
		flagConfig = flag.String("config", "", "config file")
	)
	defer tool.Init()()
	flag.Parse()
	if *flagConfig == "" {
		log.Fatalf("config file is required")
	}

	cfg, err := loadConfig(*flagConfig)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	if err != nil {
		log.Fatalf("failed to create dashboard client: %v", err)
	}

	const repoDir = "/lore-repo/checkout"
	poller, err := lore.NewPoller(lore.PollerConfig{
		RepoDir:   repoDir,
		URL:       cfg.LoreURL,
		OwnEmails: cfg.OwnEmails,
		Tracer:    &debugtracer.GenericTracer{TraceWriter: os.Stdout, WithTime: true},
	})
	if err != nil {
		log.Fatalf("failed to create lore poller: %v", err)
	}

	fromAddr, err := cfg.ParseFrom()
	if err != nil {
		log.Fatalf("failed to parse SMTP from address: %v", err)
	}
	smtpPort, err := strconv.Atoi(cfg.SMTP.Port)
	if err != nil {
		log.Fatalf("failed to parse SMTP port %q: %v", cfg.SMTP.Port, err)
	}
	emailSender := sender.NewSMTPSender(sender.SMTPConfig{
		Host:     cfg.SMTP.Host,
		Port:     smtpPort,
		User:     cfg.SMTP.User,
		Password: cfg.SMTP.Password,
		From:     fromAddr,
	})

	relayCfg := &lorerelay.Config{
		DashboardPollInterval: cfg.DashboardPollInterval,
		LorePollInterval:      cfg.LorePollInterval,
		DocsLink:              cfg.DocsLink,
		LoreArchive:           cfg.LoreArchive,
		Tracer:                &debugtracer.GenericTracer{TraceWriter: os.Stderr, WithTime: true},
	}
	relay := lorerelay.NewRelay(relayCfg, dash, poller, emailSender)

	ctx := context.Background()
	shutdownPending := make(chan struct{})
	osutil.HandleInterrupts(shutdownPending)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-shutdownPending
		cancel()
	}()

	log.Printf("starting lore-relay")
	if err := relay.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("relay failed: %v", err)
	}
	log.Printf("lore-relay stopped")
}
