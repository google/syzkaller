// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigs(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	// We are in syz-cluster/pkg/app.
	// We want to find syz-cluster/overlays.
	overlaysDir := filepath.Join(wd, "..", "..", "overlays")

	err = filepath.Walk(overlaysDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, "global-config.yaml") {
			return nil
		}

		t.Run(path, func(t *testing.T) {
			_, err := loadConfig(path)
			if err != nil {
				t.Fatalf("validation failed: %v", err)
			}
		})
		return nil
	})

	if err != nil {
		t.Fatalf("filepath.Walk failed: %v", err)
	}
}

func TestOwnEmails(t *testing.T) {
	cfg := &EmailConfig{
		Dashapi: &DashapiConfig{
			From: "bot@dashapi.com",
		},
		SMTP: &SMTPConfig{
			From: "bot@smtp.com",
		},
		ExtraOwnEmails: []string{
			"bot@kernel.org",
			"bot@dashapi.com",
		},
	}

	got := cfg.OwnEmails()
	want := []string{"bot@dashapi.com", "bot@kernel.org", "bot@smtp.com"}
	require.Equal(t, want, got)
}
