// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"cloud.google.com/go/spanner"
)

type ReportRepository struct {
	client *spanner.Client
	*genericEntityOps[SessionReport, string]
}

func NewReportRepository(client *spanner.Client) *ReportRepository {
	return &ReportRepository{
		client: client,
		genericEntityOps: &genericEntityOps[SessionReport, string]{
			client:   client,
			keyField: "ID",
			table:    "SessionReports",
		},
	}
}

func (repo *ReportRepository) Insert(ctx context.Context, rep *SessionReport) error {
	if rep.ID != "" {
		return repo.genericEntityOps.Insert(ctx, rep)
	}
	const attempts = 3
	for i := 0; i < attempts; i++ {
		var err error
		rep.ID, err = randomReportID()
		if err != nil {
			return err
		}
		err = repo.genericEntityOps.Insert(ctx, rep)
		if err == errEntityExists {
			continue
		}
		return err
	}
	// We shouldn't be getting here until we have sent out billions of reports.
	// But let's return some error to still exit gracefully.
	return fmt.Errorf("failed to pick a non-existing report ID")
}

func (repo *ReportRepository) ListNotReported(ctx context.Context, reporter string,
	limit int) ([]*SessionReport, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `SessionReports` WHERE `Reporter` = @reporter AND `ReportedAt` IS NULL",
		Params: map[string]any{
			"reporter": reporter,
		},
	}
	addLimit(&stmt, limit)
	return repo.readEntities(ctx, stmt)
}

// As report ID may be included in the email address, we'd prefer it to be shorter than a typical UUID.
// A 16 byte hex ID should be good enough.
func randomReportID() (string, error) {
	data := make([]byte, 8)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
