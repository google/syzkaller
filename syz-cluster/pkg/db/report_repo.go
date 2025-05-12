// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
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
	if rep.ID == "" {
		rep.ID = uuid.NewString()
	}
	return repo.genericEntityOps.Insert(ctx, rep)
}

func (repo *ReportRepository) ListNotReported(ctx context.Context, reporter string,
	limit int) ([]*SessionReport, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `SessionReports` WHERE `Reporter` = @reporter AND `ReportedAt` IS NULL",
		Params: map[string]interface{}{
			"reporter": reporter,
		},
	}
	addLimit(&stmt, limit)
	return repo.readEntities(ctx, stmt)
}

func (repo *ReportRepository) FindByMessageID(ctx context.Context, reporter, messageID string) (*SessionReport, error) {
	stmt := spanner.Statement{
		SQL: "SELECT * FROM `SessionReports` WHERE `Reporter` = @reporter AND `MessageID` = @messageID",
		Params: map[string]interface{}{
			"reporter":  reporter,
			"messageID": messageID,
		},
	}
	return repo.readEntity(ctx, stmt)
}
