// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"context"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
)

type FilesRecord struct {
	Session      string
	FilePath     string
	Instrumented int64
	Covered      int64
}

type FileSubsystems struct {
	Namespace  string
	FilePath   string
	Subsystems []string
}

type HistoryRecord struct {
	Session   string
	Time      time.Time
	Namespace string
	Repo      string
	Commit    string
	Duration  int64
	DateTo    civil.Date
	TotalRows int64
}

func NewClient(ctx context.Context, projectID string) (*spanner.Client, error) {
	database := "projects/" + projectID + "/instances/syzbot/databases/coverage"
	return spanner.NewClient(ctx, database)
}
