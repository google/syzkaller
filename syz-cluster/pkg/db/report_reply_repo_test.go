// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReportReplyRepository(t *testing.T) {
	client, ctx := NewTransientDB(t)
	dtd := &dummyTestData{t, ctx, client}
	session := dtd.dummySession(dtd.dummySeries())

	reportRepo := NewReportRepository(client)
	report := &SessionReport{SessionID: session.ID, Reporter: dummyReporter}
	err := reportRepo.Insert(ctx, report)
	assert.NoError(t, err)

	replyRepo := NewReportReplyRepository(client)
	baseTime := time.Now()
	for i := range 2 {
		err = replyRepo.Insert(ctx, &ReportReply{
			MessageID: fmt.Sprintf("message-id-%d", i),
			ReportID:  report.ID,
			Time:      baseTime.Add(time.Duration(i) * time.Second),
		})
		assert.NoError(t, err)
	}

	t.Run("insert-dup-reply", func(t *testing.T) {
		err := replyRepo.Insert(ctx, &ReportReply{
			MessageID: "message-id-0",
			ReportID:  report.ID,
			Time:      time.Now(),
		})
		assert.Error(t, ErrReportReplyExists, err)
	})

	t.Run("find-by-parent", func(t *testing.T) {
		reportID, err := replyRepo.FindParentReportID(ctx, dummyReporter, "message-id-0")
		assert.NoError(t, err)
		assert.Equal(t, report.ID, reportID)
	})
}
