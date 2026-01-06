// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"errors"

	"cloud.google.com/go/spanner"
)

type ReportReplyRepository struct {
	client *spanner.Client
}

func NewReportReplyRepository(client *spanner.Client) *ReportReplyRepository {
	return &ReportReplyRepository{
		client: client,
	}
}

func (repo *ReportReplyRepository) FindParentReportID(ctx context.Context, reporter, messageID string) (string, error) {
	type result struct {
		ReportID string `spanner:"ReportID"`
	}
	ret, err := readEntity[result](ctx, repo.client.Single(), spanner.Statement{
		SQL: "SELECT `ReportReplies`.ReportID FROM `ReportReplies` " +
			"JOIN `SessionReports` ON `SessionReports`.ID = `ReportReplies`.ReportID " +
			"WHERE `ReportReplies`.MessageID = @messageID " +
			"AND `SessionReports`.Reporter = @reporter LIMIT 1",
		Params: map[string]any{
			"reporter":  reporter,
			"messageID": messageID,
		},
	})
	if err != nil {
		return "", err
	} else if ret != nil {
		return ret.ReportID, nil
	}
	return "", nil
}

var ErrReportReplyExists = errors.New("the reply has already been recorded")

func (repo *ReportReplyRepository) Insert(ctx context.Context, reply *ReportReply) error {
	_, err := repo.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			entity, err := readEntity[ReportReply](ctx, txn, spanner.Statement{
				SQL: "SELECT * from `ReportReplies` " +
					"WHERE `ReportID`=@reportID AND `MessageID`=@messageID",
				Params: map[string]any{
					"reportID":  reply.ReportID,
					"messageID": reply.MessageID,
				},
			})
			if err != nil {
				return err
			} else if entity != nil {
				return ErrReportReplyExists
			}
			insert, err := spanner.InsertStruct("ReportReplies", reply)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{insert})
		})
	return err
}

func (repo *ReportReplyRepository) LastForReporter(ctx context.Context, reporter string) (*ReportReply, error) {
	return readEntity[ReportReply](ctx, repo.client.Single(), spanner.Statement{
		SQL: "SELECT `ReportReplies`.* FROM `ReportReplies` " +
			"JOIN `SessionReports` ON `SessionReports`.ID=`ReportReplies`.ReportID " +
			"WHERE `SessionReports`.Reporter=@reporter " +
			"ORDER BY `Time` DESC LIMIT 1",
		Params: map[string]any{
			"reporter": reporter,
		},
	})
}
