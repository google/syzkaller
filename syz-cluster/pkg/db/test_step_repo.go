// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"

	"github.com/google/syzkaller/syz-cluster/pkg/api"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
)

type SessionTestStepRepository struct {
	client *spanner.Client
	*genericEntityOps[SessionTestStep, string]
}

func NewSessionTestStepRepository(client *spanner.Client) *SessionTestStepRepository {
	return &SessionTestStepRepository{
		client: client,
		genericEntityOps: &genericEntityOps[SessionTestStep, string]{
			client:   client,
			keyField: "ID",
			table:    "SessionTestSteps",
		},
	}
}

type SessionTestStepID struct {
	SessionID string
	TestName  string
	Title     string
	Target    string
}

func (r *SessionTestStepRepository) Store(ctx context.Context, id SessionTestStepID,
	cb func(session *Session, old *SessionTestStep) (*SessionTestStep, error)) error {
	_, err := r.client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.Statement{
			SQL: `SELECT * FROM SessionTestSteps
				WHERE SessionID = @sessionID AND TestName = @testName AND Title = @title AND Target = @target`,
			Params: map[string]any{
				"sessionID": id.SessionID,
				"testName":  id.TestName,
				"title":     id.Title,
				"target":    id.Target,
			},
		}
		oldStep, err := readEntity[SessionTestStep](ctx, txn, stmt)
		if err != nil {
			return err
		}
		session, err := readEntity[Session](ctx, txn, spanner.Statement{
			SQL:    "SELECT * FROM `Sessions` WHERE `ID`=@id",
			Params: map[string]any{"id": id.SessionID},
		})
		if err != nil {
			return err
		}
		newStep, err := cb(session, oldStep)
		if err != nil {
			return err
		} else if newStep == nil {
			return nil
		} else if newStep.ID == "" {
			newStep.ID = uuid.NewString()
		}
		m, err := spanner.InsertStruct("SessionTestSteps", newStep)
		if err != nil {
			return err
		}
		var mutations []*spanner.Mutation
		if oldStep != nil {
			mutations = append(mutations, spanner.Delete("SessionTestSteps", spanner.Key{oldStep.ID}))
		}
		mutations = append(mutations, m)
		return txn.BufferWrite(mutations)
	})
	return err
}

func (r *SessionTestStepRepository) ListForSession(ctx context.Context, sessionID,
	testName string) ([]*SessionTestStep, error) {
	stmt := spanner.Statement{
		SQL: `SELECT * FROM SessionTestSteps ` +
			`WHERE SessionID = @sessionID AND TestName = @testName ORDER BY CreatedAt ASC`,
		Params: map[string]any{"sessionID": sessionID, "testName": testName},
	}
	return readEntities[SessionTestStep](ctx, r.client.Single(), stmt)
}

type TestStepGroup struct {
	Title   string
	Base    *SessionTestStep
	Patched *SessionTestStep
}

func GroupTestSteps(steps []*SessionTestStep) []*TestStepGroup {
	rowMap := map[string]*TestStepGroup{}
	var orderedRows []*TestStepGroup

	for _, step := range steps {
		row, ok := rowMap[step.Title]
		if !ok {
			row = &TestStepGroup{Title: step.Title}
			rowMap[step.Title] = row
			orderedRows = append(orderedRows, row)
		}
		switch step.Target {
		case api.StepTargetBase:
			row.Base = step
		case api.StepTargetPatched:
			row.Patched = step
		}
	}
	return orderedRows
}
