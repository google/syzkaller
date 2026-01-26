// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/uuid"
	"google.golang.org/appengine/v2"
)

const (
	Instance = "syzbot"
	Database = "ai"
)

func init() {
	// This forces unmarshalling of JSON integers into json.Number rather than float64.
	spanner.UseNumberWithJSONDecoderEncoder(true)
}

func LoadWorkflows(ctx context.Context) ([]*Workflow, error) {
	return selectAll[Workflow](ctx, spanner.Statement{
		SQL: selectWorkflows(),
	})
}

func UpdateWorkflows(ctx context.Context, active []dashapi.AIWorkflow) error {
	workflows, err := LoadWorkflows(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]*Workflow)
	for _, f := range workflows {
		m[f.Name] = f
	}
	// Truncate the time so that we don't need to update the database on each poll.
	nowDate := TimeNow(ctx).Truncate(24 * time.Hour)
	var mutations []*spanner.Mutation
	for _, f := range active {
		flow := &Workflow{
			Name:       f.Name,
			Type:       f.Type,
			LastActive: nowDate,
		}
		if have := m[flow.Name]; reflect.DeepEqual(have, flow) {
			continue
		}
		mut, err := spanner.InsertOrUpdateStruct("Workflows", flow)
		if err != nil {
			return err
		}
		mutations = append(mutations, mut)
	}
	if len(mutations) == 0 {
		return nil
	}
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, mutations)
	return err
}

func CreateJob(ctx context.Context, job *Job) error {
	job.ID = uuid.NewString()
	job.Created = TimeNow(ctx)
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.InsertStruct("Jobs", job)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func UpdateJob(ctx context.Context, job *Job) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.UpdateStruct("Jobs", job)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func StartJob(ctx context.Context, req *dashapi.AIJobPollReq) (*Job, error) {
	var workflows []string
	for _, flow := range req.Workflows {
		workflows = append(workflows, flow.Name)
	}
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	var job *Job
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		{
			iter := txn.Query(ctx, spanner.Statement{
				SQL: selectJobs() + `WHERE Workflow IN UNNEST(@workflows)
						AND Started IS NULL
					ORDER BY Created ASC LIMIT 1`,
				Params: map[string]any{
					"workflows": workflows,
				},
			})
			defer iter.Stop()
			var jobs []*Job
			if err := spanner.SelectAll(iter, &jobs); err != nil || len(jobs) == 0 {
				return err
			}
			job = jobs[0]
		}
		job.Started = spanner.NullTime{Time: TimeNow(ctx), Valid: true}
		job.CodeRevision = req.CodeRevision
		mut, err := spanner.InsertOrUpdateStruct("Jobs", job)
		if err != nil {
			return err
		}
		return txn.BufferWrite([]*spanner.Mutation{mut})
	})
	return job, err
}

func LoadNamespaceJobs(ctx context.Context, ns string) ([]*Job, error) {
	return selectAll[Job](ctx, spanner.Statement{
		SQL: selectJobs() + `WHERE Namespace = @ns ORDER BY Created DESC`,
		Params: map[string]any{
			"ns": ns,
		},
	})
}

func LoadBugJobs(ctx context.Context, bugID string) ([]*Job, error) {
	return selectAll[Job](ctx, spanner.Statement{
		SQL: selectJobs() + `WHERE BugID = @bugID ORDER BY Created DESC`,
		Params: map[string]any{
			"bugID": bugID,
		},
	})
}

func LoadJob(ctx context.Context, id string) (*Job, error) {
	return selectOne[Job](ctx, spanner.Statement{
		SQL: selectJobs() + `WHERE ID = @id`,
		Params: map[string]any{
			"id": id,
		},
	})
}

func StoreTrajectorySpan(ctx context.Context, jobID string, span *trajectory.Span) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	ent := TrajectorySpan{
		JobID:                jobID,
		Seq:                  int64(span.Seq),
		Nesting:              int64(span.Nesting),
		Type:                 string(span.Type),
		Name:                 span.Name,
		Model:                span.Model,
		Started:              span.Started,
		Finished:             toNullTime(span.Finished),
		Error:                toNullString(span.Error),
		Args:                 toNullJSON(span.Args),
		Results:              toNullJSON(span.Results),
		Instruction:          toNullString(span.Instruction),
		Prompt:               toNullString(span.Prompt),
		Reply:                toNullString(span.Reply),
		Thoughts:             toNullString(span.Thoughts),
		InputTokens:          toNullInt64(span.InputTokens),
		OutputTokens:         toNullInt64(span.OutputTokens),
		OutputThoughtsTokens: toNullInt64(span.OutputThoughtsTokens),
	}
	mut, err := spanner.InsertOrUpdateStruct("TrajectorySpans", ent)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func LoadTrajectory(ctx context.Context, jobID string) ([]*TrajectorySpan, error) {
	return selectAll[TrajectorySpan](ctx, spanner.Statement{
		SQL: selectTrajectorySpans() + `WHERE JobID = @job_id ORDER BY Seq ASC`,
		Params: map[string]any{
			"job_id": jobID,
		},
	})
}

func selectAll[T any](ctx context.Context, stmt spanner.Statement) ([]*T, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	var items []*T
	err = spanner.SelectAll(iter, &items)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func selectOne[T any](ctx context.Context, stmt spanner.Statement) (*T, error) {
	all, err := selectAll[T](ctx, stmt)
	if err != nil {
		return nil, err
	}
	if len(all) != 1 {
		return nil, fmt.Errorf("selectOne: got %v of %T", len(all), *new(T))
	}
	return all[0], nil
}

var clients sync.Map // map[string]*spanner.Client

func dbClient(ctx context.Context) (*spanner.Client, error) {
	appID := appengine.AppID(ctx)
	if v, ok := clients.Load(appID); ok {
		return v.(*spanner.Client), nil
	}
	path := fmt.Sprintf("projects/%v/instances/%v/databases/%v",
		appID, Instance, Database)
	// We use background context for the client, so that it survives the request.
	client, err := spanner.NewClientWithConfig(context.Background(), path, spanner.ClientConfig{
		SessionPoolConfig: spanner.SessionPoolConfig{
			MinOpened: 1,
			MaxOpened: 20,
		},
	})
	if err != nil {
		return nil, err
	}
	if actual, loaded := clients.LoadOrStore(appID, client); loaded {
		client.Close()
		return actual.(*spanner.Client), nil
	}
	return client, nil
}

func CloseClient(ctx context.Context) {
	appID := appengine.AppID(ctx)
	if v, ok := clients.LoadAndDelete(appID); ok {
		v.(*spanner.Client).Close()
	}
}

var TimeNow = func(ctx context.Context) time.Time {
	return time.Now()
}

func selectWorkflows() string {
	return selectAllFrom[Workflow]("Workflows")
}

func selectJobs() string {
	return selectAllFrom[Job]("Jobs")
}

func selectTrajectorySpans() string {
	return selectAllFrom[TrajectorySpan]("TrajectorySpans")
}

func selectJournal() string {
	return selectAllFrom[Journal]("Journal")
}

func AddJournalEntry(ctx context.Context, entry *Journal) error {
	entry.ID = uuid.NewString()
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.InsertStruct("Journal", entry)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func LoadJobJournal(ctx context.Context, jobID, action string) ([]*Journal, error) {
	return selectAll[Journal](ctx, spanner.Statement{
		SQL: selectJournal() + `WHERE JobID = @jobID AND Action = @action ORDER BY Date DESC`,
		Params: map[string]any{
			"jobID":  jobID,
			"action": action,
		},
	})
}

func selectAllFrom[T any](table string) string {
	var fields []string
	for _, field := range reflect.VisibleFields(reflect.TypeFor[T]()) {
		fields = append(fields, field.Name)
	}
	return fmt.Sprintf("SELECT %v FROM %v ", strings.Join(fields, ", "), table)
}

func toNullJSON(v map[string]any) spanner.NullJSON {
	if v == nil {
		return spanner.NullJSON{}
	}
	return spanner.NullJSON{Value: v, Valid: true}
}

func toNullTime(v time.Time) spanner.NullTime {
	if v.IsZero() {
		return spanner.NullTime{}
	}
	return spanner.NullTime{Time: v, Valid: true}
}

func toNullString(v string) spanner.NullString {
	if v == "" {
		return spanner.NullString{}
	}
	return spanner.NullString{StringVal: v, Valid: true}
}

func toNullInt64(v int) spanner.NullInt64 {
	if v == 0 {
		return spanner.NullInt64{}
	}
	return spanner.NullInt64{Int64: int64(v), Valid: true}
}
