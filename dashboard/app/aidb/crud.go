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

	"errors"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"google.golang.org/appengine/v2"
	"google.golang.org/grpc/codes"
)

const (
	Instance = "syzbot"
	Database = "ai"
)

var ErrNotFound = errors.New("entity not found")

type ErrCannotUpstream struct {
	Reason string
}

func (e *ErrCannotUpstream) Error() string {
	return e.Reason
}

func init() {
	// This forces unmarshalling of JSON integers into json.Number rather than float64.
	spanner.UseNumberWithJSONDecoderEncoder(true)
}

func LoadActiveWorkflows(ctx context.Context) ([]*ActiveWorkflow, error) {
	return selectAll[ActiveWorkflow](ctx, spanner.Statement{
		SQL: `SELECT Name, Type, MAX(Agents.LastActive) AS LastActive
			FROM Workflows JOIN Agents USING(AgentName)
			GROUP BY Name, Type`,
	})
}

func UpdateWorkflows(ctx context.Context, agentName string, active []dashapi.AIWorkflow) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		var mutations []*spanner.Mutation
		mutations = append(mutations, spanner.Delete("Workflows", spanner.KeyRange{
			Start: spanner.Key{agentName},
			End:   spanner.Key{agentName},
			Kind:  spanner.ClosedClosed,
		}))
		for _, f := range active {
			flow := &Workflow{
				AgentName: agentName,
				Name:      f.Name,
				Type:      f.Type,
			}
			mut, err := spanner.InsertStruct("Workflows", flow)
			if err != nil {
				return err
			}
			mutations = append(mutations, mut)
		}
		if len(mutations) == 0 {
			return nil
		}
		return txn.BufferWrite(mutations)
	})
	return err
}

func AgentIsAlive(ctx context.Context, agentName string) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.InsertOrUpdateStruct("Agents", &Agent{
		AgentName:  agentName,
		LastActive: TimeNow(ctx),
	})
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func LoadAgent(ctx context.Context, agentName string) (*Agent, error) {
	return selectOne[Agent](ctx, spanner.Statement{
		SQL: selectAgents() + `WHERE AgentName = @name`,
		Params: map[string]any{
			"name": agentName,
		},
	})
}

func CreateJob(ctx context.Context, job *Job) (string, error) {
	job.ID = uuid.NewString()
	job.Created = TimeNow(ctx)
	client, err := dbClient(ctx)
	if err != nil {
		return "", err
	}
	mut, err := spanner.InsertStruct("Jobs", job)
	if err != nil {
		return "", err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return job.ID, err
}

func UpdateJob(ctx context.Context, job *Job) error {
	return saveEntity(ctx, "Jobs", job)
}

func startJob(ctx context.Context, req *dashapi.AIJobPollReq, job *Job) (*spanner.Mutation, error) {
	job.Started = spanner.NullTime{Time: TimeNow(ctx), Valid: true}
	job.CodeRevision = req.CodeRevision
	job.AgentName = toNullString(req.AgentName)
	return spanner.InsertOrUpdateStruct("Jobs", job)
}

func cloneJob(ctx context.Context, orig *Job) *Job {
	return &Job{
		ID:          uuid.NewString(),
		Created:     TimeNow(ctx),
		Type:        orig.Type,
		Workflow:    orig.Workflow,
		Namespace:   orig.Namespace,
		BugID:       orig.BugID,
		Description: orig.Description,
		Link:        orig.Link,
		Args:        orig.Args,
	}
}

func StartJob(ctx context.Context, req *dashapi.AIJobPollReq, namespaces []string) (*Job, error) {
	var workflows []string
	for _, flow := range req.Workflows {
		workflows = append(workflows, flow.Name)
	}
	params := map[string]any{
		"workflows":  workflows,
		"namespaces": namespaces,
	}
	sql := selectJobs() + `WHERE Workflow IN UNNEST(@workflows) AND Started IS NULL
			AND Namespace IN UNNEST(@namespaces)
		ORDER BY Created ASC LIMIT 1`

	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	var job *Job
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// Reset job from previous transaction runs, otherwise we might return stale
		// result if the job has been taken by a concurent thread (the len(jobs) == 0 case).
		job = nil
		iter := txn.Query(ctx, spanner.Statement{
			SQL:    sql,
			Params: params,
		})
		defer iter.Stop()
		var jobs []*Job
		if err := spanner.SelectAll(iter, &jobs); err != nil || len(jobs) == 0 {
			return err
		}
		job = jobs[0]
		mut, err := startJob(ctx, req, job)
		if err != nil {
			return err
		}
		return txn.BufferWrite([]*spanner.Mutation{mut})
	})
	return job, err
}

func NextStaleJob(ctx context.Context, req *dashapi.AIJobPollReq, namespaces []string) (*Job, error) {
	var workflows []string
	for _, flow := range req.Workflows {
		workflows = append(workflows, flow.Name)
	}
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := TimeNow(ctx).Add(-8 * time.Hour)
	var job *Job
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		// Avoid reusing the entities from previous transaction commit attempts.
		job = nil
		var jobs []*Job

		// First, check if the requesting agent has any unfinished jobs (implying a restart).
		if req.AgentName != "" {
			iter := txn.Query(ctx, unfinishedAgentJobs(req, workflows, namespaces))
			defer iter.Stop()
			if err := spanner.SelectAll(iter, &jobs); err != nil {
				return err
			}
		}

		// Check if any other agent has stale/abandoned jobs.
		if len(jobs) == 0 {
			iter := txn.Query(ctx, staleUnfinishedJobs(cutoff, workflows, namespaces))
			defer iter.Stop()
			if err := spanner.SelectAll(iter, &jobs); err != nil {
				return err
			}
		}

		if len(jobs) == 0 {
			return nil
		}

		origJob := jobs[0]

		// Fail the original job.
		origJob.Finished = spanner.NullTime{Time: TimeNow(ctx), Valid: true}
		origJob.Aborted = true
		if origJob.AgentName.StringVal == req.AgentName {
			origJob.Error = "Aborted: assigned agent restarted"
		} else {
			origJob.Error = "Aborted: assigned agent has been inactive for too long"
		}

		mut, err := spanner.UpdateStruct("Jobs", origJob)
		if err != nil {
			return err
		}
		if err := txn.BufferWrite([]*spanner.Mutation{mut}); err != nil {
			return err
		}

		job = cloneJob(ctx, origJob)
		mut, err = startJob(ctx, req, job)
		if err != nil {
			return err
		}
		return txn.BufferWrite([]*spanner.Mutation{mut})
	})
	return job, err
}

func unfinishedAgentJobs(req *dashapi.AIJobPollReq, workflows, namespaces []string) spanner.Statement {
	sql := selectJobs() + ` WHERE Started IS NOT NULL AND Finished IS NULL
			AND AgentName = @agentName AND Workflow IN UNNEST(@workflows)
			AND Namespace IN UNNEST(@namespaces) LIMIT 1`
	params := map[string]any{
		"agentName":  req.AgentName,
		"workflows":  workflows,
		"namespaces": namespaces,
	}
	return spanner.Statement{SQL: sql, Params: params}
}

func staleUnfinishedJobs(cutoff time.Time, workflows, namespaces []string) spanner.Statement {
	sql := selectJobs() + ` JOIN Agents USING(AgentName)
			WHERE Started IS NOT NULL AND Finished IS NULL
			AND LastActive <= @cutoff AND Workflow IN UNNEST(@workflows)
			AND Namespace IN UNNEST(@namespaces) LIMIT 1`
	params := map[string]any{
		"cutoff":     cutoff,
		"workflows":  workflows,
		"namespaces": namespaces,
	}
	return spanner.Statement{SQL: sql, Params: params}
}

type JobFilter struct {
	Workflow    string
	ShowAborted bool
}

func LoadNamespaceJobs(ctx context.Context, ns string, filter *JobFilter) ([]*Job, error) {
	sql := selectJobs() + "WHERE Namespace = @ns"
	params := map[string]any{
		"ns": ns,
	}
	if filter == nil {
		filter = &JobFilter{}
	}
	switch filter.Workflow {
	case "", WorkflowAll:
		// No filtering by workflow.
	case WorkflowNeedsModeration:
		sql += " AND Type = Workflow AND Finished IS NOT NULL AND Error = '' AND Correct IS NULL"
	default:
		sql += " AND Workflow = @workflow"
		params["workflow"] = filter.Workflow
	}
	if !filter.ShowAborted {
		sql += " AND NOT Aborted"
	}
	sql += " ORDER BY Created DESC"
	return selectAll[Job](ctx, spanner.Statement{
		SQL:    sql,
		Params: params,
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
	if len(all) == 0 {
		return nil, ErrNotFound
	}
	if len(all) > 1 {
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
	client, err := spanner.NewClientWithConfig(context.Background(), path, spanner.ClientConfig{})
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

func selectAgents() string {
	return selectAllFrom[Agent]("Agents")
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

func selectJobReporting() string {
	return selectAllFrom[JobReporting]("JobReporting")
}

func AddJobReporting(ctx context.Context, entry *JobReporting) error {
	return saveEntity(ctx, "JobReporting", entry)
}

func checkNoParallelConflict(ctx context.Context, txn *spanner.ReadWriteTransaction, job *Job, stage string) error {
	iterConflict := txn.Query(ctx, spanner.Statement{
		SQL: `SELECT Jobs.ID
				FROM Jobs
				JOIN JobReporting ON Jobs.ID = JobReporting.JobID
				WHERE Jobs.BugID = @bugID
				  AND JobReporting.Stage = @stage
				  AND (Jobs.Correct IS NULL OR Jobs.Correct = true)
				  AND Jobs.ID != @currentJobID
				LIMIT 1`,
		Params: map[string]any{
			"bugID":        job.BugID.StringVal,
			"stage":        stage,
			"currentJobID": job.ID,
		},
	})
	defer iterConflict.Stop()
	var conflicts []string
	if err := spanner.SelectAll(iterConflict, &conflicts); err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &ErrCannotUpstream{
			Reason: fmt.Sprintf("cannot upstream: another report for this bug has already been sent to %s", stage),
		}
	}
	return nil
}

func AddJobReportingTransactional(ctx context.Context, job *Job, entry *JobReporting, noParallel bool) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	entry.ID = uuid.NewString()
	entry.JobID = job.ID
	entry.CreatedAt = TimeNow(ctx)

	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		if noParallel && job.BugID.Valid {
			if err := checkNoParallelConflict(ctx, txn, job, entry.Stage); err != nil {
				return err
			}
		}

		mut, err := spanner.InsertStruct("JobReporting", entry)
		if err != nil {
			return err
		}
		return txn.BufferWrite([]*spanner.Mutation{mut})
	})
	if err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists {
			return &ErrCannotUpstream{
				Reason: fmt.Sprintf("cannot upstream: another report for this bug has already been sent to %s", entry.Stage),
			}
		}
		return err
	}
	return nil
}

func UpstreamReportCommand(ctx context.Context, args UpstreamReportArgs) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	if args.Reporting != nil {
		args.Reporting.ID = uuid.NewString()
		args.Reporting.JobID = args.Job.ID
		args.Reporting.CreatedAt = TimeNow(ctx)
	}

	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.Statement{
			SQL:    selectJobs() + ` WHERE ID = @id`,
			Params: map[string]any{"id": args.Job.ID},
		}
		job, err := readRow[Job](ctx, txn, stmt)
		if err != nil {
			return err
		}
		if job == nil {
			return ErrNotFound
		}

		if args.NoParallel && job.BugID.Valid && args.Reporting != nil {
			if err := checkNoParallelConflict(ctx, txn, job, args.Reporting.Stage); err != nil {
				return err
			}
		}

		journal := &Journal{
			ID:          uuid.NewString(),
			JobID:       toNullString(args.Job.ID),
			Date:        TimeNow(ctx),
			User:        args.User,
			Action:      ActionApprove,
			Source:      toNullString(args.CommandSource),
			SourceExtID: toNullString(args.CommandExtID),
		}
		if args.Reporting != nil {
			journal.ReportingID = toNullString(args.Reporting.ID)
		}
		if args.Reason != "" {
			journal.Details = spanner.NullJSON{Value: map[string]string{"reason": args.Reason}, Valid: true}
		}
		journalMut, err := spanner.InsertStruct("Journal", journal)
		if err != nil {
			return err
		}
		jobMut := spanner.Update("Jobs",
			[]string{"ID", "Correct"},
			[]any{args.Job.ID, spanner.NullBool{Bool: true, Valid: true}})
		var mutations []*spanner.Mutation
		mutations = append(mutations, jobMut, journalMut)

		if args.Reporting != nil {
			reportingMut, err := spanner.InsertStruct("JobReporting", args.Reporting)
			if err != nil {
				return err
			}
			mutations = append(mutations, reportingMut)
		}

		return txn.BufferWrite(mutations)
	})
	if err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists {
			return nil // Idempotent no-op.
		}
		return err
	}
	return nil
}

func RejectReportCommand(ctx context.Context, args RejectReportArgs) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}

	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		journal := &Journal{
			ID:          uuid.NewString(),
			JobID:       toNullString(args.Job.ID),
			Date:        TimeNow(ctx),
			User:        args.User,
			Action:      ActionReject,
			Source:      toNullString(args.CommandSource),
			SourceExtID: toNullString(args.CommandExtID),
		}
		if args.Reason != "" {
			journal.Details = spanner.NullJSON{Value: map[string]string{"reason": args.Reason}, Valid: true}
		}
		journalMut, err := spanner.InsertStruct("Journal", journal)
		if err != nil {
			return err
		}

		jobMut := spanner.Update("Jobs",
			[]string{"ID", "Correct"},
			[]any{args.Job.ID, spanner.NullBool{Bool: false, Valid: true}})
		return txn.BufferWrite([]*spanner.Mutation{jobMut, journalMut})
	})
	if err != nil {
		if spanner.ErrCode(err) == codes.AlreadyExists {
			return nil // Idempotent no-op.
		}
		return err
	}
	return nil
}

func LoadPendingJobReportingBySource(ctx context.Context, source string) ([]*JobReporting, error) {
	return selectAll[JobReporting](ctx, spanner.Statement{
		SQL:    selectJobReporting() + `WHERE Source = @source AND ReportedAt IS NULL`,
		Params: map[string]any{"source": source},
	})
}

func LoadJobReportings(ctx context.Context, jobID string) ([]*JobReporting, error) {
	return selectAll[JobReporting](ctx, spanner.Statement{
		SQL:    selectJobReporting() + `WHERE JobID = @jobID`,
		Params: map[string]any{"jobID": jobID},
	})
}

func SaveJobComment(ctx context.Context, entry *JobComment) error {
	entry.ID = uuid.NewString()
	return saveEntity(ctx, "JobComments", entry)
}

func LoadJobComments(ctx context.Context, jobID string) ([]*JobComment, error) {
	return selectAll[JobComment](ctx, spanner.Statement{
		SQL: `SELECT JobComments.* FROM JobComments JOIN JobReporting ` +
			`ON JobComments.ReportingID = JobReporting.ID ` +
			`WHERE JobReporting.JobID = @jobID ` +
			`ORDER BY JobComments.Date ASC`,
		Params: map[string]any{"jobID": jobID},
	})
}

func JobReportingPublished(ctx context.Context, id, extID string) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		iter := tx.Query(ctx, spanner.Statement{
			SQL:    selectJobReporting() + ` WHERE ID = @id`,
			Params: map[string]any{"id": id},
		})
		defer iter.Stop()
		var reportings []*JobReporting
		if err := spanner.SelectAll(iter, &reportings); err != nil {
			return err
		}
		if len(reportings) == 0 {
			return ErrNotFound
		}
		r := reportings[0]
		r.ReportedAt = spanner.NullTime{Time: TimeNow(ctx), Valid: true}
		r.ExtID = spanner.NullString{StringVal: extID, Valid: extID != ""}

		mut, err := spanner.InsertOrUpdateStruct("JobReporting", r)
		if err != nil {
			return err
		}
		return tx.BufferWrite([]*spanner.Mutation{mut})
	})
	return err
}

type UpstreamReportArgs struct {
	Job           *Job
	Reporting     *JobReporting
	NoParallel    bool
	CommandSource string
	CommandExtID  string
	Reason        string
	User          string
}

type RejectReportArgs struct {
	Job           *Job
	CommandSource string
	CommandExtID  string
	User          string
	Reason        string
}

func LoadJobReportingByExtID(ctx context.Context, extID string) (*JobReporting, error) {
	res, err := selectOne[JobReporting](ctx, spanner.Statement{
		SQL:    selectJobReporting() + `WHERE ExtID = @extID LIMIT 1`,
		Params: map[string]any{"extID": extID},
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return res, err
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

func LoadJobJournal(ctx context.Context, jobID string) ([]*Journal, error) {
	return selectAll[Journal](ctx, spanner.Statement{
		SQL: selectJournal() + `WHERE JobID = @jobID ORDER BY Date DESC`,
		Params: map[string]any{
			"jobID": jobID,
		},
	})
}

func SetJobDone(ctx context.Context, jobID string, finished time.Time,
	errStr string, results map[string]any) (*Job, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	var job *Job
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.Statement{
			SQL:    selectJobs() + ` WHERE ID = @id`,
			Params: map[string]any{"id": jobID},
		}
		var err error
		job, err = readRow[Job](ctx, txn, stmt)
		if err != nil {
			return err
		}
		if job == nil {
			return ErrNotFound
		}

		if job.Finished.Valid {
			return fmt.Errorf("job %s is already finished", jobID)
		}

		job.Finished = spanner.NullTime{Time: finished, Valid: true}
		job.Error = errStr
		job.Results = toNullJSON(results)

		mut, err := spanner.UpdateStruct("Jobs", job)
		if err != nil {
			return err
		}
		return txn.BufferWrite([]*spanner.Mutation{mut})
	})
	if err != nil {
		return nil, err
	}
	return job, nil
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

func RunInTransaction(ctx context.Context, f func(ctx context.Context, txn *spanner.ReadWriteTransaction) error) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.ReadWriteTransaction(ctx, f)
	return err
}

func saveEntity[T any](ctx context.Context, table string, obj *T) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.InsertOrUpdateStruct(table, obj)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

type dbQuerier interface {
	Query(context.Context, spanner.Statement) *spanner.RowIterator
}

func readRow[T any](ctx context.Context, txn dbQuerier, stmt spanner.Statement) (*T, error) {
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()

	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var obj T
	err = row.ToStruct(&obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}
