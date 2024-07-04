// Copyright 2015 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bigquery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/internal"
	"cloud.google.com/go/internal/trace"
	gax "github.com/googleapis/gax-go/v2"
	bq "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

// A Job represents an operation which has been submitted to BigQuery for processing.
type Job struct {
	c          *Client
	projectID  string
	jobID      string
	location   string
	email      string
	config     *bq.JobConfiguration
	lastStatus *JobStatus
}

// JobFromID creates a Job which refers to an existing BigQuery job. The job
// need not have been created by this package. For example, the job may have
// been created in the BigQuery console.
//
// For jobs whose location is other than "US" or "EU", set Client.Location or use
// JobFromIDLocation.
func (c *Client) JobFromID(ctx context.Context, id string) (*Job, error) {
	return c.JobFromProject(ctx, c.projectID, id, c.Location)
}

// JobFromIDLocation creates a Job which refers to an existing BigQuery job. The job
// need not have been created by this package (for example, it may have
// been created in the BigQuery console), but it must exist in the specified location.
func (c *Client) JobFromIDLocation(ctx context.Context, id, location string) (j *Job, err error) {
	return c.JobFromProject(ctx, c.projectID, id, location)
}

// JobFromProject creates a Job which refers to an existing BigQuery job. The job
// need not have been created by this package, nor does it need to reside within the same
// project or location as the instantiated client.
func (c *Client) JobFromProject(ctx context.Context, projectID, jobID, location string) (j *Job, err error) {
	ctx = trace.StartSpan(ctx, "cloud.google.com/go/bigquery.JobFromProject")
	defer func() { trace.EndSpan(ctx, err) }()

	bqjob, err := c.getJobInternal(ctx, jobID, location, projectID, "user_email", "configuration", "jobReference", "status", "statistics")
	if err != nil {
		return nil, err
	}
	return bqToJob(bqjob, c)
}

// ProjectID returns the job's associated project.
func (j *Job) ProjectID() string {
	return j.projectID
}

// ID returns the job's ID.
func (j *Job) ID() string {
	return j.jobID
}

// Location returns the job's location.
func (j *Job) Location() string {
	return j.location
}

// Email returns the email of the job's creator.
func (j *Job) Email() string {
	return j.email
}

// State is one of a sequence of states that a Job progresses through as it is processed.
type State int

const (
	// StateUnspecified is the default JobIterator state.
	StateUnspecified State = iota
	// Pending is a state that describes that the job is pending.
	Pending
	// Running is a state that describes that the job is running.
	Running
	// Done is a state that describes that the job is done.
	Done
)

// JobStatus contains the current State of a job, and errors encountered while processing that job.
type JobStatus struct {
	State State

	err error

	// All errors encountered during the running of the job.
	// Not all Errors are fatal, so errors here do not necessarily mean that the job has completed or was unsuccessful.
	Errors []*Error

	// Statistics about the job.
	Statistics *JobStatistics
}

// JobConfig contains configuration information for a job. It is implemented by
// *CopyConfig, *ExtractConfig, *LoadConfig and *QueryConfig.
type JobConfig interface {
	isJobConfig()
}

func (*CopyConfig) isJobConfig()    {}
func (*ExtractConfig) isJobConfig() {}
func (*LoadConfig) isJobConfig()    {}
func (*QueryConfig) isJobConfig()   {}

// Config returns the configuration information for j.
func (j *Job) Config() (JobConfig, error) {
	return bqToJobConfig(j.config, j.c)
}

// Children returns a job iterator for enumerating child jobs
// of the current job.  Currently only scripts, a form of query job,
// will create child jobs.
func (j *Job) Children(ctx context.Context) *JobIterator {
	it := j.c.Jobs(ctx)
	it.ParentJobID = j.ID()
	return it
}

func bqToJobConfig(q *bq.JobConfiguration, c *Client) (JobConfig, error) {
	switch {
	case q == nil:
		return nil, nil
	case q.Copy != nil:
		return bqToCopyConfig(q, c), nil
	case q.Extract != nil:
		return bqToExtractConfig(q, c), nil
	case q.Load != nil:
		return bqToLoadConfig(q, c), nil
	case q.Query != nil:
		return bqToQueryConfig(q, c)
	default:
		return nil, nil
	}
}

// JobIDConfig  describes how to create an ID for a job.
type JobIDConfig struct {
	// JobID is the ID to use for the job. If empty, a random job ID will be generated.
	JobID string

	// If AddJobIDSuffix is true, then a random string will be appended to JobID.
	AddJobIDSuffix bool

	// Location is the location for the job.
	Location string

	// ProjectID is the Google Cloud project associated with the job.
	ProjectID string
}

// createJobRef creates a JobReference.
func (j *JobIDConfig) createJobRef(c *Client) *bq.JobReference {
	projectID := j.ProjectID
	if projectID == "" { // Use Client.ProjectID as a default.
		projectID = c.projectID
	}
	loc := j.Location
	if loc == "" { // Use Client.Location as a default.
		loc = c.Location
	}
	jr := &bq.JobReference{ProjectId: projectID, Location: loc}
	if j.JobID == "" {
		jr.JobId = randomIDFn()
	} else if j.AddJobIDSuffix {
		jr.JobId = j.JobID + "-" + randomIDFn()
	} else {
		jr.JobId = j.JobID
	}
	return jr
}

// Done reports whether the job has completed.
// After Done returns true, the Err method will return an error if the job completed unsuccessfully.
func (s *JobStatus) Done() bool {
	return s.State == Done
}

// Err returns the error that caused the job to complete unsuccessfully (if any).
func (s *JobStatus) Err() error {
	return s.err
}

// Status retrieves the current status of the job from BigQuery. It fails if the Status could not be determined.
func (j *Job) Status(ctx context.Context) (js *JobStatus, err error) {
	ctx = trace.StartSpan(ctx, "cloud.google.com/go/bigquery.Job.Status")
	defer func() { trace.EndSpan(ctx, err) }()

	bqjob, err := j.c.getJobInternal(ctx, j.jobID, j.location, j.projectID, "status", "statistics")
	if err != nil {
		return nil, err
	}
	if err := j.setStatus(bqjob.Status); err != nil {
		return nil, err
	}
	j.setStatistics(bqjob.Statistics, j.c)
	return j.lastStatus, nil
}

// LastStatus returns the most recently retrieved status of the job. The status is
// retrieved when a new job is created, or when JobFromID or Job.Status is called.
// Call Job.Status to get the most up-to-date information about a job.
func (j *Job) LastStatus() *JobStatus {
	return j.lastStatus
}

// Cancel requests that a job be cancelled. This method returns without waiting for
// cancellation to take effect. To check whether the job has terminated, use Job.Status.
// Cancelled jobs may still incur costs.
func (j *Job) Cancel(ctx context.Context) error {
	// Jobs.Cancel returns a job entity, but the only relevant piece of
	// data it may contain (the status of the job) is unreliable.  From the
	// docs: "This call will return immediately, and the client will need
	// to poll for the job status to see if the cancel completed
	// successfully".  So it would be misleading to return a status.
	call := j.c.bqs.Jobs.Cancel(j.projectID, j.jobID).
		Location(j.location).
		Fields(). // We don't need any of the response data.
		Context(ctx)
	setClientHeader(call.Header())
	return runWithRetry(ctx, func() error {
		sCtx := trace.StartSpan(ctx, "bigquery.jobs.cancel")
		_, err := call.Do()
		trace.EndSpan(sCtx, err)
		return err
	})
}

// Delete deletes the job.
func (j *Job) Delete(ctx context.Context) (err error) {
	ctx = trace.StartSpan(ctx, "cloud.google.com/go/bigquery.Job.Delete")
	defer func() { trace.EndSpan(ctx, err) }()

	call := j.c.bqs.Jobs.Delete(j.projectID, j.jobID).Context(ctx)
	if j.location != "" {
		call = call.Location(j.location)
	}
	setClientHeader(call.Header())

	return runWithRetry(ctx, func() (err error) {
		sCtx := trace.StartSpan(ctx, "bigquery.jobs.delete")
		err = call.Do()
		trace.EndSpan(sCtx, err)
		return err
	})
}

// Wait blocks until the job or the context is done. It returns the final status
// of the job.
// If an error occurs while retrieving the status, Wait returns that error. But
// Wait returns nil if the status was retrieved successfully, even if
// status.Err() != nil. So callers must check both errors. See the example.
func (j *Job) Wait(ctx context.Context) (js *JobStatus, err error) {
	ctx = trace.StartSpan(ctx, "cloud.google.com/go/bigquery.Job.Wait")
	defer func() { trace.EndSpan(ctx, err) }()

	if j.isQuery() {
		// We can avoid polling for query jobs.
		if _, _, err := j.waitForQuery(ctx, j.projectID); err != nil {
			return nil, err
		}
		// Note: extra RPC even if you just want to wait for the query to finish.
		js, err := j.Status(ctx)
		if err != nil {
			return nil, err
		}
		return js, nil
	}
	// Non-query jobs must poll.
	err = internal.Retry(ctx, gax.Backoff{}, func() (stop bool, err error) {
		js, err = j.Status(ctx)
		if err != nil {
			return true, err
		}
		if js.Done() {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return js, nil
}

// Read fetches the results of a query job.
// If j is not a query job, Read returns an error.
func (j *Job) Read(ctx context.Context) (ri *RowIterator, err error) {
	ctx = trace.StartSpan(ctx, "cloud.google.com/go/bigquery.Job.Read")
	defer func() { trace.EndSpan(ctx, err) }()

	return j.read(ctx, j.waitForQuery, fetchPage)
}

func (j *Job) read(ctx context.Context, waitForQuery func(context.Context, string) (Schema, uint64, error), pf pageFetcher) (*RowIterator, error) {
	if !j.isQuery() {
		return nil, errors.New("bigquery: cannot read from a non-query job")
	}
	schema, totalRows, err := waitForQuery(ctx, j.projectID)
	if err != nil {
		return nil, err
	}
	var it *RowIterator
	if j.c.isStorageReadAvailable() {
		it, err = newStorageRowIteratorFromJob(ctx, j)
		if err != nil {
			it = nil
		}
	}
	if it == nil {
		// Shave off some potential overhead by only retaining the minimal job representation in the iterator.
		itJob := &Job{
			c:         j.c,
			projectID: j.projectID,
			jobID:     j.jobID,
			location:  j.location,
		}
		it = newRowIterator(ctx, &rowSource{j: itJob}, pf)
		it.TotalRows = totalRows
	}
	it.Schema = schema
	return it, nil
}

// waitForQuery waits for the query job to complete and returns its schema. It also
// returns the total number of rows in the result set.
func (j *Job) waitForQuery(ctx context.Context, projectID string) (Schema, uint64, error) {
	// Use GetQueryResults only to wait for completion, not to read results.
	call := j.c.bqs.Jobs.GetQueryResults(projectID, j.jobID).Location(j.location).Context(ctx).MaxResults(0)
	call = call.FormatOptionsUseInt64Timestamp(true)
	setClientHeader(call.Header())
	backoff := gax.Backoff{
		Initial:    1 * time.Second,
		Multiplier: 2,
		Max:        60 * time.Second,
	}
	var res *bq.GetQueryResultsResponse
	err := internal.Retry(ctx, backoff, func() (stop bool, err error) {
		sCtx := trace.StartSpan(ctx, "bigquery.jobs.getQueryResults")
		res, err = call.Do()
		trace.EndSpan(sCtx, err)
		if err != nil {
			return !retryableError(err, jobRetryReasons), err
		}
		if !res.JobComplete { // GetQueryResults may return early without error; retry.
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return nil, 0, err
	}
	return bqToSchema(res.Schema), res.TotalRows, nil
}

// JobStatistics contains statistics about a job.
type JobStatistics struct {
	CreationTime        time.Time
	StartTime           time.Time
	EndTime             time.Time
	TotalBytesProcessed int64

	Details Statistics

	// NumChildJobs indicates the number of child jobs run as part of a script.
	NumChildJobs int64

	// ParentJobID indicates the origin job for jobs run as part of a script.
	ParentJobID string

	// ScriptStatistics includes information run as part of a child job within
	// a script.
	ScriptStatistics *ScriptStatistics

	// ReservationUsage attributes slot consumption to reservations.
	ReservationUsage []*ReservationUsage

	// TransactionInfo indicates the transaction ID associated with the job, if any.
	TransactionInfo *TransactionInfo

	// SessionInfo contains information about the session if this job is part of one.
	SessionInfo *SessionInfo
}

// Statistics is one of ExtractStatistics, LoadStatistics or QueryStatistics.
type Statistics interface {
	implementsStatistics()
}

// ExtractStatistics contains statistics about an extract job.
type ExtractStatistics struct {
	// The number of files per destination URI or URI pattern specified in the
	// extract configuration. These values will be in the same order as the
	// URIs specified in the 'destinationUris' field.
	DestinationURIFileCounts []int64
}

// LoadStatistics contains statistics about a load job.
type LoadStatistics struct {
	// The number of bytes of source data in a load job.
	InputFileBytes int64

	// The number of source files in a load job.
	InputFiles int64

	// Size of the loaded data in bytes. Note that while a load job is in the
	// running state, this value may change.
	OutputBytes int64

	// The number of rows imported in a load job. Note that while an import job is
	// in the running state, this value may change.
	OutputRows int64
}

// QueryStatistics contains statistics about a query job.
type QueryStatistics struct {

	// BI-Engine specific statistics.
	BIEngineStatistics *BIEngineStatistics

	// Billing tier for the job.
	BillingTier int64

	// Whether the query result was fetched from the query cache.
	CacheHit bool

	// The type of query statement, if valid.
	StatementType string

	// Total bytes billed for the job.
	TotalBytesBilled int64

	// Total bytes processed for the job.
	TotalBytesProcessed int64

	// For dry run queries, indicates how accurate the TotalBytesProcessed value is.
	// When indicated, values include:
	// UNKNOWN: accuracy of the estimate is unknown.
	// PRECISE: estimate is precise.
	// LOWER_BOUND: estimate is lower bound of what the query would cost.
	// UPPER_BOUND: estimate is upper bound of what the query would cost.
	TotalBytesProcessedAccuracy string

	// Describes execution plan for the query.
	QueryPlan []*ExplainQueryStage

	// The number of rows affected by a DML statement. Present only for DML
	// statements INSERT, UPDATE or DELETE.
	NumDMLAffectedRows int64

	// DMLStats provides statistics about the row mutations performed by
	// DML statements.
	DMLStats *DMLStatistics

	// Describes a timeline of job execution.
	Timeline []*QueryTimelineSample

	// ReferencedTables: [Output-only] Referenced tables for
	// the job. Queries that reference more than 50 tables will not have a
	// complete list.
	ReferencedTables []*Table

	// The schema of the results. Present only for successful dry run of
	// non-legacy SQL queries.
	Schema Schema

	// Slot-milliseconds consumed by this query job.
	SlotMillis int64

	// Standard SQL: list of undeclared query parameter names detected during a
	// dry run validation.
	UndeclaredQueryParameterNames []string

	// DDL target table.
	DDLTargetTable *Table

	// DDL Operation performed on the target table.  Used to report how the
	// query impacted the DDL target table.
	DDLOperationPerformed string

	// The DDL target table, present only for CREATE/DROP FUNCTION/PROCEDURE queries.
	DDLTargetRoutine *Routine

	// Statistics for the EXPORT DATA statement as part of Query Job.
	ExportDataStatistics *ExportDataStatistics
}

// ExportDataStatistics represents statistics for
// a EXPORT DATA statement as part of Query Job.
type ExportDataStatistics struct {
	// Number of destination files generated.
	FileCount int64

	// Number of destination rows generated.
	RowCount int64
}

func bqToExportDataStatistics(in *bq.ExportDataStatistics) *ExportDataStatistics {
	if in == nil {
		return nil
	}
	stats := &ExportDataStatistics{
		FileCount: in.FileCount,
		RowCount:  in.RowCount,
	}
	return stats
}

// BIEngineStatistics contains query statistics specific to the use of BI Engine.
type BIEngineStatistics struct {
	// Specifies which mode of BI Engine acceleration was performed.
	BIEngineMode string

	// In case of DISABLED or PARTIAL BIEngineMode, these
	// contain the explanatory reasons as to why BI Engine could not
	// accelerate. In case the full query was accelerated, this field is not
	// populated.
	BIEngineReasons []*BIEngineReason
}

func bqToBIEngineStatistics(in *bq.BiEngineStatistics) *BIEngineStatistics {
	if in == nil {
		return nil
	}
	stats := &BIEngineStatistics{
		BIEngineMode: in.BiEngineMode,
	}
	for _, v := range in.BiEngineReasons {
		stats.BIEngineReasons = append(stats.BIEngineReasons, bqToBIEngineReason(v))
	}
	return stats
}

// BIEngineReason contains more detailed information about why a query wasn't fully
// accelerated.
type BIEngineReason struct {
	// High-Level BI engine reason for partial or disabled acceleration.
	Code string

	// Human-readable reason for partial or disabled acceleration.
	Message string
}

func bqToBIEngineReason(in *bq.BiEngineReason) *BIEngineReason {
	if in == nil {
		return nil
	}
	return &BIEngineReason{
		Code:    in.Code,
		Message: in.Message,
	}
}

// ExplainQueryStage describes one stage of a query.
type ExplainQueryStage struct {
	// CompletedParallelInputs: Number of parallel input segments completed.
	CompletedParallelInputs int64

	// ComputeAvg: Duration the average shard spent on CPU-bound tasks.
	ComputeAvg time.Duration

	// ComputeMax: Duration the slowest shard spent on CPU-bound tasks.
	ComputeMax time.Duration

	// Relative amount of the total time the average shard spent on CPU-bound tasks.
	ComputeRatioAvg float64

	// Relative amount of the total time the slowest shard spent on CPU-bound tasks.
	ComputeRatioMax float64

	// EndTime: Stage end time.
	EndTime time.Time

	// Unique ID for stage within plan.
	ID int64

	// InputStages: IDs for stages that are inputs to this stage.
	InputStages []int64

	// Human-readable name for stage.
	Name string

	// ParallelInputs: Number of parallel input segments to be processed.
	ParallelInputs int64

	// ReadAvg: Duration the average shard spent reading input.
	ReadAvg time.Duration

	// ReadMax: Duration the slowest shard spent reading input.
	ReadMax time.Duration

	// Relative amount of the total time the average shard spent reading input.
	ReadRatioAvg float64

	// Relative amount of the total time the slowest shard spent reading input.
	ReadRatioMax float64

	// Number of records read into the stage.
	RecordsRead int64

	// Number of records written by the stage.
	RecordsWritten int64

	// ShuffleOutputBytes: Total number of bytes written to shuffle.
	ShuffleOutputBytes int64

	// ShuffleOutputBytesSpilled: Total number of bytes written to shuffle
	// and spilled to disk.
	ShuffleOutputBytesSpilled int64

	// StartTime: Stage start time.
	StartTime time.Time

	// Current status for the stage.
	Status string

	// List of operations within the stage in dependency order (approximately
	// chronological).
	Steps []*ExplainQueryStep

	// WaitAvg: Duration the average shard spent waiting to be scheduled.
	WaitAvg time.Duration

	// WaitMax: Duration the slowest shard spent waiting to be scheduled.
	WaitMax time.Duration

	// Relative amount of the total time the average shard spent waiting to be scheduled.
	WaitRatioAvg float64

	// Relative amount of the total time the slowest shard spent waiting to be scheduled.
	WaitRatioMax float64

	// WriteAvg: Duration the average shard spent on writing output.
	WriteAvg time.Duration

	// WriteMax: Duration the slowest shard spent on writing output.
	WriteMax time.Duration

	// Relative amount of the total time the average shard spent on writing output.
	WriteRatioAvg float64

	// Relative amount of the total time the slowest shard spent on writing output.
	WriteRatioMax float64
}

// ExplainQueryStep describes one step of a query stage.
type ExplainQueryStep struct {
	// Machine-readable operation type.
	Kind string

	// Human-readable stage descriptions.
	Substeps []string
}

// QueryTimelineSample represents a sample of execution statistics at a point in time.
type QueryTimelineSample struct {

	// Total number of units currently being processed by workers, represented as largest value since last sample.
	ActiveUnits int64

	// Total parallel units of work completed by this query.
	CompletedUnits int64

	// Time elapsed since start of query execution.
	Elapsed time.Duration

	// Total parallel units of work remaining for the active stages.
	PendingUnits int64

	// Cumulative slot-milliseconds consumed by the query.
	SlotMillis int64
}

// ReservationUsage contains information about a job's usage of a single reservation.
type ReservationUsage struct {
	// SlotMillis reports the slot milliseconds utilized within in the given reservation.
	SlotMillis int64
	// Name indicates the utilized reservation name, or "unreserved" for ondemand usage.
	Name string
}

func bqToReservationUsage(ru []*bq.JobStatisticsReservationUsage) []*ReservationUsage {
	var usage []*ReservationUsage
	for _, in := range ru {
		usage = append(usage, &ReservationUsage{
			SlotMillis: in.SlotMs,
			Name:       in.Name,
		})
	}
	return usage
}

// ScriptStatistics report information about script-based query jobs.
type ScriptStatistics struct {
	EvaluationKind string
	StackFrames    []*ScriptStackFrame
}

func bqToScriptStatistics(bs *bq.ScriptStatistics) *ScriptStatistics {
	if bs == nil {
		return nil
	}
	ss := &ScriptStatistics{
		EvaluationKind: bs.EvaluationKind,
	}
	for _, f := range bs.StackFrames {
		ss.StackFrames = append(ss.StackFrames, bqToScriptStackFrame(f))
	}
	return ss
}

// ScriptStackFrame represents the location of the statement/expression being evaluated.
//
// Line and column numbers are defined as follows:
//
//   - Line and column numbers start with one.  That is, line 1 column 1 denotes
//     the start of the script.
//   - When inside a stored procedure, all line/column numbers are relative
//     to the procedure body, not the script in which the procedure was defined.
//   - Start/end positions exclude leading/trailing comments and whitespace.
//     The end position always ends with a ";", when present.
//   - Multi-byte Unicode characters are treated as just one column.
//   - If the original script (or procedure definition) contains TAB characters,
//     a tab "snaps" the indentation forward to the nearest multiple of 8
//     characters, plus 1. For example, a TAB on column 1, 2, 3, 4, 5, 6 , or 8
//     will advance the next character to column 9.  A TAB on column 9, 10, 11,
//     12, 13, 14, 15, or 16 will advance the next character to column 17.
type ScriptStackFrame struct {
	StartLine   int64
	StartColumn int64
	EndLine     int64
	EndColumn   int64
	// Name of the active procedure.  Empty if in a top-level script.
	ProcedureID string
	// Text of the current statement/expression.
	Text string
}

func bqToScriptStackFrame(bsf *bq.ScriptStackFrame) *ScriptStackFrame {
	if bsf == nil {
		return nil
	}
	return &ScriptStackFrame{
		StartLine:   bsf.StartLine,
		StartColumn: bsf.StartColumn,
		EndLine:     bsf.EndLine,
		EndColumn:   bsf.EndColumn,
		ProcedureID: bsf.ProcedureId,
		Text:        bsf.Text,
	}
}

// DMLStatistics contains counts of row mutations triggered by a DML query statement.
type DMLStatistics struct {
	// Rows added by the statement.
	InsertedRowCount int64
	// Rows removed by the statement.
	DeletedRowCount int64
	// Rows changed by the statement.
	UpdatedRowCount int64
}

func bqToDMLStatistics(q *bq.DmlStatistics) *DMLStatistics {
	if q == nil {
		return nil
	}
	return &DMLStatistics{
		InsertedRowCount: q.InsertedRowCount,
		DeletedRowCount:  q.DeletedRowCount,
		UpdatedRowCount:  q.UpdatedRowCount,
	}
}

func (*ExtractStatistics) implementsStatistics() {}
func (*LoadStatistics) implementsStatistics()    {}
func (*QueryStatistics) implementsStatistics()   {}

// Jobs lists jobs within a project.
func (c *Client) Jobs(ctx context.Context) *JobIterator {
	it := &JobIterator{
		ctx:       ctx,
		c:         c,
		ProjectID: c.projectID,
	}
	it.pageInfo, it.nextFunc = iterator.NewPageInfo(
		it.fetch,
		func() int { return len(it.items) },
		func() interface{} { b := it.items; it.items = nil; return b })
	return it
}

// JobIterator iterates over jobs in a project.
type JobIterator struct {
	ProjectID       string    // Project ID of the jobs to list. Default is the client's project.
	AllUsers        bool      // Whether to list jobs owned by all users in the project, or just the current caller.
	State           State     // List only jobs in the given state. Defaults to all states.
	MinCreationTime time.Time // List only jobs created after this time.
	MaxCreationTime time.Time // List only jobs created before this time.
	ParentJobID     string    // List only jobs that are children of a given scripting job.

	ctx      context.Context
	c        *Client
	pageInfo *iterator.PageInfo
	nextFunc func() error
	items    []*Job
}

// PageInfo is a getter for the JobIterator's PageInfo.
func (it *JobIterator) PageInfo() *iterator.PageInfo { return it.pageInfo }

// Next returns the next Job. Its second return value is iterator.Done if
// there are no more results. Once Next returns Done, all subsequent calls will
// return Done.
func (it *JobIterator) Next() (*Job, error) {
	if err := it.nextFunc(); err != nil {
		return nil, err
	}
	item := it.items[0]
	it.items = it.items[1:]
	return item, nil
}

func (it *JobIterator) fetch(pageSize int, pageToken string) (string, error) {
	var st string
	switch it.State {
	case StateUnspecified:
		st = ""
	case Pending:
		st = "pending"
	case Running:
		st = "running"
	case Done:
		st = "done"
	default:
		return "", fmt.Errorf("bigquery: invalid value for JobIterator.State: %d", it.State)
	}

	req := it.c.bqs.Jobs.List(it.ProjectID).
		Context(it.ctx).
		PageToken(pageToken).
		Projection("full").
		AllUsers(it.AllUsers)
	if st != "" {
		req.StateFilter(st)
	}
	if !it.MinCreationTime.IsZero() {
		req.MinCreationTime(uint64(it.MinCreationTime.UnixNano() / 1e6))
	}
	if !it.MaxCreationTime.IsZero() {
		req.MaxCreationTime(uint64(it.MaxCreationTime.UnixNano() / 1e6))
	}
	setClientHeader(req.Header())
	if pageSize > 0 {
		req.MaxResults(int64(pageSize))
	}
	if it.ParentJobID != "" {
		req.ParentJobId(it.ParentJobID)
	}
	var res *bq.JobList
	err := runWithRetry(it.ctx, func() (err error) {
		sCtx := trace.StartSpan(it.ctx, "bigquery.jobs.list")
		res, err = req.Do()
		trace.EndSpan(sCtx, err)
		return err
	})

	if err != nil {
		return "", err
	}
	for _, j := range res.Jobs {
		job, err := convertListedJob(j, it.c)
		if err != nil {
			return "", err
		}
		it.items = append(it.items, job)
	}
	return res.NextPageToken, nil
}

func convertListedJob(j *bq.JobListJobs, c *Client) (*Job, error) {
	return bqToJob2(j.JobReference, j.Configuration, j.Status, j.Statistics, j.UserEmail, c)
}

func (c *Client) getJobInternal(ctx context.Context, jobID, location, projectID string, fields ...googleapi.Field) (*bq.Job, error) {
	var job *bq.Job
	proj := projectID
	if proj == "" {
		proj = c.projectID
	}
	call := c.bqs.Jobs.Get(proj, jobID).Context(ctx)
	if location != "" {
		call = call.Location(location)
	}
	if len(fields) > 0 {
		call = call.Fields(fields...)
	}
	setClientHeader(call.Header())
	err := runWithRetry(ctx, func() (err error) {
		sCtx := trace.StartSpan(ctx, "bigquery.jobs.get")
		job, err = call.Do()
		trace.EndSpan(sCtx, err)
		return err
	})
	if err != nil {
		return nil, err
	}
	return job, nil
}

func bqToJob(q *bq.Job, c *Client) (*Job, error) {
	return bqToJob2(q.JobReference, q.Configuration, q.Status, q.Statistics, q.UserEmail, c)
}

func bqToJob2(qr *bq.JobReference, qc *bq.JobConfiguration, qs *bq.JobStatus, qt *bq.JobStatistics, email string, c *Client) (*Job, error) {
	j := &Job{
		projectID: qr.ProjectId,
		jobID:     qr.JobId,
		location:  qr.Location,
		c:         c,
		email:     email,
	}
	j.setConfig(qc)
	if err := j.setStatus(qs); err != nil {
		return nil, err
	}
	j.setStatistics(qt, c)
	return j, nil
}

func (j *Job) setConfig(config *bq.JobConfiguration) {
	if config == nil {
		return
	}
	j.config = config
}

func (j *Job) isQuery() bool {
	return j.config != nil && j.config.Query != nil
}

func (j *Job) isScript() bool {
	return j.hasStatementType("SCRIPT")
}

func (j *Job) isSelectQuery() bool {
	return j.hasStatementType("SELECT")
}

func (j *Job) hasStatementType(statementType string) bool {
	if !j.isQuery() {
		return false
	}
	if j.lastStatus == nil {
		return false
	}
	queryStats, ok := j.lastStatus.Statistics.Details.(*QueryStatistics)
	if !ok {
		return false
	}
	return queryStats.StatementType == statementType
}

var stateMap = map[string]State{"PENDING": Pending, "RUNNING": Running, "DONE": Done}

func (j *Job) setStatus(qs *bq.JobStatus) error {
	if qs == nil {
		return nil
	}
	state, ok := stateMap[qs.State]
	if !ok {
		return fmt.Errorf("unexpected job state: %s", qs.State)
	}
	j.lastStatus = &JobStatus{
		State: state,
		err:   nil,
	}
	if err := bqToError(qs.ErrorResult); state == Done && err != nil {
		j.lastStatus.err = err
	}
	for _, ep := range qs.Errors {
		j.lastStatus.Errors = append(j.lastStatus.Errors, bqToError(ep))
	}
	return nil
}

func (j *Job) setStatistics(s *bq.JobStatistics, c *Client) {
	if s == nil || j.lastStatus == nil {
		return
	}
	js := &JobStatistics{
		CreationTime:        unixMillisToTime(s.CreationTime),
		StartTime:           unixMillisToTime(s.StartTime),
		EndTime:             unixMillisToTime(s.EndTime),
		TotalBytesProcessed: s.TotalBytesProcessed,
		NumChildJobs:        s.NumChildJobs,
		ParentJobID:         s.ParentJobId,
		ScriptStatistics:    bqToScriptStatistics(s.ScriptStatistics),
		ReservationUsage:    bqToReservationUsage(s.ReservationUsage),
		TransactionInfo:     bqToTransactionInfo(s.TransactionInfo),
		SessionInfo:         bqToSessionInfo(s.SessionInfo),
	}
	switch {
	case s.Extract != nil:
		js.Details = &ExtractStatistics{
			DestinationURIFileCounts: []int64(s.Extract.DestinationUriFileCounts),
		}
	case s.Load != nil:
		js.Details = &LoadStatistics{
			InputFileBytes: s.Load.InputFileBytes,
			InputFiles:     s.Load.InputFiles,
			OutputBytes:    s.Load.OutputBytes,
			OutputRows:     s.Load.OutputRows,
		}
	case s.Query != nil:
		var names []string
		for _, qp := range s.Query.UndeclaredQueryParameters {
			names = append(names, qp.Name)
		}
		var tables []*Table
		for _, tr := range s.Query.ReferencedTables {
			tables = append(tables, bqToTable(tr, c))
		}
		js.Details = &QueryStatistics{
			BIEngineStatistics:            bqToBIEngineStatistics(s.Query.BiEngineStatistics),
			BillingTier:                   s.Query.BillingTier,
			CacheHit:                      s.Query.CacheHit,
			DDLTargetTable:                bqToTable(s.Query.DdlTargetTable, c),
			DDLOperationPerformed:         s.Query.DdlOperationPerformed,
			DDLTargetRoutine:              bqToRoutine(s.Query.DdlTargetRoutine, c),
			ExportDataStatistics:          bqToExportDataStatistics(s.Query.ExportDataStatistics),
			StatementType:                 s.Query.StatementType,
			TotalBytesBilled:              s.Query.TotalBytesBilled,
			TotalBytesProcessed:           s.Query.TotalBytesProcessed,
			TotalBytesProcessedAccuracy:   s.Query.TotalBytesProcessedAccuracy,
			NumDMLAffectedRows:            s.Query.NumDmlAffectedRows,
			DMLStats:                      bqToDMLStatistics(s.Query.DmlStats),
			QueryPlan:                     queryPlanFromProto(s.Query.QueryPlan),
			Schema:                        bqToSchema(s.Query.Schema),
			SlotMillis:                    s.Query.TotalSlotMs,
			Timeline:                      timelineFromProto(s.Query.Timeline),
			ReferencedTables:              tables,
			UndeclaredQueryParameterNames: names,
		}
	}
	j.lastStatus.Statistics = js
}

func queryPlanFromProto(stages []*bq.ExplainQueryStage) []*ExplainQueryStage {
	var res []*ExplainQueryStage
	for _, s := range stages {
		var steps []*ExplainQueryStep
		for _, p := range s.Steps {
			steps = append(steps, &ExplainQueryStep{
				Kind:     p.Kind,
				Substeps: p.Substeps,
			})
		}
		res = append(res, &ExplainQueryStage{
			CompletedParallelInputs:   s.CompletedParallelInputs,
			ComputeAvg:                time.Duration(s.ComputeMsAvg) * time.Millisecond,
			ComputeMax:                time.Duration(s.ComputeMsMax) * time.Millisecond,
			ComputeRatioAvg:           s.ComputeRatioAvg,
			ComputeRatioMax:           s.ComputeRatioMax,
			EndTime:                   time.Unix(0, s.EndMs*1e6),
			ID:                        s.Id,
			InputStages:               s.InputStages,
			Name:                      s.Name,
			ParallelInputs:            s.ParallelInputs,
			ReadAvg:                   time.Duration(s.ReadMsAvg) * time.Millisecond,
			ReadMax:                   time.Duration(s.ReadMsMax) * time.Millisecond,
			ReadRatioAvg:              s.ReadRatioAvg,
			ReadRatioMax:              s.ReadRatioMax,
			RecordsRead:               s.RecordsRead,
			RecordsWritten:            s.RecordsWritten,
			ShuffleOutputBytes:        s.ShuffleOutputBytes,
			ShuffleOutputBytesSpilled: s.ShuffleOutputBytesSpilled,
			StartTime:                 time.Unix(0, s.StartMs*1e6),
			Status:                    s.Status,
			Steps:                     steps,
			WaitAvg:                   time.Duration(s.WaitMsAvg) * time.Millisecond,
			WaitMax:                   time.Duration(s.WaitMsMax) * time.Millisecond,
			WaitRatioAvg:              s.WaitRatioAvg,
			WaitRatioMax:              s.WaitRatioMax,
			WriteAvg:                  time.Duration(s.WriteMsAvg) * time.Millisecond,
			WriteMax:                  time.Duration(s.WriteMsMax) * time.Millisecond,
			WriteRatioAvg:             s.WriteRatioAvg,
			WriteRatioMax:             s.WriteRatioMax,
		})
	}
	return res
}

func timelineFromProto(timeline []*bq.QueryTimelineSample) []*QueryTimelineSample {
	var res []*QueryTimelineSample
	for _, s := range timeline {
		res = append(res, &QueryTimelineSample{
			ActiveUnits:    s.ActiveUnits,
			CompletedUnits: s.CompletedUnits,
			Elapsed:        time.Duration(s.ElapsedMs) * time.Millisecond,
			PendingUnits:   s.PendingUnits,
			SlotMillis:     s.TotalSlotMs,
		})
	}
	return res
}

// TransactionInfo contains information about a multi-statement transaction that may have associated with a job.
type TransactionInfo struct {
	// TransactionID is the system-generated identifier for the transaction.
	TransactionID string
}

func bqToTransactionInfo(in *bq.TransactionInfo) *TransactionInfo {
	if in == nil {
		return nil
	}
	return &TransactionInfo{
		TransactionID: in.TransactionId,
	}
}

// SessionInfo contains information about a session associated with a job.
type SessionInfo struct {
	SessionID string
}

func bqToSessionInfo(in *bq.SessionInfo) *SessionInfo {
	if in == nil {
		return nil
	}
	return &SessionInfo{
		SessionID: in.SessionId,
	}
}
