// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/gerrit"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/vcs"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

const AIAccessLevel = AccessUser

type uiAIJobsPage struct {
	Header          *uiHeader
	Jobs            []*uiAIJob
	Workflows       []string
	CurrentWorkflow string
}

type uiAIJobPage struct {
	Header *uiHeader
	Job    *uiAIJob
	// The slice contains the same single Job, just for HTML templates convenience.
	Jobs        []*uiAIJob
	CrashReport template.HTML
	Trajectory  []*uiAITrajectorySpan
	History     []*uiJobReviewHistory
}

type uiJobReviewHistory struct {
	Date    time.Time
	User    string
	Correct string
}

type uiAIJob struct {
	ID               string
	Link             string
	Workflow         string
	Description      string
	DescriptionLink  string
	Created          time.Time
	Started          time.Time
	Finished         time.Time
	CodeRevision     string
	CodeRevisionLink string
	Error            string
	Correct          string
	Results          []*uiAIResult
}

type uiAIResult struct {
	Name   string
	IsBool bool
	Value  any
}

type uiAITrajectorySpan struct {
	Started              time.Time
	Seq                  int64
	Nesting              int64
	Type                 string
	Name                 string
	Model                string
	Duration             time.Duration
	Error                string
	Args                 string
	Results              string
	Instruction          string
	Prompt               string
	Reply                string
	Thoughts             string
	InputTokens          int
	OutputTokens         int
	OutputThoughtsTokens int
}

func handleAIJobsPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if err := checkAccessLevel(ctx, r, AIAccessLevel); err != nil {
		return err
	}
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	jobs, err := aidb.LoadNamespaceJobs(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	workflowParam := r.FormValue("workflow")
	var uiJobs []*uiAIJob
	for _, job := range jobs {
		if workflowParam != "" && job.Workflow != workflowParam {
			continue
		}
		uiJobs = append(uiJobs, makeUIAIJob(job))
	}
	workflows, err := aidb.LoadWorkflows(ctx)
	if err != nil {
		return err
	}
	var workflowNames []string
	for _, w := range workflows {
		workflowNames = append(workflowNames, w.Name)
	}
	slices.Sort(workflowNames)
	page := &uiAIJobsPage{
		Header:          hdr,
		Jobs:            uiJobs,
		Workflows:       workflowNames,
		CurrentWorkflow: workflowParam,
	}
	return serveTemplate(w, "ai_jobs.html", page)
}

func handleAIJobPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if err := checkAccessLevel(ctx, r, AIAccessLevel); err != nil {
		return err
	}
	job, err := aidb.LoadJob(ctx, r.FormValue("id"))
	if err != nil {
		return err
	}
	if correct := r.FormValue("correct"); correct != "" {
		if !job.Finished.Valid || job.Error != "" {
			return fmt.Errorf("job is in wrong state to set correct status")
		}
		switch correct {
		case aiCorrectnessCorrect:
			job.Correct = spanner.NullBool{Bool: true, Valid: true}
		case aiCorrectnessIncorrect:
			job.Correct = spanner.NullBool{Bool: false, Valid: true}
		default:
			job.Correct = spanner.NullBool{}
		}
		userEmail := ""
		if user := currentUser(ctx); user != nil {
			userEmail = user.Email
		}
		if err := aidb.AddJournalEntry(ctx, &aidb.Journal{
			JobID:   spanner.NullString{StringVal: job.ID, Valid: true},
			Date:    timeNow(ctx),
			User:    userEmail,
			Action:  aidb.ActionJobReview,
			Details: spanner.NullJSON{Value: aidb.JobReviewDetails{Correct: job.Correct.Bool}, Valid: true},
		}); err != nil {
			return err
		}
		if err := aiJobUpdate(ctx, job); err != nil {
			return err
		}
	}
	trajectory, err := aidb.LoadTrajectory(ctx, job.ID)
	if err != nil {
		return err
	}
	history, err := aidb.LoadJobJournal(ctx, job.ID, aidb.ActionJobReview)
	if err != nil {
		return err
	}
	hdr, err := commonHeader(ctx, r, w, job.Namespace)
	if err != nil {
		return err
	}
	var args map[string]any
	if job.Args.Valid {
		args = job.Args.Value.(map[string]any)
	}
	var crashReport template.HTML
	if reportID, _ := args["CrashReportID"].(json.Number).Int64(); reportID != 0 {
		report, _, err := getText(ctx, textCrashReport, reportID)
		if err != nil {
			return err
		}
		crashReport = linkifyReport(report, args["KernelRepo"].(string), args["KernelCommit"].(string))
	}
	uiJob := makeUIAIJob(job)
	page := &uiAIJobPage{
		Header:      hdr,
		Job:         uiJob,
		Jobs:        []*uiAIJob{uiJob},
		CrashReport: crashReport,
		Trajectory:  makeUIAITrajectory(trajectory),
		History:     makeUIJobReviewHistory(history),
	}
	return serveTemplate(w, "ai_job.html", page)
}

func makeUIAIJob(job *aidb.Job) *uiAIJob {
	var results []*uiAIResult
	if m, ok := job.Results.Value.(map[string]any); ok && job.Results.Valid {
		for name, value := range m {
			_, isBool := value.(bool)
			results = append(results, &uiAIResult{
				Name:   name,
				IsBool: isBool,
				Value:  value,
			})
		}
	}
	slices.SortFunc(results, func(a, b *uiAIResult) int {
		// Pop up bool flags to the top.
		if a.IsBool != b.IsBool {
			if a.IsBool {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})

	correct := aiCorrectnessIncorrect
	if !job.Started.Valid {
		correct = aiCorrectnessPending
	} else if !job.Finished.Valid {
		correct = aiCorrectnessRunning
	} else if job.Error != "" {
		correct = aiCorrectnessErrored
	} else if !job.Correct.Valid {
		correct = aiCorrectnessUnset
	} else if job.Correct.Bool {
		correct = aiCorrectnessCorrect
	}
	return &uiAIJob{
		ID:               job.ID,
		Link:             fmt.Sprintf("/ai_job?id=%v", job.ID),
		Workflow:         job.Workflow,
		Description:      job.Description,
		DescriptionLink:  job.Link,
		Created:          job.Created,
		Started:          nullTime(job.Started),
		Finished:         nullTime(job.Finished),
		CodeRevision:     job.CodeRevision,
		CodeRevisionLink: vcs.LogLink(vcs.SyzkallerRepo, job.CodeRevision),
		Error:            job.Error,
		Correct:          correct,
		Results:          results,
	}
}

func makeUIAITrajectory(trajetory []*aidb.TrajectorySpan) []*uiAITrajectorySpan {
	var res []*uiAITrajectorySpan
	for _, span := range trajetory {
		var duration time.Duration
		if span.Finished.Valid {
			duration = span.Finished.Time.Sub(span.Started)
		}
		res = append(res, &uiAITrajectorySpan{
			Started:              span.Started,
			Seq:                  span.Seq,
			Nesting:              span.Nesting,
			Type:                 span.Type,
			Name:                 span.Name,
			Model:                span.Model,
			Duration:             duration,
			Error:                nullString(span.Error),
			Args:                 nullJSON(span.Args),
			Results:              nullJSON(span.Results),
			Instruction:          nullString(span.Instruction),
			Prompt:               nullString(span.Prompt),
			Reply:                nullString(span.Reply),
			Thoughts:             nullString(span.Thoughts),
			InputTokens:          nullInt64(span.InputTokens),
			OutputTokens:         nullInt64(span.OutputTokens),
			OutputThoughtsTokens: nullInt64(span.OutputThoughtsTokens),
		})
	}
	return res
}

func makeUIJobReviewHistory(history []*aidb.Journal) []*uiJobReviewHistory {
	var res []*uiJobReviewHistory
	for _, h := range history {
		val := aiCorrectnessUnset
		if h.Details.Valid {
			if details, err := parseJSON[aidb.JobReviewDetails](h.Details); err == nil {
				if details.Correct {
					val = aiCorrectnessCorrect
				} else {
					val = aiCorrectnessIncorrect
				}
			}
		}
		res = append(res, &uiJobReviewHistory{
			Date:    h.Date,
			User:    h.User,
			Correct: val,
		})
	}
	return res
}

func apiAIJobPoll(ctx context.Context, req *dashapi.AIJobPollReq) (any, error) {
	if len(req.Workflows) == 0 || req.CodeRevision == "" {
		return nil, fmt.Errorf("invalid request")
	}
	for _, flow := range req.Workflows {
		if flow.Type == "" || flow.Name == "" {
			return nil, fmt.Errorf("invalid request")
		}
	}
	if err := aidb.UpdateWorkflows(ctx, req.Workflows); err != nil {
		return nil, fmt.Errorf("failed UpdateWorkflows: %w", err)
	}
	job, err := aidb.StartJob(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed StartJob: %w", err)
	}
	if job == nil {
		if created, err := autoCreateAIJobs(ctx); err != nil || !created {
			return &dashapi.AIJobPollResp{}, err
		}
		job, err = aidb.StartJob(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed StartJob: %w", err)
		}
		if job == nil {
			return &dashapi.AIJobPollResp{}, nil
		}
	}
	args := make(map[string]any)
	var textErr error
	assignText := func(anyID any, tag, name string) {
		id, err := anyID.(json.Number).Int64()
		if err != nil {
			textErr = err
		}
		if id == 0 {
			return
		}
		data, _, err := getText(ctx, tag, id)
		if err != nil {
			textErr = err
		}
		args[name] = string(data)
	}
	if !job.Args.Valid {
		job.Args.Value = map[string]any{}
	}
	for name, val := range job.Args.Value.(map[string]any) {
		switch name {
		case "ReproSyzID":
			assignText(val, textReproSyz, "ReproSyz")
		case "ReproCID":
			assignText(val, textReproC, "ReproC")
		case "CrashReportID":
			assignText(val, textCrashReport, "CrashReport")
		case "KernelConfigID":
			assignText(val, textKernelConfig, "KernelConfig")
		default:
			args[name] = val
		}
	}
	if textErr != nil {
		return nil, textErr
	}
	return &dashapi.AIJobPollResp{
		ID:       job.ID,
		Workflow: job.Workflow,
		Args:     args,
	}, nil
}

func apiAIJobDone(ctx context.Context, req *dashapi.AIJobDoneReq) (any, error) {
	job, err := aidb.LoadJob(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	if job.Finished.Valid {
		return nil, fmt.Errorf("the job %v is already finished", req.ID)
	}
	job.Finished = spanner.NullTime{Time: timeNow(ctx), Valid: true}
	job.Error = req.Error[:min(len(req.Error), 4<<10)]
	if len(req.Results) != 0 {
		job.Results = spanner.NullJSON{Value: req.Results, Valid: true}
	}
	if err = aiJobUpdate(ctx, job); err != nil {
		return nil, err
	}
	if job.Type == ai.WorkflowPatching && job.BugID.Valid && job.Finished.Valid && job.Error == "" {
		if err := createGerritChange(ctx, job); err != nil {
			log.Errorf(ctx, "failed to create gerrit change for job %v: %v", job.ID, err)
		}
	}
	return nil, nil
}

func aiJobUpdate(ctx context.Context, job *aidb.Job) error {
	if err := aidb.UpdateJob(ctx, job); err != nil {
		return err
	}
	if !job.BugID.Valid || !job.Finished.Valid || job.Error != "" {
		return nil
	}
	bug, err := loadBug(ctx, job.BugID.StringVal)
	if err != nil {
		return err
	}
	labelType, labelValue, labelAdd, err := aiBugLabel(job)
	if err != nil || labelType == EmptyLabel {
		return err
	}
	label := BugLabel{
		Label: labelType,
		Value: labelValue,
		Link:  job.ID,
	}
	labelSet := makeLabelSet(ctx, bug)
	return updateSingleBug(ctx, bug.key(ctx), func(bug *Bug) error {
		if bug.HasUserLabel(labelType) {
			return nil
		}
		if labelAdd {
			return bug.SetLabels(labelSet, []BugLabel{label})
		}
		bug.UnsetLabels(labelType)
		return nil
	})
}

func aiBugLabel(job *aidb.Job) (typ BugLabelType, value string, set bool, err0 error) {
	switch job.Type {
	case ai.WorkflowAssessmentKCSAN:
		// For now we require a manual correctness check,
		// later we may apply some labels w/o the manual check.
		if !job.Correct.Valid {
			return
		}
		if !job.Correct.Bool {
			return RaceLabel, "", false, nil
		}
		res, err := castJobResults[ai.AssessmentKCSANOutputs](job)
		if err != nil {
			err0 = err
			return
		}
		if !res.Confident {
			return
		}
		if res.Benign {
			return RaceLabel, BenignRace, true, nil
		}
		return RaceLabel, HarmfulRace, true, nil
	}
	return
}

func castJobResults[T any](job *aidb.Job) (T, error) {
	if !job.Results.Valid {
		var res T
		return res, fmt.Errorf("finished job %v %v does not have results", job.Type, job.ID)
	}
	return parseJSON[T](job.Results)
}

func parseJSON[T any](val spanner.NullJSON) (T, error) {
	var res T
	// Database may store older versions of the output structs.
	// It's not possible to automatically handle all possible changes to the structs.
	// For now we just parse in some way. Later when we start changing output structs,
	// we may need to reconsider and use more careful parsing.
	data, err := json.Marshal(val.Value)
	if err != nil {
		return res, err
	}
	return osutil.ParseJSON[T](data)
}

func apiAITrajectoryLog(ctx context.Context, req *dashapi.AITrajectoryReq) (any, error) {
	err := aidb.StoreTrajectorySpan(ctx, req.JobID, req.Span)
	return nil, err
}

type uiWorkflow struct {
	Name             string
	CustomBaseCommit bool
}

// aiBugWorkflows returns active workflows that are applicable for the bug.
func aiBugWorkflows(ctx context.Context, bug *Bug) ([]*uiWorkflow, error) {
	workflows, err := aidb.LoadWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	applicable := workflowsForBug(bug, true)
	var result []*uiWorkflow
	for _, flow := range workflows {
		// Also check that the workflow is active on some syz-agent's.
		if applicable[flow.Type] && timeSince(ctx, flow.LastActive) < 25*time.Hour {
			result = append(result, &uiWorkflow{
				Name:             flow.Name,
				CustomBaseCommit: flow.Type == ai.WorkflowPatching,
			})
		}
	}
	slices.SortFunc(result, func(a, b *uiWorkflow) int {
		return strings.Compare(a.Name, b.Name)
	})
	return result, nil
}

// aiBugWorkflows returns active workflows that are applicable for the bug.

func aiBugJobCreate(ctx context.Context, workflow string, bug *Bug, extraArgs map[string]any) error {
	workflows, err := aidb.LoadWorkflows(ctx)
	if err != nil {
		return err
	}
	var typ ai.WorkflowType
	for _, flow := range workflows {
		if flow.Name == workflow {
			typ = flow.Type
			break
		}
	}
	if typ == "" {
		return fmt.Errorf("workflow %v does not exist", workflow)
	}
	return bugJobCreate(ctx, workflow, typ, bug, extraArgs)
}

func bugJobCreate(ctx context.Context, workflow string, typ ai.WorkflowType, bug *Bug, extraArgs map[string]any) error {
	crash, crashKey, err := findCrashForBug(ctx, bug)
	if err != nil {
		return err
	}
	build, err := loadBuild(ctx, bug.Namespace, crash.BuildID)
	if err != nil {
		return err
	}
	tx := func(ctx context.Context) error {
		return addCrashReference(ctx, crashKey.IntID(), bug.key(ctx),
			CrashReference{CrashReferenceAIJob, "", timeNow(ctx)})
	}
	if err := runInTransaction(ctx, tx, &db.TransactionOptions{
		XG: true,
	}); err != nil {
		return fmt.Errorf("addCrashReference failed: %w", err)
	}
	args := map[string]any{
		"BugTitle":        bug.Title,
		"ReproOpts":       string(crash.ReproOpts),
		"ReproSyzID":      crash.ReproSyz,
		"ReproCID":        crash.ReproC,
		"CrashReportID":   crash.Report,
		"KernelRepo":      build.KernelRepo,
		"KernelCommit":    build.KernelCommit,
		"KernelConfigID":  build.KernelConfig,
		"SyzkallerCommit": build.SyzkallerCommit,
	}
	for k, v := range extraArgs {
		args[k] = v
	}
	return aidb.CreateJob(ctx, &aidb.Job{
		Type:        typ,
		Workflow:    workflow,
		Namespace:   bug.Namespace,
		BugID:       spanner.NullString{StringVal: bug.keyHash(ctx), Valid: true},
		Description: bug.displayTitle(),
		Link:        fmt.Sprintf("/bug?id=%v", bug.keyHash(ctx)),
		Args:        spanner.NullJSON{Valid: true, Value: args},
	})
}

// autoCreateAIJobs incrementally creates AI jobs for existing bugs, returns if any new jobs were created.
//
// The idea is as follows. We have a predicate (workflowsForBug) which says what workflows need to be
// created for a bug. Each bug has AIJobCheck integer field, which holds version of the predicate
// that was applied to the bug. The current/latest version is stored in currentAIJobCheckSeq.
// We fetch some number of bugs with AIJobCheck<currentAIJobCheckSeq and check if we need to create
// new jobs for them. The check is done by executing workflowsForBug for the bug, loading existing
// pending/finished jobs for the bug, and finding any jobs returned by workflowsForBug that don't exist yet.
//
// If the predicate workflowsForBug is updated, currentAIJobCheckSeq needs to be incremented as well.
// This will trigger immediate incremental re-checking of all existing bugs to create new jobs.
// AIJobCheck can always be reset to 0 for a particular bug to trigger re-checking for this single bug.
// This may be useful when, for example, a bug gets the first reproducer, and some jobs are created
// only for bugs with reproducers. AIJobCheck may also be reset to 0 when a job finishes with an error
// to trigger creation of a new job of the same type.
//
// TODO(dvyukov): figure out how to handle jobs with errors and unfinished jobs.
// Do we want to automatically restart them or not?
func autoCreateAIJobs(ctx context.Context) (bool, error) {
	for ns, cfg := range getConfig(ctx).Namespaces {
		if !cfg.AI {
			continue
		}
		var bugs []*Bug
		keys, err := db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("AIJobCheck<", currentAIJobCheckSeq).
			Limit(100).
			GetAll(ctx, &bugs)
		if err != nil {
			return false, fmt.Errorf("failed to fetch bugs: %w", err)
		}
		if len(bugs) == 0 {
			continue
		}
		created := false
		var updateKeys []*db.Key
		for i, bug := range bugs {
			updateKeys = append(updateKeys, keys[i])
			created, err = autoCreateAIJob(ctx, bug, keys[i])
			if err != nil {
				return false, err
			}
			if created {
				break
			}
		}
		if err := updateBatch(ctx, updateKeys, func(_ *db.Key, bug *Bug) {
			bug.AIJobCheck = currentAIJobCheckSeq
		}); err != nil {
			return false, err
		}
		if created {
			return true, nil
		}
	}
	return false, nil
}

func autoCreateAIJob(ctx context.Context, bug *Bug, bugKey *db.Key) (bool, error) {
	workflows := workflowsForBug(bug, false)
	if len(workflows) == 0 {
		return false, nil
	}
	jobs, err := aidb.LoadBugJobs(ctx, bugKey.StringID())
	if err != nil {
		return false, err
	}
	for _, job := range jobs {
		// Already have a pending unfinished job.
		if !job.Finished.Valid ||
			// Have finished successful job.
			job.Finished.Valid && job.Error == "" {
			delete(workflows, ai.WorkflowType(job.Workflow))
		}
	}
	for workflow := range workflows {
		if err := bugJobCreate(ctx, string(workflow), workflow, bug, nil); err != nil {
			return false, err
		}
	}
	return len(workflows) != 0, nil
}

const currentAIJobCheckSeq = 1

func workflowsForBug(bug *Bug, manual bool) map[ai.WorkflowType]bool {
	workflows := make(map[ai.WorkflowType]bool)
	typ := crash.TitleToType(bug.Title)
	// UAF bugs stuck in last but one reporting.
	if typ.IsUAF() && len(bug.Reporting) > 1 &&
		bug.Reporting[len(bug.Reporting)-1].Reported.IsZero() &&
		!bug.Reporting[len(bug.Reporting)-2].Reported.IsZero() {
		workflows[ai.WorkflowModeration] = true
	}
	if typ == crash.KCSANDataRace {
		workflows[ai.WorkflowAssessmentKCSAN] = true
	}
	if manual {
		// Types we don't create automatically yet, but can be created manually.
		if typ.IsUAF() {
			workflows[ai.WorkflowModeration] = true
		}
		if bug.HeadReproLevel > dashapi.ReproLevelNone {
			workflows[ai.WorkflowPatching] = true
		}
	}
	return workflows
}

func createGerritChange(ctx context.Context, job *aidb.Job) error {
	res, err := castJobResults[ai.PatchingOutputs](job)
	if err != nil {
		return err
	}
	// TODO: add Reported-by tag for the syzbot bug, or a link to lore report.
	// Add Fixes tag if we have cause bisection, but we need to verify it with LLMs
	// somehow since lots of them are wrong.
	// Probably shouldn't cc stable for all patches (e.g. removing a WARNING)?
	res.Recipients = append(res.Recipients, ai.Recipient{Email: "stable@vger.kernel.org"})
	// TODO: move these constants to config.
	const author = "syzbot@kernel.org"
	description := email.FormatPatchDescription(res.PatchDescription, []string{author}, res.Recipients)
	changeID, link, err := gerrit.CreateChange(ctx, res.KernelRepo, res.KernelBranch,
		res.KernelCommit, description, res.PatchDiff)
	if err != nil {
		return err
	}
	log.Infof(ctx, "created gerrit change %v for job %v: %v", changeID, job.ID, link)
	return nil
}

const (
	aiCorrectnessCorrect   = "✅"
	aiCorrectnessIncorrect = "❌"
	aiCorrectnessUnset     = "❓"
	aiCorrectnessPending   = "⏳"
	aiCorrectnessRunning   = "🏃"
	aiCorrectnessErrored   = "💥"
)

func nullTime(v spanner.NullTime) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return v.Time
}

func nullString(v spanner.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.StringVal
}

func nullJSON(v spanner.NullJSON) string {
	if !v.Valid {
		return ""
	}
	return fmt.Sprint(v.Value)
}

func nullInt64(v spanner.NullInt64) int {
	if !v.Valid {
		return 0
	}
	return int(v.Int64)
}
