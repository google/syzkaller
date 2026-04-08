// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	aflowhtml "github.com/google/syzkaller/pkg/aflow/trajectory/html"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/gerrit"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/vcs"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

type uiAIJobsPage struct {
	Header          *uiHeader
	Jobs            []*uiAIJob
	Workflows       []string
	CurrentWorkflow string
	ShowAborted     bool
}

type uiAIJobPage struct {
	Header *uiHeader
	Job    *uiAIJob
	// The slice contains the same single Job, just for HTML templates convenience.
	Jobs           []*uiAIJob
	CrashReport    template.HTML
	TrajectoryHTML template.HTML
	History        []*uiJobReviewHistory
	CurrentStage   string
	NextStage      string
	Reportings     []*uiJobReporting
}

type uiJobReporting struct {
	Reporting *aidb.JobReporting
	Comments  []*aidb.JobComment
	Link      string
}

type uiJobReviewHistory struct {
	Date    time.Time
	User    string
	Correct string
	Source  string
	Stage   string
}

type uiAIJob struct {
	ID               string
	Link             string
	Workflow         string
	Description      string
	DescriptionLink  string
	AgentName        string
	Created          time.Time
	Started          time.Time
	Finished         time.Time
	CodeRevision     string
	CodeRevisionLink string
	Error            string
	Correct          string
	CorrectTitle     string
	Results          []*uiAIResult
}

type uiAIResult struct {
	Name   string
	IsBool bool
	Value  any
}

func handleAIJobsPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	currentWorkflow := r.FormValue("workflow")
	showAborted := r.FormValue("show_aborted") != ""

	jobs, err := aidb.LoadNamespaceJobs(ctx, hdr.Namespace, &aidb.JobFilter{
		Workflow:    currentWorkflow,
		ShowAborted: showAborted,
	})
	if err != nil {
		return err
	}
	jobs, err = filterJobsAccess(ctx, r, jobs)
	if err != nil {
		return err
	}

	var uiJobs []*uiAIJob
	for _, job := range jobs {
		uiJobs = append(uiJobs, makeUIAIJob(job))
	}
	workflows, err := aidb.LoadActiveWorkflows(ctx)
	if err != nil {
		return err
	}
	workflowNames := []string{aidb.WorkflowAll, aidb.WorkflowNeedsModeration}
	for _, w := range workflows {
		workflowNames = append(workflowNames, w.Name)
	}
	slices.Sort(workflowNames)
	if currentWorkflow == "" {
		currentWorkflow = aidb.WorkflowAll
	}
	page := &uiAIJobsPage{
		Header:          hdr,
		Jobs:            uiJobs,
		Workflows:       workflowNames,
		CurrentWorkflow: currentWorkflow,
		ShowAborted:     showAborted,
	}
	return serveTemplate(w, "ai_jobs.html", page)
}

func getJobStageInfo(ctx context.Context, job *aidb.Job) (*aidb.JobReporting, *AIPatchStageConfig, error) {
	reportings, err := aidb.LoadJobReportings(ctx, job.ID)
	if err != nil {
		return nil, nil, err
	}
	var latest *aidb.JobReporting
	currentStage := ""
	nsCfg := getNsConfig(ctx, job.Namespace)

	if len(reportings) > 0 && nsCfg.AI != nil && len(nsCfg.AI.Stages) > 0 {
		stageMap := make(map[string]*aidb.JobReporting)
		for _, r := range reportings {
			stageMap[r.Stage] = r
		}
		for i := len(nsCfg.AI.Stages) - 1; i >= 0; i-- {
			stageName := nsCfg.AI.Stages[i].Name
			if r, ok := stageMap[stageName]; ok {
				latest = r
				currentStage = stageName
				break
			}
		}
	}

	var nextStageCfg *AIPatchStageConfig
	if nsCfg.AI != nil && len(nsCfg.AI.Stages) > 0 {
		nextStageCfg, _ = determineNextStage(ctx, nsCfg.AI, job, currentStage)
	}
	return latest, nextStageCfg, nil
}

func handleAIJobPagePost(ctx context.Context, job *aidb.Job, r *http.Request, hdr *uiHeader) error {
	correct := r.FormValue("correct")
	if correct == "" {
		return nil
	}
	if !hdr.AIActions {
		return ErrAccess
	}
	if !job.Finished.Valid || job.Error != "" {
		return fmt.Errorf("job is in wrong state to set correct status")
	}
	user := currentUser(ctx)
	if user == nil {
		return ErrAccess
	}
	userEmail := user.Email

	switch correct {
	case aiCorrectnessCorrect:
		currentReporting, _, err := getJobStageInfo(ctx, job)
		if err != nil {
			return err
		}
		err = processUpstreamSubcommand(ctx, job, currentReporting, &dashapi.SendExternalCommandReq{
			Source: SourceWebUI,
			Author: userEmail,
		})
		if err != nil {
			return err
		}
	case aiCorrectnessIncorrect:
		err := aidb.RejectReportCommand(ctx, aidb.RejectReportArgs{
			Job:           job,
			CommandSource: SourceWebUI,
			CommandExtID:  "",
			User:          userEmail,
			Reason:        "",
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown correct value %q", ErrClientBadRequest, correct)
	}
	job, err := aidb.LoadJob(ctx, job.ID)
	if err != nil {
		return err
	}
	if err := aiJobApplyLabels(ctx, job); err != nil {
		return err
	}
	return nil
}

func handleAIJobPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	job, err := aidb.LoadJob(ctx, r.FormValue("id"))
	if err != nil {
		if errors.Is(err, aidb.ErrNotFound) {
			return fmt.Errorf("failed to query the job: %w", ErrClientNotFound)
		}
		return err
	}
	if jobs, err := filterJobsAccess(ctx, r, []*aidb.Job{job}); err != nil {
		return err
	} else if len(jobs) == 0 {
		return ErrAccess
	}
	hdr, err := commonHeader(ctx, r, w, job.Namespace)
	if err != nil {
		return err
	}

	if err := handleAIJobPagePost(ctx, job, r, hdr); err != nil {
		return err
	}

	trajectory, err := aidb.LoadTrajectory(ctx, job.ID)
	if err != nil {
		return err
	}
	uiHistory, err := LoadUIJobReviewHistory(ctx, job.ID)
	if err != nil {
		return err
	}

	currentReporting, nextStageCfg, err := getJobStageInfo(ctx, job)
	if err != nil {
		return err
	}

	currentStageStr := ""
	if currentReporting != nil {
		currentStageStr = currentReporting.Stage
	}
	nextStageStr := ""
	if nextStageCfg != nil {
		nextStageStr = nextStageCfg.Name
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

	uiTrajectory := makeUIAITrajectory(trajectory)
	trajectoryHTML, err := aflowhtml.RenderTrajectory(uiTrajectory)
	if err != nil {
		return err
	}
	uiReportings, err := loadJobReportingsWithComments(ctx, job.ID)
	if err != nil {
		return err
	}
	page := &uiAIJobPage{
		Header:         hdr,
		Job:            uiJob,
		Jobs:           []*uiAIJob{uiJob},
		CrashReport:    crashReport,
		History:        uiHistory,
		TrajectoryHTML: trajectoryHTML,
		CurrentStage:   currentStageStr,
		NextStage:      nextStageStr,
		Reportings:     uiReportings,
	}
	return serveTemplate(w, "ai_job.html", page)
}

func loadJobReportingsWithComments(ctx context.Context, jobID string) ([]*uiJobReporting, error) {
	allReportings, err := aidb.LoadJobReportings(ctx, jobID)
	if err != nil {
		return nil, err
	}
	allComments, err := aidb.LoadJobComments(ctx, jobID)
	if err != nil {
		return nil, err
	}
	var uris []string
	for _, c := range allComments {
		uris = append(uris, c.BodyURI)
	}
	resolved, err := loadContent(ctx, uris)
	if err != nil {
		return nil, err
	}
	for _, c := range allComments {
		if text, ok := resolved[c.BodyURI]; ok {
			c.BodyURI = text
		}
	}

	var uiReportings []*uiJobReporting
	for _, r := range allReportings {
		var comments []*aidb.JobComment
		for _, c := range allComments {
			if c.ReportingID == r.ID {
				comments = append(comments, c)
			}
		}
		link := ""
		if r.Source == string(dashapi.AIJobSourceLore) && r.ExtID.Valid {
			link = lore.LinkToMessage(r.ExtID.StringVal)
		}
		uiReportings = append(uiReportings, &uiJobReporting{
			Reporting: r,
			Comments:  comments,
			Link:      link,
		})
	}
	return uiReportings, nil
}

func loadContent(ctx context.Context, uris []string) (map[string]string, error) {
	res := make(map[string]string)
	for _, uri := range uris {
		if !strings.HasPrefix(uri, "text://") {
			return nil, fmt.Errorf("unrecognized content prefix: %q", uri)
		}
		idStr := strings.TrimPrefix(uri, "text://")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid content id %q: %w", idStr, err)
		}
		if id != 0 {
			body, _, err := getText(ctx, textJobComment, id)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch content for %v: %w", id, err)
			}
			res[uri] = string(body)
		}
	}
	return res, nil
}

func filterJobsAccess(ctx context.Context, r *http.Request, jobs []*aidb.Job) ([]*aidb.Job, error) {
	if accessLevel(ctx, r) == AccessAdmin {
		return jobs, nil
	}
	bugKeyIDs := map[string]bool{}
	bugAccess := map[string]AccessLevel{}
	// Datastore has this limit for number of entities selected with GetMulti.
	// Pretend that older bugs are AccessAdmin for simplicity until we have proper pagination/filtering.
	const maxBugs = 1000
	for _, job := range jobs {
		if !job.BugID.Valid {
			// Jobs not associated with bugs are considered public.
		} else if len(bugKeyIDs) < maxBugs {
			bugKeyIDs[job.BugID.StringVal] = true
		} else {
			bugAccess[job.BugID.StringVal] = AccessAdmin
		}
	}
	var bugKeys []*db.Key
	for id := range bugKeyIDs {
		bugKeys = append(bugKeys, db.NewKey(ctx, "Bug", id, 0, nil))
	}
	bugs := make([]*Bug, len(bugKeys))
	if err := db.GetMulti(ctx, bugKeys, bugs); err != nil {
		return nil, err
	}
	accessLevel := accessLevel(ctx, r)
	for _, bug := range bugs {
		bugAccess[bug.keyHash(ctx)] = bug.sanitizeAccess(ctx, accessLevel)
	}
	jobs = slices.DeleteFunc(jobs, func(job *aidb.Job) bool {
		return job.BugID.Valid && accessLevel < bugAccess[job.BugID.StringVal]
	})
	return jobs, nil
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
	title := "Incorrect"
	if !job.Started.Valid {
		correct = aiCorrectnessPending
		title = "Job is pending"
	} else if !job.Finished.Valid {
		correct = aiCorrectnessRunning
		title = "Job is running"
	} else if job.Error != "" {
		correct = aiCorrectnessErrored
		title = "Job failed with an error"
	} else if !job.Correct.Valid {
		correct = aiCorrectnessUnset
		title = "Not yet reviewed"
	} else if job.Correct.Bool {
		correct = aiCorrectnessCorrect
		title = "Correct"
	}
	return &uiAIJob{
		ID:               job.ID,
		Link:             fmt.Sprintf("/ai_job?id=%v", job.ID),
		Workflow:         job.Workflow,
		Description:      job.Description,
		DescriptionLink:  job.Link,
		AgentName:        nullString(job.AgentName),
		Created:          job.Created,
		Started:          nullTime(job.Started),
		Finished:         nullTime(job.Finished),
		CodeRevision:     job.CodeRevision,
		CodeRevisionLink: vcs.LogLink(vcs.SyzkallerRepo, job.CodeRevision),
		Error:            job.Error,
		Correct:          correct,
		CorrectTitle:     title,
		Results:          results,
	}
}

func makeUIAITrajectory(trajetory []*aidb.TrajectorySpan) []*aflowhtml.UIAITrajectorySpan {
	var res []*aflowhtml.UIAITrajectorySpan
	for _, span := range trajetory {
		var duration time.Duration
		if span.Finished.Valid {
			duration = span.Finished.Time.Sub(span.Started)
		}
		res = append(res, &aflowhtml.UIAITrajectorySpan{
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

func makeUIJobReviewHistory(history []*aidb.Journal, reportings []*aidb.JobReporting) []*uiJobReviewHistory {
	stageMap := make(map[string]string)
	for _, r := range reportings {
		stageMap[r.ID] = r.Stage
	}
	var res []*uiJobReviewHistory
	for _, h := range history {
		val := aiCorrectnessUnset
		switch h.Action {
		case aidb.ActionApprove:
			val = aiCorrectnessCorrect
		case aidb.ActionReject:
			val = aiCorrectnessIncorrect
		case aidb.ActionJobReview:
			// ActionJobReview is obsolete, we only keep it because there are entities in the DB.
			if h.Details.Valid {
				if details, err := parseJSON[aidb.JobReviewDetails](h.Details); err == nil {
					if details.Correct {
						val = aiCorrectnessCorrect
					} else {
						val = aiCorrectnessIncorrect
					}
				}
			}
		default:
			val = "?"
		}
		res = append(res, &uiJobReviewHistory{
			Date:    h.Date,
			User:    h.User,
			Correct: val,
			Source:  h.Source.StringVal,
			Stage:   stageMap[h.ReportingID.StringVal],
		})
	}
	return res
}

func LoadUIJobReviewHistory(ctx context.Context, jobID string) ([]*uiJobReviewHistory, error) {
	history, err := aidb.LoadJobJournal(ctx, jobID)
	if err != nil {
		return nil, err
	}
	reportings, err := aidb.LoadJobReportings(ctx, jobID)
	if err != nil {
		return nil, err
	}
	return makeUIJobReviewHistory(history, reportings), nil
}

func apiAIJobPoll(ctx context.Context, req *dashapi.AIJobPollReq) (any, error) {
	if len(req.Workflows) == 0 || req.CodeRevision == "" || req.AgentName == "" {
		return nil, fmt.Errorf("invalid request")
	}
	client := apiContext(ctx).client
	if err := aidb.AgentIsAlive(ctx, req.AgentName); err != nil {
		log.Errorf(ctx, "failed to update agent %q: %v", req.AgentName, err)
	}
	for _, flow := range req.Workflows {
		if flow.Type == "" || flow.Name == "" {
			return nil, fmt.Errorf("invalid request")
		}
		if err := aiCheckClientWorkflow(ctx, flow.Name); err != nil {
			return nil, err
		}
	}
	if err := aidb.UpdateWorkflows(ctx, req.AgentName, req.Workflows); err != nil {
		return nil, fmt.Errorf("failed UpdateWorkflows: %w", err)
	}
	job, err := pollAIJob(ctx, req, client)
	if err != nil {
		return nil, err
	}
	if job == nil {
		return &dashapi.AIJobPollResp{}, nil
	}
	if !job.Args.Valid {
		job.Args.Value = map[string]any{}
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
	textFields := map[string]struct{ tag, name string }{
		"ReproSyzID":     {textReproSyz, "ReproSyz"},
		"ReproCID":       {textReproC, "ReproC"},
		"CrashReportID":  {textCrashReport, "CrashReport"},
		"CrashLogID":     {textCrashLog, "CrashLog"},
		"KernelConfigID": {textKernelConfig, "KernelConfig"},
	}
	for name, val := range job.Args.Value.(map[string]any) {
		if text, ok := textFields[name]; ok {
			assignText(val, text.tag, text.name)
		} else {
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

func pollAIJob(ctx context.Context, req *dashapi.AIJobPollReq, client APIClient) (*aidb.Job, error) {
	job, err := aidb.StartJob(ctx, req, client.AIJobNamespaces)
	if err != nil {
		return nil, fmt.Errorf("failed StartJob: %w", err)
	}
	if job != nil {
		return job, nil
	}
	job, err = aidb.NextStaleJob(ctx, req, client.AIJobNamespaces)
	if err != nil {
		log.Errorf(ctx, "NextStaleJob failed: %v", err)
	}
	if job != nil {
		return job, nil
	}
	if created, err := autoCreateAIJobs(ctx, req.Workflows, client); err != nil || !created {
		return nil, err
	}
	job, err = aidb.StartJob(ctx, req, client.AIJobNamespaces)
	if err != nil {
		return nil, fmt.Errorf("failed StartJob after autoCreate: %w", err)
	}
	return job, nil
}

func checkAiJobAccess(ctx context.Context, jobID string) (*aidb.Job, error) {
	job, err := aidb.LoadJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	client := apiContext(ctx).client
	if !client.AllowedNamespace(job.Namespace) {
		return nil, fmt.Errorf("client not authorized for namespace %q", job.Namespace)
	}
	return job, nil
}

func apiAIJobDone(ctx context.Context, req *dashapi.AIJobDoneReq) (any, error) {
	job, err := checkAiJobAccess(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	if err := aiCheckClientWorkflow(ctx, job.Workflow); err != nil {
		return nil, err
	}
	if job.Finished.Valid {
		return nil, fmt.Errorf("the job %v is already finished", req.ID)
	}
	finished := timeNow(ctx)
	errStr := req.Error[:min(len(req.Error), 4<<10)]
	job, err = aidb.SetJobDone(ctx, req.ID, finished, errStr, req.Results)
	if err != nil {
		return nil, err
	}
	if err = aiJobApplyLabels(ctx, job); err != nil {
		return nil, err
	}
	if !shouldReportJob(job) {
		return nil, nil
	}
	nsCfg := getNsConfig(ctx, job.Namespace)
	if nsCfg.AI == nil {
		return nil, nil
	}
	if nsCfg.AI.UploadPatchesToGerrit {
		if err := createGerritChange(ctx, job); err != nil {
			log.Errorf(ctx, "failed to create gerrit change for job %v: %v", job.ID, err)
		}
	}
	stageCfg, err := determineNextStage(ctx, nsCfg.AI, job, "")
	if err != nil {
		log.Errorf(ctx, "failed to determine next stage for job %v: %v", job.ID, err)
		return nil, nil
	}
	if stageCfg == nil {
		return nil, nil
	}
	reporting := &aidb.JobReporting{
		Stage:  stageCfg.Name,
		Source: stageCfg.ServingIntegration,
	}
	if err := aidb.AddJobReportingTransactional(ctx, job, reporting, stageCfg.NoParallelReports); err != nil {
		log.Errorf(ctx, "failed to add initial job reporting for job %v: %v", job.ID, err)
	}
	return nil, nil
}

func shouldReportJob(job *aidb.Job) bool {
	return job.Type == ai.WorkflowPatching &&
		job.BugID.Valid &&
		job.Finished.Valid &&
		job.Error == ""
}

func aiCheckClientWorkflow(ctx context.Context, workflow string) error {
	suffix := apiContext(ctx).client.AIWorkflowSuffix
	if !strings.HasSuffix(workflow, suffix) {
		return fmt.Errorf("the client is not allowed to execute AI jobs without %q suffix", suffix)
	}
	return nil
}

func aiJobApplyLabels(ctx context.Context, job *aidb.Job) error {
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
	case ai.WorkflowModeration:
		// For now we require a manual correctness check.
		if !job.Correct.Valid {
			return
		}
		if !job.Correct.Bool {
			return ActionableLabel, "", false, nil
		}
		res, err := castJobResults[ai.ModerationOutputs](job)
		if err != nil {
			err0 = err
			return
		}
		if !res.Confident {
			return
		}
		return ActionableLabel, "", res.Actionable, nil
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
	_, err := checkAiJobAccess(ctx, req.JobID)
	if err != nil {
		return nil, err
	}
	if req.AgentName != "" {
		if err := aidb.AgentIsAlive(ctx, req.AgentName); err != nil {
			log.Errorf(ctx, "failed to update agent %q: %v", req.AgentName, err)
		}
	}
	err = aidb.StoreTrajectorySpan(ctx, req.JobID, req.Span)
	return nil, err
}

type uiWorkflow struct {
	Name             string
	CustomBaseCommit bool
}

// aiBugWorkflows returns active workflows that are applicable for the bug.
func aiBugWorkflows(ctx context.Context, bug *Bug) ([]*uiWorkflow, error) {
	workflows, err := aidb.LoadActiveWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	applicable := workflowsForBug(ctx, bug, true)
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

func aiBugJobCreate(ctx context.Context, workflow string, bug *Bug, extraArgs map[string]any) (string, error) {
	workflows, err := aidb.LoadActiveWorkflows(ctx)
	if err != nil {
		return "", err
	}
	var typ ai.WorkflowType
	for _, flow := range workflows {
		if flow.Name == workflow {
			typ = flow.Type
			break
		}
	}
	if typ == "" {
		return "", fmt.Errorf("workflow %v does not exist", workflow)
	}
	return bugJobCreate(ctx, workflow, typ, bug, extraArgs)
}

func bugJobCreate(ctx context.Context, workflow string, typ ai.WorkflowType, bug *Bug, extraArgs map[string]any) (
	string, error) {
	crash, crashKey, err := findCrashForBug(ctx, bug)
	if err != nil {
		return "", err
	}
	build, err := loadBuild(ctx, bug.Namespace, crash.BuildID)
	if err != nil {
		return "", err
	}
	tx := func(ctx context.Context) error {
		return addCrashReference(ctx, crashKey.IntID(), bug.key(ctx),
			CrashReference{CrashReferenceAIJob, "", timeNow(ctx)})
	}
	if err := runInTransaction(ctx, tx, &db.TransactionOptions{
		XG: true,
	}); err != nil {
		return "", fmt.Errorf("addCrashReference failed: %w", err)
	}
	args := map[string]any{
		"BugTitle":        bug.Title,
		"ReproOpts":       string(crash.ReproOpts),
		"ReproSyzID":      crash.ReproSyz,
		"ReproCID":        crash.ReproC,
		"CrashReportID":   crash.Report,
		"CrashLogID":      crash.Log,
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

// autoCreateAIJobs attempts to auto-assign AI jobs for the given requested workflows.
// To avoid race conditions between concurrent agents, it operates in two phases,
// both leveraging Datastore transactions:
//  1. findPendingJobs: checks bugs that have matching AIPendingWorkflows.
//  2. processStaleBugs: evaluates stale bugs (AIJobCheck < currentDate).
//
// Both phases (re-)compute applicable workflows and update AIJobCheck and AIPendingWorkflows.
func autoCreateAIJobs(ctx context.Context, reqWorkflows []dashapi.AIWorkflow, client APIClient) (bool, error) {
	date := int64(timeDate(timeNow(ctx)))
	for ns, cfg := range getConfig(ctx).Namespaces {
		if cfg.AI == nil || !client.AllowedNamespace(ns) {
			continue
		}
		if created, err := findPendingJobs(ctx, ns, date, reqWorkflows); err != nil {
			return false, err
		} else if created {
			return true, nil
		}
		if created, err := processStaleBugs(ctx, ns, date, reqWorkflows); err != nil {
			return false, err
		} else if created {
			return true, nil
		}
	}
	return false, nil
}

func findPendingJobs(ctx context.Context, ns string, date int64, reqWorkflows []dashapi.AIWorkflow) (bool, error) {
	for _, req := range reqWorkflows {
		var bugs []*Bug
		keys, err := db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("AIPendingWorkflows=", string(req.Type)).
			Limit(1).
			GetAll(ctx, &bugs)
		if err != nil {
			return false, fmt.Errorf("failed to fetch pending bugs: %w", err)
		}
		if len(bugs) == 0 {
			continue
		}
		created, err := tryCreateAIJobForBug(ctx, bugs[0], keys[0], date, reqWorkflows)
		if created || err != nil {
			return created, err
		}
	}
	return false, nil
}

func processStaleBugs(ctx context.Context, ns string, date int64, reqWorkflows []dashapi.AIWorkflow) (bool, error) {
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Status=", BugStatusOpen).
		Filter("AIJobCheck<", date).
		Limit(100).
		GetAll(ctx, &bugs)
	if err != nil {
		return false, fmt.Errorf("failed to fetch stale bugs: %w", err)
	}

	for i, bug := range bugs {
		created, err := tryCreateAIJobForBug(ctx, bug, keys[i], date, reqWorkflows)
		if created || err != nil {
			return created, err
		}
	}
	return false, nil
}

func tryCreateAIJobForBug(ctx context.Context, bug *Bug, bugKey *db.Key, date int64,
	reqWorkflows []dashapi.AIWorkflow) (bool, error) {
	pending, err := pendingWorkflowsForBug(ctx, bug, bugKey)
	if err != nil {
		log.Errorf(ctx, "failed to LoadBugJobs for bug %v: %v", bugKey.StringID(), err)
		return false, nil
	}

	created := false
	var matchedReq dashapi.AIWorkflow
	for _, req := range reqWorkflows {
		idx := slices.Index(pending, string(req.Type))
		if idx != -1 {
			pending = slices.Delete(pending, idx, idx+1)
			created = true
			matchedReq = req
			break
		}
	}

	errConflict := fmt.Errorf("bug already evaluated or modified")
	err = updateSingleBug(ctx, bugKey, func(txBug *Bug) error {
		if txBug.AIJobCheck != bug.AIJobCheck || !slices.Equal(txBug.AIPendingWorkflows, bug.AIPendingWorkflows) {
			return errConflict
		}
		txBug.AIJobCheck = max(txBug.AIJobCheck, date)
		txBug.AIPendingWorkflows = pending
		return nil
	})
	if err != nil {
		if errors.Is(err, errConflict) {
			return false, nil
		}
		return false, err
	}

	if created {
		if _, createErr := bugJobCreate(ctx, matchedReq.Name, matchedReq.Type, bug, nil); createErr != nil {
			return false, fmt.Errorf("failed to create ai job %v for bug %v: %w", matchedReq.Type, bugKey.StringID(), createErr)
		}
		return true, nil
	}
	return false, nil
}

// pendingWorkflowsForBug returns a list of workflow types that the bug qualifies for,
// excluding workflows that already have running or completed jobs, or jobs that are
// in exponential backoff.
func pendingWorkflowsForBug(ctx context.Context, bug *Bug, bugKey *db.Key) ([]string, error) {
	workflows := workflowsForBug(ctx, bug, false)
	if len(workflows) == 0 {
		return nil, nil
	}
	jobs, err := aidb.LoadBugJobs(ctx, bugKey.StringID())
	if err != nil {
		return nil, err
	}
	workflowAttempts := map[ai.WorkflowType]struct {
		count int
		last  time.Time
	}{}
	for _, job := range jobs {
		typ := ai.WorkflowType(job.Workflow)
		// Have finished successful job.
		if job.Finished.Valid && job.Error == "" ||
			// Or already have a pending or a running job.
			!job.Finished.Valid {
			// Don't create new jobs for these types.
			delete(workflows, typ)
			continue
		}
		// Have a failed, or aborted job.
		attempts := workflowAttempts[typ]
		attempts.count++
		if job.Started.Time.After(attempts.last) {
			attempts.last = job.Started.Time
		}
		workflowAttempts[typ] = attempts
	}
	// For failed/aborted jobs, we don't know if the reason was temporary or permanent.
	// Failed kernel builds and failed repros may be permanent, but also may be flakes,
	// or may be fixed over time. So we retry failed/aborted jobs with an exponential
	// backoff based on attempts count. 1 job is retried in 1 day; 2 jobs - in 2 days;
	// 3 jobs - in 4 days, and so on up to the cap of 30 days.
	for typ, attempts := range workflowAttempts {
		retryPeriod := time.Duration(min(30, 1<<(attempts.count-1))) * 24 * time.Hour
		if timeSince(ctx, attempts.last) < retryPeriod {
			delete(workflows, typ)
		}
	}
	var pending []string
	for workflow := range workflows {
		pending = append(pending, string(workflow))
	}
	slices.Sort(pending)
	return pending, nil
}

func workflowsForBug(ctx context.Context, bug *Bug, manual bool) map[ai.WorkflowType]bool {
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
		workflows[ai.WorkflowRepro] = true
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

func compactAIJobs(jobs []*aidb.Job) []*aidb.Job {
	// Only keep non-aborted jobs, and show aborted jobs if they are newest per workflow.
	newestJob := make(map[string]*aidb.Job)
	for _, job := range jobs {
		g := newestJob[job.Workflow]
		if g == nil || job.Created.After(g.Created) {
			newestJob[job.Workflow] = job
		}
	}

	var filtered []*aidb.Job
	for _, job := range jobs {
		if !job.Aborted {
			filtered = append(filtered, job)
		} else if job == newestJob[job.Workflow] {
			filtered = append(filtered, job)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Created.After(filtered[j].Created)
	})

	return filtered
}
