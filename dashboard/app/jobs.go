// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/git"
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// handleTestRequest added new job to datastore.
// Returns empty string if job added successfully, or reason why it wasn't added.
func handleTestRequest(c context.Context, bugID, user, extID, patch, repo, branch string) string {
	log.Infof(c, "test request: bug=%q user=%q extID=%q patch=%v, repo=%q branch=%q",
		bugID, user, extID, len(patch), repo, branch)
	reply, err := addTestJob(c, bugID, user, extID, patch, repo, branch)
	if err != nil {
		log.Errorf(c, "test request failed: %v", err)
		if reply == "" {
			reply = internalError
		}
	}
	return reply
}

func addTestJob(c context.Context, bugID, user, extID, patch, repo, branch string) (string, error) {
	bug, bugKey, err := findBugByReportingID(c, bugID)
	if err != nil {
		return "can't find associated bug", err
	}
	now := timeNow(c)
	bugReporting, _ := bugReportingByID(bug, bugID, now)

	// TODO(dvyukov): find the exact crash that we reported.
	crash, crashKey, err := findCrashForBug(c, bug)
	if err != nil {
		return "", err
	}
	if crash.ReproC == 0 && crash.ReproSyz == 0 {
		return "This crash does not have a reproducer. I cannot test it.", nil
	}

	switch {
	case !git.CheckRepoAddress(repo):
		return fmt.Sprintf("%q does not look like a valid git repo address.", repo), nil
	case !git.CheckBranch(branch):
		return fmt.Sprintf("%q does not look like a valid git branch name.", branch), nil
	case len(patch) == 0:
		return "I don't see any patch attached to the request.", nil
	case crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it.", nil
	case bug.Status == BugStatusFixed:
		return "This bug is already marked as fixed. No point in testing.", nil
	case bug.Status == BugStatusInvalid:
		return "This bug is already marked as invalid. No point in testing.", nil
	// TODO(dvyukov): for BugStatusDup check status of the canonical bug.
	case !bugReporting.Closed.IsZero():
		return "This bug is already upstreamed. Please test upstream.", nil
	}

	patchID, err := putText(c, bug.Namespace, "Patch", []byte(patch), false)
	if err != nil {
		return "", err
	}

	job := &Job{
		Created:      now,
		User:         user,
		Reporting:    bugReporting.Name,
		ExtID:        extID,
		Namespace:    bug.Namespace,
		Manager:      crash.Manager,
		BugTitle:     bug.displayTitle(),
		CrashID:      crashKey.IntID(),
		KernelRepo:   repo,
		KernelBranch: branch,
		Patch:        patchID,
	}
	jobKey, err := datastore.Put(c, datastore.NewIncompleteKey(c, "Job", bugKey), job)
	if err != nil {
		return "", fmt.Errorf("failed to put job: %v", err)
	}
	jobID := extJobID(jobKey)

	// Add user to bug reporting CC.
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := datastore.Get(c, bugKey, bug); err != nil {
			return err
		}
		bugReporting := bugReportingByName(bug, bugReporting.Name)
		cc := strings.Split(bugReporting.CC, "|")
		if stringInList(cc, user) {
			return nil
		}
		merged := email.MergeEmailLists(cc, []string{user})
		bugReporting.CC = strings.Join(merged, "|")
		if _, err := datastore.Put(c, bugKey, bug); err != nil {
			return err
		}
		return nil
	}
	if err := datastore.RunInTransaction(c, tx, nil); err != nil {
		// We've already stored the job, so just log the error.
		log.Errorf(c, "job %v: failed to update bug: %v", jobID, err)
	}
	return "", nil
}

// pollPendingJobs returns the next job to execute for the provided list of managers.
func pollPendingJobs(c context.Context, managers []string) (interface{}, error) {
retry:
	job, jobKey, err := loadPendingJob(c, managers)
	if job == nil || err != nil {
		return job, err
	}
	jobID := extJobID(jobKey)
	patch, err := getText(c, "Patch", job.Patch)
	if err != nil {
		return nil, err
	}
	bugKey := jobKey.Parent()
	crashKey := datastore.NewKey(c, "Crash", "", job.CrashID, bugKey)
	crash := new(Crash)
	if err := datastore.Get(c, crashKey, crash); err != nil {
		return nil, fmt.Errorf("job %v: failed to get crash: %v", jobID, err)
	}

	build, err := loadBuild(c, job.Namespace, crash.BuildID)
	if err != nil {
		return nil, err
	}
	kernelConfig, err := getText(c, "KernelConfig", build.KernelConfig)
	if err != nil {
		return nil, err
	}

	reproC, err := getText(c, "ReproC", crash.ReproC)
	if err != nil {
		return nil, err
	}
	reproSyz, err := getText(c, "ReproSyz", crash.ReproSyz)
	if err != nil {
		return nil, err
	}

	now := timeNow(c)
	stale := false
	tx := func(c context.Context) error {
		stale = false
		job := new(Job)
		if err := datastore.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get in tx: %v", jobID, err)
		}
		if !job.Finished.IsZero() {
			// This happens sometimes due to inconsistent datastore.
			stale = true
			return nil
		}
		job.Attempts++
		job.Started = now
		if _, err := datastore.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to put: %v", jobID, err)
		}
		return nil
	}
	if err := datastore.RunInTransaction(c, tx, nil); err != nil {
		return nil, err
	}
	if stale {
		goto retry
	}
	resp := &dashapi.JobPollResp{
		ID:              jobID,
		Manager:         job.Manager,
		KernelRepo:      job.KernelRepo,
		KernelBranch:    job.KernelBranch,
		KernelConfig:    kernelConfig,
		SyzkallerCommit: build.SyzkallerCommit,
		Patch:           patch,
		ReproOpts:       crash.ReproOpts,
		ReproSyz:        reproSyz,
		ReproC:          reproC,
	}
	return resp, nil
}

// doneJob is called by syz-ci to mark completion of a job.
func doneJob(c context.Context, req *dashapi.JobDoneReq) error {
	jobID := req.ID
	jobKey, err := jobID2Key(c, req.ID)
	if err != nil {
		return err
	}
	now := timeNow(c)
	tx := func(c context.Context) error {
		job := new(Job)
		if err := datastore.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get job: %v", jobID, err)
		}
		if !job.Finished.IsZero() {
			return fmt.Errorf("job %v: already finished", jobID)
		}
		ns := job.Namespace
		if err := uploadBuild(c, ns, &req.Build); err != nil {
			return err
		}
		if job.Error, err = putText(c, ns, "Error", req.Error, false); err != nil {
			return err
		}
		if job.CrashLog, err = putText(c, ns, "CrashLog", req.CrashLog, false); err != nil {
			return err
		}
		if job.CrashReport, err = putText(c, ns, "CrashReport", req.CrashReport, false); err != nil {
			return err
		}
		job.BuildID = req.Build.ID
		job.CrashTitle = req.CrashTitle
		job.Finished = now
		if _, err := datastore.Put(c, jobKey, job); err != nil {
			return err
		}
		return nil
	}
	return datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{XG: true, Attempts: 30})
}

func pollCompletedJobs(c context.Context, typ string) ([]*dashapi.BugReport, error) {
	var jobs []*Job
	keys, err := datastore.NewQuery("Job").
		Filter("Finished>", time.Time{}).
		Filter("Reported=", false).
		GetAll(c, &jobs)
	if err != nil {
		return nil, fmt.Errorf("failed to query jobs: %v", err)
	}
	var reports []*dashapi.BugReport
	for i, job := range jobs {
		reporting := config.Namespaces[job.Namespace].ReportingByName(job.Reporting)
		if reporting.Config.Type() != typ {
			continue
		}
		rep, err := createBugReportForJob(c, job, keys[i], reporting.Config)
		if err != nil {
			log.Errorf(c, "failed to create report for job: %v", err)
			continue
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

func createBugReportForJob(c context.Context, job *Job, jobKey *datastore.Key, config interface{}) (*dashapi.BugReport, error) {
	reportingConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	crashLog, err := getText(c, "CrashLog", job.CrashLog)
	if err != nil {
		return nil, err
	}
	if len(crashLog) > maxMailLogLen {
		crashLog = crashLog[len(crashLog)-maxMailLogLen:]
	}
	report, err := getText(c, "CrashReport", job.CrashReport)
	if err != nil {
		return nil, err
	}
	if len(report) > maxMailReportLen {
		report = report[:maxMailReportLen]
	}
	jobError, err := getText(c, "Error", job.Error)
	if err != nil {
		return nil, err
	}
	if len(jobError) > maxMailLogLen {
		jobError = jobError[:maxMailLogLen]
	}
	patch, err := getText(c, "Patch", job.Patch)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, job.Namespace, job.BuildID)
	if err != nil {
		return nil, err
	}
	kernelConfig, err := getText(c, "KernelConfig", build.KernelConfig)
	if err != nil {
		return nil, err
	}
	bug := new(Bug)
	if err := datastore.Get(c, jobKey.Parent(), bug); err != nil {
		return nil, fmt.Errorf("failed to load job parent bug: %v", err)
	}
	bugReporting := bugReportingByName(bug, job.Reporting)
	if bugReporting == nil {
		return nil, fmt.Errorf("job bug has no reporting %q", job.Reporting)
	}
	rep := &dashapi.BugReport{
		Namespace:    job.Namespace,
		Config:       reportingConfig,
		ID:           bugReporting.ID,
		JobID:        extJobID(jobKey),
		ExtID:        bugReporting.ExtID,
		Title:        bug.displayTitle(),
		Log:          crashLog,
		Report:       report,
		OS:           build.OS,
		Arch:         build.Arch,
		VMArch:       build.VMArch,
		CompilerID:   build.CompilerID,
		KernelRepo:   build.KernelRepo,
		KernelBranch: build.KernelBranch,
		KernelCommit: build.KernelCommit,
		KernelConfig: kernelConfig,
		CrashTitle:   job.CrashTitle,
		Error:        jobError,
		Patch:        patch,
	}
	if bugReporting.CC != "" {
		rep.CC = strings.Split(bugReporting.CC, "|")
	}
	rep.CC = append(rep.CC, job.User)
	return rep, nil
}

func jobReported(c context.Context, jobID string) error {
	jobKey, err := jobID2Key(c, jobID)
	if err != nil {
		return err
	}
	tx := func(c context.Context) error {
		job := new(Job)
		if err := datastore.Get(c, jobKey, job); err != nil {
			return fmt.Errorf("job %v: failed to get job: %v", jobID, err)
		}
		job.Reported = true
		if _, err := datastore.Put(c, jobKey, job); err != nil {
			return err
		}
		return nil
	}
	return datastore.RunInTransaction(c, tx, nil)
}

func loadPendingJob(c context.Context, managers []string) (*Job, *datastore.Key, error) {
	var jobs []*Job
	keys, err := datastore.NewQuery("Job").
		Filter("Finished=", time.Time{}).
		Order("Attempts").
		Order("Created").
		GetAll(c, &jobs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query jobs: %v", err)
	}
	mgrs := make(map[string]bool)
	for _, mgr := range managers {
		mgrs[mgr] = true
	}
	for i, job := range jobs {
		if !mgrs[job.Manager] {
			continue
		}
		return job, keys[i], nil
	}
	return nil, nil, nil
}

func extJobID(jobKey *datastore.Key) string {
	return fmt.Sprintf("%v|%v", jobKey.Parent().StringID(), jobKey.IntID())
}

func jobID2Key(c context.Context, id string) (*datastore.Key, error) {
	keyStr := strings.Split(id, "|")
	if len(keyStr) != 2 {
		return nil, fmt.Errorf("bad job id %q", id)
	}
	jobKeyID, err := strconv.ParseInt(keyStr[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad job id %q", id)
	}
	bugKey := datastore.NewKey(c, "Bug", keyStr[0], 0, nil)
	jobKey := datastore.NewKey(c, "Job", "", jobKeyID, bugKey)
	return jobKey, nil
}
