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
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// handleTestRequest added new job to datastore.
// Returns empty string if job added successfully, or reason why it wasn't added.
func handleTestRequest(c context.Context, bugID, user, extID, link, patch, repo, branch string,
	jobCC []string) string {
	log.Infof(c, "test request: bug=%q user=%q extID=%q patch=%v, repo=%q branch=%q",
		bugID, user, extID, len(patch), repo, branch)
	for _, blacklisted := range config.EmailBlacklist {
		if user == blacklisted {
			log.Errorf(c, "test request from blacklisted user: %v", user)
			return ""
		}
	}
	bug, bugKey, err := findBugByReportingID(c, bugID)
	if err != nil {
		log.Errorf(c, "can't find bug: %v", err)
		if link != "" {
			return "" // don't send duplicate error reply
		}
		myEmail, _ := email.AddAddrContext(ownEmail(c), "hash")
		return fmt.Sprintf("can't find the associated bug (do you have %v in To/CC?)", myEmail)
	}
	bugReporting, _ := bugReportingByID(bug, bugID)
	reply, err := addTestJob(c, bug, bugKey, bugReporting, user, extID, link, patch, repo, branch, jobCC)
	if err != nil {
		log.Errorf(c, "test request failed: %v", err)
		if reply == "" {
			reply = internalError
		}
	}
	// Update bug CC list in any case.
	if !stringsInList(strings.Split(bugReporting.CC, "|"), jobCC) {
		tx := func(c context.Context) error {
			bug := new(Bug)
			if err := datastore.Get(c, bugKey, bug); err != nil {
				return err
			}
			bugReporting = bugReportingByName(bug, bugReporting.Name)
			bugCC := strings.Split(bugReporting.CC, "|")
			merged := email.MergeEmailLists(bugCC, jobCC)
			bugReporting.CC = strings.Join(merged, "|")
			if _, err := datastore.Put(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to put bug: %v", err)
			}
			return nil
		}
		if err := datastore.RunInTransaction(c, tx, nil); err != nil {
			// We've already stored the job, so just log the error.
			log.Errorf(c, "failed to update bug: %v", err)
		}
	}
	if link != "" {
		reply = "" // don't send duplicate error reply
	}
	return reply
}

func addTestJob(c context.Context, bug *Bug, bugKey *datastore.Key, bugReporting *BugReporting,
	user, extID, link, patch, repo, branch string, jobCC []string) (string, error) {
	crash, crashKey, err := findCrashForBug(c, bug)
	if err != nil {
		return "", err
	}
	if reason := checkTestJob(c, bug, bugReporting, crash, repo, branch); reason != "" {
		return reason, nil
	}

	manager := crash.Manager
	for _, ns := range config.Namespaces {
		if mgr, ok := ns.Managers[manager]; ok {
			if mgr.RestrictedTestingRepo != "" && repo != mgr.RestrictedTestingRepo {
				return mgr.RestrictedTestingReason, nil
			}
			if mgr.Decommissioned {
				manager = mgr.DelegatedTo
			}
			break
		}
	}

	patchID, err := putText(c, bug.Namespace, textPatch, []byte(patch), false)
	if err != nil {
		return "", err
	}

	job := &Job{
		Created:      timeNow(c),
		User:         user,
		CC:           jobCC,
		Reporting:    bugReporting.Name,
		ExtID:        extID,
		Link:         link,
		Namespace:    bug.Namespace,
		Manager:      manager,
		BugTitle:     bug.displayTitle(),
		CrashID:      crashKey.IntID(),
		KernelRepo:   repo,
		KernelBranch: branch,
		Patch:        patchID,
	}

	deletePatch := false
	tx := func(c context.Context) error {
		deletePatch = false
		// We can get 2 emails for the same request: one direct and one from a mailing list.
		// Filter out such duplicates (for dup we only need link update).
		var jobs []*Job
		keys, err := datastore.NewQuery("Job").
			Ancestor(bugKey).
			Filter("ExtID=", extID).
			GetAll(c, &jobs)
		if len(jobs) > 1 || err != nil {
			return fmt.Errorf("failed to query jobs: jobs=%v err=%v", len(jobs), err)
		}
		if len(jobs) != 0 {
			// The job is already present, update link.
			deletePatch = true
			existingJob, jobKey := jobs[0], keys[0]
			if existingJob.Link != "" || link == "" {
				return nil
			}
			existingJob.Link = link
			if _, err := datastore.Put(c, jobKey, existingJob); err != nil {
				return fmt.Errorf("failed to put job: %v", err)
			}
			return nil
		}
		// Create a new job.
		jobKey := datastore.NewIncompleteKey(c, "Job", bugKey)
		if _, err := datastore.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
		}
		return nil
	}
	err = datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{XG: true, Attempts: 30})
	if patchID != 0 && deletePatch || err != nil {
		if err := datastore.Delete(c, datastore.NewKey(c, textPatch, "", patchID, nil)); err != nil {
			log.Errorf(c, "failed to delete patch for dup job: %v", err)
		}
	}
	if err != nil {
		return "", fmt.Errorf("job tx failed: %v", err)
	}
	return "", nil
}

func checkTestJob(c context.Context, bug *Bug, bugReporting *BugReporting, crash *Crash,
	repo, branch string) string {
	switch {
	case crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it."
	case !vcs.CheckRepoAddress(repo):
		return fmt.Sprintf("%q does not look like a valid git repo address.", repo)
	case !vcs.CheckBranch(branch) && !vcs.CheckCommitHash(branch):
		return fmt.Sprintf("%q does not look like a valid git branch or commit.", branch)
	case crash.ReproC == 0 && crash.ReproSyz == 0:
		return "This crash does not have a reproducer. I cannot test it."
	case bug.Status == BugStatusFixed:
		return "This bug is already marked as fixed. No point in testing."
	case bug.Status == BugStatusInvalid:
		return "This bug is already marked as invalid. No point in testing."
	// TODO(dvyukov): for BugStatusDup check status of the canonical bug.
	case !bugReporting.Closed.IsZero():
		return "This bug is already upstreamed. Please test upstream."
	}
	return ""
}

// pollPendingJobs returns the next job to execute for the provided list of managers.
func pollPendingJobs(c context.Context, managers []string) (interface{}, error) {
retry:
	job, jobKey, err := loadPendingJob(c, managers)
	if job == nil || err != nil {
		return job, err
	}
	jobID := extJobID(jobKey)
	patch, _, err := getText(c, textPatch, job.Patch)
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
	kernelConfig, _, err := getText(c, textKernelConfig, build.KernelConfig)
	if err != nil {
		return nil, err
	}

	reproC, _, err := getText(c, textReproC, crash.ReproC)
	if err != nil {
		return nil, err
	}
	reproSyz, _, err := getText(c, textReproSyz, crash.ReproSyz)
	if err != nil {
		return nil, err
	}

	now := timeNow(c)
	stale := false
	tx := func(c context.Context) error {
		stale = false
		job = new(Job)
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
		if isNewBuild, err := uploadBuild(c, now, ns, &req.Build, BuildJob); err != nil {
			return err
		} else if !isNewBuild {
			log.Errorf(c, "job %v: duplicate build %v", jobID, req.Build.ID)
		}
		if job.Error, err = putText(c, ns, textError, req.Error, false); err != nil {
			return err
		}
		if job.CrashLog, err = putText(c, ns, textCrashLog, req.CrashLog, false); err != nil {
			return err
		}
		if job.CrashReport, err = putText(c, ns, textCrashReport, req.CrashReport, false); err != nil {
			return err
		}
		job.BuildID = req.Build.ID
		job.CrashTitle = req.CrashTitle
		job.Finished = now
		if _, err := datastore.Put(c, jobKey, job); err != nil {
			return fmt.Errorf("failed to put job: %v", err)
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

func createBugReportForJob(c context.Context, job *Job, jobKey *datastore.Key, config interface{}) (
	*dashapi.BugReport, error) {
	reportingConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	crashLog, _, err := getText(c, textCrashLog, job.CrashLog)
	if err != nil {
		return nil, err
	}
	if len(crashLog) > maxMailLogLen {
		crashLog = crashLog[len(crashLog)-maxMailLogLen:]
	}
	report, _, err := getText(c, textCrashReport, job.CrashReport)
	if err != nil {
		return nil, err
	}
	if len(report) > maxMailReportLen {
		report = report[:maxMailReportLen]
	}
	jobError, _, err := getText(c, textError, job.Error)
	if err != nil {
		return nil, err
	}
	patch, _, err := getText(c, textPatch, job.Patch)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, job.Namespace, job.BuildID)
	if err != nil {
		return nil, err
	}
	kernelConfig, _, err := getText(c, textKernelConfig, build.KernelConfig)
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
		Namespace:         job.Namespace,
		Config:            reportingConfig,
		ID:                bugReporting.ID,
		JobID:             extJobID(jobKey),
		ExtID:             job.ExtID,
		Title:             bug.displayTitle(),
		CC:                job.CC,
		Log:               crashLog,
		LogLink:           externalLink(c, textCrashLog, job.CrashLog),
		Report:            report,
		ReportLink:        externalLink(c, textCrashReport, job.CrashReport),
		OS:                build.OS,
		Arch:              build.Arch,
		VMArch:            build.VMArch,
		CompilerID:        build.CompilerID,
		KernelRepo:        build.KernelRepo,
		KernelRepoAlias:   kernelRepoInfo(build).Alias,
		KernelBranch:      build.KernelBranch,
		KernelCommit:      build.KernelCommit,
		KernelCommitTitle: build.KernelCommitTitle,
		KernelCommitDate:  build.KernelCommitDate,
		KernelConfig:      kernelConfig,
		KernelConfigLink:  externalLink(c, textKernelConfig, build.KernelConfig),
		CrashTitle:        job.CrashTitle,
		Error:             jobError,
		ErrorLink:         externalLink(c, textError, job.Error),
		Patch:             patch,
		PatchLink:         externalLink(c, textPatch, job.Patch),
	}
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
			return fmt.Errorf("failed to put job: %v", err)
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
