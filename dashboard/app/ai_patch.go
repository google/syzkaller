// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// The sync covers the bugs that got a patching job during this period.
// Bug.AIPatch of other bugs is not updated anymore, so its users must not rely on older patches.
const aiPatchSyncWindow = 30 * 24 * time.Hour

// handleAIPatchSync periodically copies the state of AI-generated patches from the AI database
// to Bug.AIPatch, so that the code that deals with bugs (e.g. reporting filters) does not need
// to query the AI database. The state is fully recalculated every time and this is the only place
// where it's updated, so it may lag behind the AI database, but does not diverge from it.
func handleAIPatchSync(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	for ns, cfg := range getConfig(ctx).Namespaces {
		// Patches are reviewed only in namespaces with AI reporting stages.
		if cfg.AI == nil || len(cfg.AI.Stages) == 0 || cfg.Decommissioned {
			continue
		}
		if err := syncAIPatches(ctx, ns, cfg.AI); err != nil {
			log.Errorf(ctx, "failed to sync AI patches for %v: %v", ns, err)
		}
	}
}

func syncAIPatches(ctx context.Context, ns string, cfg *AIConfig) error {
	jobs, reports, err := aidb.LoadPatchJobs(ctx, ns, timeNow(ctx).Add(-aiPatchSyncWindow))
	if err != nil {
		return err
	}
	patches := bugAIPatches(cfg, jobs, reports)
	// Datastore limits the number of entities in a single GetMulti call.
	const batch = 1000
	for bugIDs := range slices.Chunk(slices.Collect(maps.Keys(patches)), batch) {
		keys := make([]*db.Key, len(bugIDs))
		for i, bugID := range bugIDs {
			keys[i] = db.NewKey(ctx, "Bug", bugID, 0, nil)
		}
		bugs := make([]*Bug, len(keys))
		if err := db.GetMulti(ctx, keys, bugs); err != nil {
			return err
		}
		// Normally only few bugs change between the runs, so update them one by one.
		for i, bug := range bugs {
			patch := patches[bugIDs[i]]
			if bug.AIPatch.equal(patch) {
				continue
			}
			err := updateSingleBug(ctx, keys[i], func(bug *Bug) error {
				bug.AIPatch = patch
				return nil
			})
			if err != nil {
				log.Errorf(ctx, "failed to update AI patch of bug %v: %v", bugIDs[i], err)
			}
		}
	}
	return nil
}

// bugAIPatches calculates Bug.AIPatch for the bugs (the map keys are bug IDs) that have the jobs.
// The jobs must be sorted from the newest to the oldest one.
func bugAIPatches(cfg *AIConfig, jobs []*aidb.PatchJob, reports []*aidb.JobReporting) map[string]BugAIPatch {
	jobReports := make(map[string][]*aidb.JobReporting)
	for _, report := range reports {
		jobReports[report.JobID] = append(jobReports[report.JobID], report)
	}
	bugJobs := make(map[string][]*aidb.PatchJob)
	for _, job := range jobs {
		bugJobs[job.BugID] = append(bugJobs[job.BugID], job)
	}
	isPatching := func(job *aidb.PatchJob) bool { return job.Type == ai.WorkflowPatching }
	patches := make(map[string]BugAIPatch)
	for bugID, jobs := range bugJobs {
		// A patching job starts a new patch, patch iteration jobs make new versions of it.
		// We are interested only in the latest patch of the bug.
		pos := slices.IndexFunc(jobs, isPatching)
		if pos == -1 {
			// The patching job is older than the sync window, so we don't see the whole patch.
			continue
		}
		patches[bugID] = makeBugAIPatch(cfg, jobs[:pos+1], jobReports)
	}
	return patches
}

// makeBugAIPatch calculates Bug.AIPatch from the jobs that worked on a single patch
// (sorted from the newest to the oldest one, which is the patching job) and the reports of their results.
func makeBugAIPatch(cfg *AIConfig, jobs []*aidb.PatchJob, jobReports map[string][]*aidb.JobReporting) BugAIPatch {
	// The latest version of the patch.
	pos := slices.IndexFunc(jobs, func(job *aidb.PatchJob) bool { return job.HasPatch })
	if pos == -1 {
		patching := jobs[len(jobs)-1]
		if patching.Finished.Valid {
			return BugAIPatch{JobID: patching.ID, State: AIPatchFailed}
		}
		return BugAIPatch{JobID: patching.ID, State: AIPatchPending}
	}
	patch := BugAIPatch{
		JobID: jobs[pos].ID,
		State: AIPatchCandidate,
	}
	if slices.ContainsFunc(jobs, func(job *aidb.PatchJob) bool { return job.Correct.Valid }) {
		patch.State = AIPatchDecided
	}
	// The bug may be held and released via any version of the patch, the last request wins.
	var lastReported, held, unheld time.Time
	for _, job := range jobs {
		if job.LastComment.Valid && job.LastComment.Time.After(patch.LastComment) {
			patch.LastComment = job.LastComment.Time
		}
		if job.Held.Valid && job.Held.Time.After(held) {
			held = job.Held.Time
		}
		if job.Unheld.Valid && job.Unheld.Time.After(unheld) {
			unheld = job.Unheld.Time
		}
		for _, report := range jobReports[job.ID] {
			reported := report.ReportedAt.Time
			if patch.Posted.IsZero() || reported.Before(patch.Posted) {
				patch.Posted = reported
			}
			// The link is for everybody, so it must point to a public report.
			idx := cfg.StageIndexByName(report.Stage)
			public := idx != -1 && cfg.Stages[idx].AccessLevel == AccessPublic
			if link := report.ExternalLink(); public && link != "" && reported.After(lastReported) {
				lastReported, patch.Link = reported, link
			}
		}
	}
	patch.Held = held.After(unheld)
	// Datastore does not preserve the full precision of timestamps.
	patch.Posted = patch.Posted.Truncate(time.Second)
	patch.LastComment = patch.LastComment.Truncate(time.Second)
	return patch
}
