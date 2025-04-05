// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"
)

func handleInvalidateBisection(c context.Context, w http.ResponseWriter, r *http.Request) error {
	encodedKey := r.FormValue("key")
	if encodedKey == "" {
		return fmt.Errorf("mandatory parameter key is missing")
	}
	jobKey, err := db.DecodeKey(encodedKey)
	if err != nil {
		return fmt.Errorf("failed to decode job key %v: %w", encodedKey, err)
	}

	err = invalidateBisection(c, jobKey, r.FormValue("restart") == "1")
	if err != nil {
		return fmt.Errorf("failed to invalidate job %v: %w", jobKey, err)
	}

	// Sending back to bug page after successful invalidation.
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusFound)
	return nil
}

// dropNamespace drops all entities related to a single namespace.
// Use with care. There is no undo.
// This functionality is intentionally not connected to any handler.
// To use it, first make a backup of the db. Then, specify the target
// namespace in the ns variable, connect the function to a handler, invoke it
// and double check the output. Finally, set dryRun to false and invoke again.
func dropNamespace(c context.Context, w http.ResponseWriter, r *http.Request) error {
	ns := "non-existent"
	dryRun := true
	if !dryRun {
		log.Criticalf(c, "dropping namespace %v", ns)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "dropping namespace %v\n", ns)
	if err := dropNamespaceReportingState(c, w, ns, dryRun); err != nil {
		return err
	}
	type Entity struct {
		name  string
		child string
	}
	entities := []Entity{
		{textPatch, ""},
		{textReproC, ""},
		{textReproSyz, ""},
		{textKernelConfig, ""},
		{"Job", ""},
		{textLog, ""},
		{textError, ""},
		{textCrashLog, ""},
		{textCrashReport, ""},
		{"Build", ""},
		{"Manager", "ManagerStats"},
		{"Bug", "Crash"},
	}
	for _, entity := range entities {
		keys, err := db.NewQuery(entity.name).
			Filter("Namespace=", ns).
			KeysOnly().
			GetAll(c, nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%v: %v\n", entity.name, len(keys))
		if entity.child != "" {
			var childKeys []*db.Key
			for _, key := range keys {
				keys1, err := db.NewQuery(entity.child).
					Ancestor(key).
					KeysOnly().
					GetAll(c, nil)
				if err != nil {
					return err
				}
				childKeys = append(childKeys, keys1...)
			}
			fmt.Fprintf(w, "  %v: %v\n", entity.child, len(childKeys))
			if err := dropEntities(c, childKeys, dryRun); err != nil {
				return err
			}
		}
		if err := dropEntities(c, keys, dryRun); err != nil {
			return err
		}
	}
	return nil
}

func dropNamespaceReportingState(c context.Context, w http.ResponseWriter, ns string, dryRun bool) error {
	tx := func(c context.Context) error {
		state, err := loadReportingState(c)
		if err != nil {
			return err
		}
		newState := new(ReportingState)
		for _, ent := range state.Entries {
			if ent.Namespace != ns {
				newState.Entries = append(newState.Entries, ent)
			}
		}
		if !dryRun {
			if err := saveReportingState(c, newState); err != nil {
				return err
			}
		}
		fmt.Fprintf(w, "ReportingState: %v\n", len(state.Entries)-len(newState.Entries))
		return nil
	}
	return runInTransaction(c, tx, nil)
}

func dropEntities(c context.Context, keys []*db.Key, dryRun bool) error {
	if dryRun {
		return nil
	}
	for len(keys) != 0 {
		batch := min(len(keys), 100)
		if err := db.DeleteMulti(c, keys[:batch]); err != nil {
			return err
		}
		keys = keys[batch:]
	}
	return nil
}

func restartFailedBisections(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	var jobs []*Job
	var jobKeys []*db.Key
	jobKeys, err := db.NewQuery("Job").
		Filter("Finished>", time.Time{}).
		GetAll(c, &jobs)
	if err != nil {
		return fmt.Errorf("failed to query jobs: %w", err)
	}
	toReset := []*db.Key{}
	for i, job := range jobs {
		if job.Namespace != ns {
			continue
		}
		if job.Type != JobBisectCause && job.Type != JobBisectFix {
			continue
		}
		if job.Error == 0 {
			continue
		}
		errorTextBytes, _, err := getText(c, textError, job.Error)
		if err != nil {
			return fmt.Errorf("failed to query error text: %w", err)
		}
		fmt.Fprintf(w, "job type %v, ns %s, finished at %s, error:%s\n========\n",
			job.Type, job.Namespace, job.Finished, string(errorTextBytes))
		toReset = append(toReset, jobKeys[i])
	}
	if r.FormValue("apply") != "yes" {
		return nil
	}
	for idx, jobKey := range toReset {
		err = invalidateBisection(c, jobKey, true)
		if err != nil {
			fmt.Fprintf(w, "job %v update failed: %s", idx, err)
		}
	}

	fmt.Fprintf(w, "Done!\n")
	return nil
}

// updateBugReporting adds missing reporting stages to bugs in a single namespace.
// Use with care. There is no undo.
// This can be used to migrate datastore to a new config with more reporting stages.
// This functionality is intentionally not connected to any handler.
// Before invoking it is recommended to stop all connected instances just in case.
func updateBugReporting(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		GetAll(c, &bugs)
	if err != nil {
		return err
	}
	log.Warningf(c, "fetched %v bugs for namespce %v", len(bugs), ns)
	cfg := getNsConfig(c, ns)
	var update []*db.Key
	for i, bug := range bugs {
		if len(bug.Reporting) >= len(cfg.Reporting) {
			continue
		}
		update = append(update, keys[i])
	}
	return updateBatch(c, update, func(_ *db.Key, bug *Bug) {
		err := bug.updateReportings(c, cfg, timeNow(c))
		if err != nil {
			panic(err)
		}
	})
}

// updateBugTitles adds missing MergedTitles/AltTitles to bugs.
// This can be used to migrate datastore to the new scheme introduced:
// by commit fd1036219797 ("dashboard/app: merge duplicate crashes").
func updateBugTitles(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	var keys []*db.Key
	if err := foreachBug(c, nil, func(bug *Bug, key *db.Key) error {
		if len(bug.MergedTitles) == 0 || len(bug.AltTitles) == 0 {
			keys = append(keys, key)
		}
		return nil
	}); err != nil {
		return err
	}
	log.Warningf(c, "fetched %v bugs for update", len(keys))
	return updateBatch(c, keys, func(_ *db.Key, bug *Bug) {
		if len(bug.MergedTitles) == 0 {
			bug.MergedTitles = []string{bug.Title}
		}
		if len(bug.AltTitles) == 0 {
			bug.AltTitles = []string{bug.Title}
		}
	})
}

// updateCrashPriorities regenerates priorities for crashes.
// This has become necessary after the "dashboard: support per-Manager priority" commit.
// For now, the method only considers the crashes referenced from bug origin.
func updateCrashPriorities(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	bugsCount := 0
	bugPerKey := map[string]*Bug{}
	var crashKeys []*db.Key
	if err := foreachBug(c, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen).Filter("Namespace=", ns)
	}, func(bug *Bug, key *db.Key) error {
		bugsCount++
		// There'll be duplicate crash IDs.
		crashIDs := map[int64]struct{}{}
		for _, item := range bug.TreeTests.List {
			crashIDs[item.CrashID] = struct{}{}
		}
		for crashID := range crashIDs {
			crashKeys = append(crashKeys, db.NewKey(c, "Crash", "", crashID, key))
		}
		bugPerKey[key.String()] = bug
		return nil
	}); err != nil {
		return err
	}
	log.Warningf(c, "fetched %d bugs and %v crash keys to update", bugsCount, len(crashKeys))
	return updateBatch(c, crashKeys, func(key *db.Key, crash *Crash) {
		bugKey := key.Parent()
		bug := bugPerKey[bugKey.String()]
		build, err := loadBuild(c, ns, crash.BuildID)
		if build == nil || err != nil {
			panic(fmt.Sprintf("err: %s, build: %v", err, build))
		}
		crash.UpdateReportingPriority(c, build, bug)
	})
}

// setMissingBugFields makes sure all Bug entity fields are present in the database.
// The problem is that, in Datastore, sorting/filtering on a field will only return entries
// where that field is present.
func setMissingBugFields(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	var keys []*db.Key
	// Query everything.
	err := foreachBug(c, nil, func(bug *Bug, key *db.Key) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return err
	}
	log.Warningf(c, "fetched %v bugs for update", len(keys))
	// Save everything unchanged.
	return updateBatch(c, keys, func(_ *db.Key, bug *Bug) {})
}

// adminSendEmail can be used to send an arbitrary message from the bot.
func adminSendEmail(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	msg := &aemail.Message{
		Sender: r.FormValue("from"),
		To:     []string{r.FormValue("to")},
		Body:   r.FormValue("body"),
	}
	return sendEmail(c, msg)
}

func updateHeadReproLevel(c context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(c, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var keys []*db.Key
	newLevels := map[string]dashapi.ReproLevel{}
	if err := foreachBug(c, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen)
	}, func(bug *Bug, key *db.Key) error {
		if len(bug.Commits) > 0 {
			return nil
		}
		actual := ReproLevelNone
		reproCrashes, _, err := queryCrashesForBug(c, key, 2)
		if err != nil {
			return fmt.Errorf("failed to fetch crashes with repro: %w", err)
		}
		for _, crash := range reproCrashes {
			if crash.ReproIsRevoked {
				continue
			}
			if crash.ReproC > 0 {
				actual = ReproLevelC
				break
			}
			if crash.ReproSyz > 0 {
				actual = ReproLevelSyz
			}
		}
		if actual != bug.HeadReproLevel {
			fmt.Fprintf(w, "%v: HeadReproLevel mismatch, actual=%d db=%d\n", bugLink(bug.keyHash(c)), actual, bug.HeadReproLevel)
			newLevels[bug.keyHash(c)] = actual
			keys = append(keys, key)
		}
		return nil
	}); err != nil {
		return err
	}
	return updateBatch(c, keys, func(_ *db.Key, bug *Bug) {
		newLevel, ok := newLevels[bug.keyHash(c)]
		if !ok {
			panic("fetched unknown bug")
		}
		bug.HeadReproLevel = newLevel
	})
}

func updateBatch[T any](c context.Context, keys []*db.Key, transform func(key *db.Key, item *T)) error {
	for len(keys) != 0 {
		batchSize := min(len(keys), 20)
		batchKeys := keys[:batchSize]
		keys = keys[batchSize:]

		tx := func(c context.Context) error {
			items := make([]*T, len(batchKeys))
			if err := db.GetMulti(c, batchKeys, items); err != nil {
				return err
			}
			for i, item := range items {
				transform(batchKeys[i], item)
			}
			_, err := db.PutMulti(c, batchKeys, items)
			return err
		}
		if err := runInTransaction(c, tx, &db.TransactionOptions{XG: true}); err != nil {
			return err
		}
		log.Warningf(c, "updated %v bugs", len(batchKeys))
	}
	return nil
}

// Prevent warnings about dead code.
var (
	_ = dropNamespace
	_ = updateBugReporting
	_ = updateBugTitles
	_ = restartFailedBisections
	_ = setMissingBugFields
	_ = adminSendEmail
	_ = updateHeadReproLevel
	_ = updateCrashPriorities
)
