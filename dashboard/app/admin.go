// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func handleInvalidateBisection(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	encodedKey := r.FormValue("key")
	if encodedKey == "" {
		return fmt.Errorf("mandatory parameter key is missing")
	}
	jobKey, err := db.DecodeKey(encodedKey)
	if err != nil {
		return fmt.Errorf("failed to decode job key %v: %w", encodedKey, err)
	}

	err = invalidateBisection(ctx, jobKey, r.FormValue("restart") == "1")
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
func dropNamespace(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ns := "non-existent"
	dryRun := true
	if !dryRun {
		log.Criticalf(ctx, "dropping namespace %v", ns)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "dropping namespace %v\n", ns)
	if err := dropNamespaceReportingState(ctx, w, ns, dryRun); err != nil {
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
			GetAll(ctx, nil)
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
					GetAll(ctx, nil)
				if err != nil {
					return err
				}
				childKeys = append(childKeys, keys1...)
			}
			fmt.Fprintf(w, "  %v: %v\n", entity.child, len(childKeys))
			if err := dropEntities(ctx, childKeys, dryRun); err != nil {
				return err
			}
		}
		if err := dropEntities(ctx, keys, dryRun); err != nil {
			return err
		}
	}
	return nil
}

func dropNamespaceReportingState(ctx context.Context, w http.ResponseWriter, ns string, dryRun bool) error {
	tx := func(ctx context.Context) error {
		state, err := loadReportingState(ctx)
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
			if err := saveReportingState(ctx, newState); err != nil {
				return err
			}
		}
		fmt.Fprintf(w, "ReportingState: %v\n", len(state.Entries)-len(newState.Entries))
		return nil
	}
	return runInTransaction(ctx, tx, nil)
}

func dropEntities(ctx context.Context, keys []*db.Key, dryRun bool) error {
	if dryRun {
		return nil
	}
	for len(keys) != 0 {
		batch := min(len(keys), 100)
		if err := db.DeleteMulti(ctx, keys[:batch]); err != nil {
			return err
		}
		keys = keys[batch:]
	}
	return nil
}

func restartFailedBisections(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
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
		GetAll(ctx, &jobs)
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
		errorTextBytes, _, err := getText(ctx, textError, job.Error)
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
		err = invalidateBisection(ctx, jobKey, true)
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
func updateBugReporting(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		GetAll(ctx, &bugs)
	if err != nil {
		return err
	}
	log.Warningf(ctx, "fetched %v bugs for namespce %v", len(bugs), ns)
	cfg := getNsConfig(ctx, ns)
	var update []*db.Key
	for i, bug := range bugs {
		if len(bug.Reporting) >= len(cfg.Reporting) {
			continue
		}
		update = append(update, keys[i])
	}
	return updateBatch(ctx, update, func(_ *db.Key, bug *Bug) {
		err := bug.updateReportings(ctx, cfg, timeNow(ctx))
		if err != nil {
			panic(err)
		}
	})
}

// updateCrashPriorities regenerates priorities for crashes.
// This has become necessary after the "dashboard: support per-Manager priority" commit.
// For now, the method only considers the crashes referenced from bug origin.
func updateCrashPriorities(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	ns := r.FormValue("ns")
	if ns == "" {
		return fmt.Errorf("no ns parameter")
	}
	bugsCount := 0
	bugPerKey := map[string]*Bug{}
	var crashKeys []*db.Key
	if err := foreachBug(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen).Filter("Namespace=", ns)
	}, func(bug *Bug, key *db.Key) error {
		bugsCount++
		// There'll be duplicate crash IDs.
		crashIDs := map[int64]struct{}{}
		for _, item := range bug.TreeTests.List {
			crashIDs[item.CrashID] = struct{}{}
		}
		for crashID := range crashIDs {
			crashKeys = append(crashKeys, db.NewKey(ctx, "Crash", "", crashID, key))
		}
		bugPerKey[key.String()] = bug
		return nil
	}); err != nil {
		return err
	}
	log.Warningf(ctx, "fetched %d bugs and %v crash keys to update", bugsCount, len(crashKeys))
	return updateBatch(ctx, crashKeys, func(key *db.Key, crash *Crash) {
		bugKey := key.Parent()
		bug := bugPerKey[bugKey.String()]
		build, err := loadBuild(ctx, ns, crash.BuildID)
		if build == nil || err != nil {
			panic(fmt.Sprintf("err: %s, build: %v", err, build))
		}
		crash.UpdateReportingPriority(ctx, build, bug)
	})
}

// setMissingBugFields makes sure all Bug entity fields are present in the database.
// The problem is that, in Datastore, sorting/filtering on a field will only return entries
// where that field is present.
func setMissingBugFields(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	var keys []*db.Key
	// Query everything.
	err := foreachBug(ctx, nil, func(bug *Bug, key *db.Key) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return err
	}
	log.Warningf(ctx, "fetched %v bugs for update", len(keys))
	// Save everything unchanged.
	return updateBatch(ctx, keys, func(_ *db.Key, bug *Bug) {})
}

// adminSendEmail can be used to send an arbitrary message from the bot.
func adminSendEmail(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	msg := &aemail.Message{
		Sender: r.FormValue("from"),
		To:     []string{r.FormValue("to")},
		Body:   r.FormValue("body"),
	}
	return sendEmail(ctx, msg)
}

func updateHeadReproLevel(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return fmt.Errorf("admin only")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var keys []*db.Key
	type reproState struct {
		hasC   bool
		hasSyz bool
	}
	newLevels := map[string]reproState{}
	if err := foreachBug(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Status=", BugStatusOpen)
	}, func(bug *Bug, key *db.Key) error {
		if len(bug.Commits) > 0 {
			return nil
		}
		actualC := false
		actualSyz := false
		reproCrashes, _, err := queryCrashesForBug(ctx, key, 2)
		if err != nil {
			return fmt.Errorf("failed to fetch crashes with repro: %w", err)
		}
		for _, crash := range reproCrashes {
			if crash.ReproIsRevoked {
				continue
			}
			if crash.ReproC > 0 {
				actualC = true
			}
			if crash.ReproSyz > 0 {
				actualSyz = true
			}
		}
		dbHasC := bug.GetHeadReproLevelHasC()
		dbHasSyz := bug.GetHeadReproLevelHasSyz()
		mismatch := (actualC != dbHasC) || (actualSyz != dbHasSyz)
		if mismatch {
			fmt.Fprintf(w, "%v: HeadReproLevel mismatch, actual C/Syz=%t/%t, db C/Syz=%t/%t\n",
				bugLink(bug.keyHash(ctx)), actualC, actualSyz, dbHasC, dbHasSyz)
			newLevels[bug.keyHash(ctx)] = reproState{hasC: actualC, hasSyz: actualSyz}
			keys = append(keys, key)
		}
		return nil
	}); err != nil {
		return err
	}
	return updateBatch(ctx, keys, func(_ *db.Key, bug *Bug) {
		state, ok := newLevels[bug.keyHash(ctx)]
		if !ok {
			panic("fetched unknown bug")
		}
		bug.SetHeadReproLevel(state.hasC, state.hasSyz)
	})
}

func updateBatch[T any](ctx context.Context, keys []*db.Key, transform func(key *db.Key, item *T)) error {
	for len(keys) != 0 {
		batchSize := min(len(keys), 20)
		batchKeys := keys[:batchSize]
		keys = keys[batchSize:]

		tx := func(ctx context.Context) error {
			items := make([]*T, len(batchKeys))
			if err := db.GetMulti(ctx, batchKeys, items); err != nil {
				return err
			}
			for i, item := range items {
				transform(batchKeys[i], item)
			}
			_, err := db.PutMulti(ctx, batchKeys, items)
			return err
		}
		if err := runInTransaction(ctx, tx, &db.TransactionOptions{XG: true}); err != nil {
			return err
		}
		log.Warningf(ctx, "updated %v bugs", len(batchKeys))
	}
	return nil
}

func forceCommitInfoUpdate(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	// Read an optional "?limit=X" parameter from the URL.
	limit := 0
	if limitStr := r.FormValue("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil {
			return fmt.Errorf("invalid limit parameter %q: %w", limitStr, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("limit parameter must be positive")
		}
		limit = parsed
	}

	var keys []*db.Key
	err := foreachBug(ctx, nil, func(bug *Bug, key *db.Key) error {
		if limit > 0 && len(keys) >= limit {
			return nil // Stop accumulating if we hit our requested limit.
		}
		if len(bug.Commits) > 0 && !bug.NeedCommitInfo {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return err
	}

	log.Warningf(ctx, "fetched %v bugs for commit info update", len(keys))
	return updateBatch(ctx, keys, func(_ *db.Key, bug *Bug) {
		bug.NeedCommitInfo = true
	})
}

func handleMigrateReproBools(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if accessLevel(ctx, r) != AccessAdmin {
		return ErrAccess
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	limit := 1000
	if val := r.FormValue("limit"); val != "" {
		l, err := strconv.Atoi(val)
		if err != nil || l <= 0 {
			return fmt.Errorf("limit parameter must be a positive integer")
		}
		limit = l
	}

	var unmigratedKeys []*db.Key
	errStop := errors.New("stop")
	err := foreachBug(ctx, nil, func(bug *Bug, key *db.Key) error {
		if bug.StructVersion == 0 {
			unmigratedKeys = append(unmigratedKeys, key)
			if len(unmigratedKeys) >= limit {
				return errStop
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return err
	}

	if len(unmigratedKeys) == 0 {
		fmt.Fprintf(w, "All bugs already migrated!\n")
		return nil
	}

	err = updateBatch(ctx, unmigratedKeys, func(key *db.Key, bug *Bug) {
		if bug.StructVersion > 0 {
			return
		}
		bug.HasCRepro, bug.HasSyzRepro = reproLevelToCAndSyz(bug.ReproLevel)
		bug.HeadHasCRepro, bug.HeadHasSyzRepro = reproLevelToCAndSyz(bug.HeadReproLevel)

		bug.StructVersion = 1
	})
	if err != nil {
		return fmt.Errorf("migration batch failed: %w", err)
	}

	fmt.Fprintf(w, "Successfully migrated %d bugs.\n", len(unmigratedKeys))
	return nil
}

func reproLevelToCAndSyz(l dashapi.ReproLevel) (hasC, hasSyz bool) {
	switch l {
	case dashapi.ReproLevelC:
		return true, true
	case dashapi.ReproLevelSyz:
		return false, true
	default:
		return false, false
	}
}

func init() {
	// Prevent warnings about dead code.
	runtime.KeepAlive(dropNamespace)
	runtime.KeepAlive(dropEntities)
	runtime.KeepAlive(adminSendEmail)
	runtime.KeepAlive(updateHeadReproLevel)
	runtime.KeepAlive(updateCrashPriorities)
	runtime.KeepAlive(handleMigrateReproBools)
}
