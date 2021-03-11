// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/context"
	db "google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

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
	return db.RunInTransaction(c, tx, nil)
}

func dropEntities(c context.Context, keys []*db.Key, dryRun bool) error {
	if dryRun {
		return nil
	}
	for len(keys) != 0 {
		batch := 100
		if batch > len(keys) {
			batch = len(keys)
		}
		if err := db.DeleteMulti(c, keys[:batch]); err != nil {
			return err
		}
		keys = keys[batch:]
	}
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
	cfg := config.Namespaces[ns]
	var update []*db.Key
	for i, bug := range bugs {
		if len(bug.Reporting) >= len(cfg.Reporting) {
			continue
		}
		update = append(update, keys[i])
	}
	return updateBugBatch(c, update, func(bug *Bug) {
		createBugReporting(bug, cfg)
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
	return updateBugBatch(c, keys, func(bug *Bug) {
		if len(bug.MergedTitles) == 0 {
			bug.MergedTitles = []string{bug.Title}
		}
		if len(bug.AltTitles) == 0 {
			bug.AltTitles = []string{bug.Title}
		}
	})
}

func updateBugBatch(c context.Context, keys []*db.Key, transform func(bug *Bug)) error {
	for len(keys) != 0 {
		batchSize := 20
		if batchSize > len(keys) {
			batchSize = len(keys)
		}
		batchKeys := keys[:batchSize]
		keys = keys[batchSize:]

		tx := func(c context.Context) error {
			bugs := make([]*Bug, len(batchKeys))
			if err := db.GetMulti(c, batchKeys, bugs); err != nil {
				return err
			}
			for _, bug := range bugs {
				transform(bug)
			}
			_, err := db.PutMulti(c, batchKeys, bugs)
			return err
		}
		if err := db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true}); err != nil {
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
)
