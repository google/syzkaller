// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

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
	var batchKeys []*db.Key
	const batchSize = 20
	for i, bug := range bugs {
		if len(bug.Reporting) >= len(cfg.Reporting) {
			continue
		}
		batchKeys = append(batchKeys, keys[i])
		if len(batchKeys) == batchSize {
			if err := updateBugReportingBatch(c, cfg, batchKeys); err != nil {
				return err
			}
			batchKeys = nil
		}
	}
	if len(batchKeys) != 0 {
		if err := updateBugReportingBatch(c, cfg, batchKeys); err != nil {
			return err
		}
	}
	return nil
}

func updateBugReportingBatch(c context.Context, cfg *Config, keys []*db.Key) error {
	tx := func(c context.Context) error {
		bugs := make([]*Bug, len(keys))
		if err := db.GetMulti(c, keys, bugs); err != nil {
			return err
		}
		for _, bug := range bugs {
			createBugReporting(bug, cfg)
		}
		_, err := db.PutMulti(c, keys, bugs)
		return err
	}
	err := db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true})
	log.Warningf(c, "updated %v bugs: %v", len(keys), err)
	return err
}

// Prevent warnings about dead code.
var (
	_ = dropNamespace
	_ = updateBugReporting
)
