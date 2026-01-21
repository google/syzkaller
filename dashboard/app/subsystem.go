// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/subsystem"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// reassignBugSubsystems is expected to be periodically called to refresh old automatic
// subsystem assignments.
func reassignBugSubsystems(ctx context.Context, ns string, count int) error {
	service := getNsConfig(ctx, ns).Subsystems.Service
	if service == nil {
		return nil
	}
	bugs, keys, err := bugsToUpdateSubsystems(ctx, ns, count)
	if err != nil {
		return err
	}
	log.Infof(ctx, "updating subsystems for %d bugs in %#v", len(keys), ns)
	rev := service.Revision
	for i, bugKey := range keys {
		if bugs[i].hasUserSubsystems() {
			// It might be that the user-set subsystem no longer exists.
			// For now let's just log an error in this case.
			checkOutdatedSubsystems(ctx, service, bugs[i])
			// If we don't set the latst revision, we'll have to update this
			// bug over and over again.
			err = updateBugSubsystems(ctx, bugKey, nil, updateRevision(rev))
		} else {
			var list []*subsystem.Subsystem
			list, err = inferSubsystems(ctx, bugs[i], bugKey, &debugtracer.NullTracer{})
			if err != nil {
				return fmt.Errorf("failed to infer subsystems: %w", err)
			}
			err = updateBugSubsystems(ctx, bugKey, list, autoInference(rev))
		}
		if err != nil {
			return fmt.Errorf("failed to save subsystems: %w", err)
		}
	}
	return nil
}

func bugsToUpdateSubsystems(ctx context.Context, ns string, count int) ([]*Bug, []*db.Key, error) {
	now := timeNow(ctx)
	rev := getSubsystemService(ctx, ns).Revision
	queries := []*db.Query{
		// If revision has been updated, first update open bugs.
		db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("SubsystemsRev<", rev),
		// The next priority is the regular update of open bugs.
		db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("SubsystemsTime<", now.Add(-openBugsUpdateTime)),
		// Then let's consider the update of closed bugs.
		db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusFixed).
			Filter("SubsystemsRev<", rev),
		// And, at the end, everything else.
		db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("SubsystemsRev<", rev),
	}
	var bugs []*Bug
	var keys []*db.Key
	for i, query := range queries {
		if count <= 0 {
			break
		}
		var tmpBugs []*Bug
		tmpKeys, err := query.Limit(count).GetAll(ctx, &tmpBugs)
		if err != nil {
			return nil, nil, fmt.Errorf("query %d failed: %w", i, err)
		}
		bugs = append(bugs, tmpBugs...)
		keys = append(keys, tmpKeys...)
		count -= len(tmpKeys)
	}
	return bugs, keys, nil
}

func checkOutdatedSubsystems(ctx context.Context, service *subsystem.Service, bug *Bug) {
	for _, item := range bug.LabelValues(SubsystemLabel) {
		if service.ByName(item.Value) == nil {
			log.Errorf(ctx, "ns=%s bug=%s subsystem %s no longer exists", bug.Namespace, bug.Title, item.Value)
		}
	}
}

type (
	autoInference  int
	updateRevision int
)

func updateBugSubsystems(ctx context.Context, bugKey *db.Key,
	list []*subsystem.Subsystem, info any) error {
	now := timeNow(ctx)
	return updateSingleBug(ctx, bugKey, func(bug *Bug) error {
		switch v := info.(type) {
		case autoInference:
			logSubsystemChange(ctx, bug, list)
			bug.SetAutoSubsystems(ctx, list, now, int(v))
		case updateRevision:
			bug.SubsystemsRev = int(v)
			bug.SubsystemsTime = now
		}
		return nil
	})
}

func logSubsystemChange(ctx context.Context, bug *Bug, new []*subsystem.Subsystem) {
	var oldNames, newNames []string
	for _, item := range bug.LabelValues(SubsystemLabel) {
		oldNames = append(oldNames, item.Value)
	}
	for _, item := range new {
		newNames = append(newNames, item.Name)
	}
	sort.Strings(oldNames)
	sort.Strings(newNames)
	if !reflect.DeepEqual(oldNames, newNames) {
		log.Infof(ctx, "bug %s: subsystems set from %v to %v",
			bug.keyHash(ctx), oldNames, newNames)
	}
}

const (
	// We load the top crashesForInference crashes to determine the bug subsystem(s).
	crashesForInference = 7
	// How often we update open bugs.
	openBugsUpdateTime = time.Hour * 24 * 30
)

// inferSubsystems determines the best yet possible estimate of the bug's subsystems.
func inferSubsystems(ctx context.Context, bug *Bug, bugKey *db.Key,
	tracer debugtracer.DebugTracer) ([]*subsystem.Subsystem, error) {
	service := getSubsystemService(ctx, bug.Namespace)
	if service == nil {
		// There's nothing we can do.
		return nil, nil
	}
	dbCrashes, dbCrashKeys, err := queryCrashesForBug(ctx, bugKey, crashesForInference)
	if err != nil {
		return nil, err
	}
	crashes := []*subsystem.Crash{}
	for i, dbCrash := range dbCrashes {
		crash := &subsystem.Crash{}
		if len(dbCrash.ReportElements.GuiltyFiles) > 0 {
			// For now we anyway only store one.
			crash.GuiltyPath = dbCrash.ReportElements.GuiltyFiles[0]
		}
		if dbCrash.ReproSyz != 0 {
			crash.SyzRepro, _, err = getText(ctx, textReproSyz, dbCrash.ReproSyz)
			if err != nil {
				return nil, fmt.Errorf("failed to load syz repro for %s: %w",
					dbCrashKeys[i], err)
			}
		}
		crashes = append(crashes, crash)
	}
	return service.TracedExtract(crashes, tracer), nil
}

// subsystemMaintainers queries the list of emails to send the bug to.
func subsystemMaintainers(ctx context.Context, ns, subsystemName string) []string {
	service := getNsConfig(ctx, ns).Subsystems.Service
	if service == nil {
		return nil
	}
	item := service.ByName(subsystemName)
	if item == nil {
		return nil
	}
	return item.Emails()
}

func getSubsystemService(ctx context.Context, ns string) *subsystem.Service {
	return getNsConfig(ctx, ns).Subsystems.Service
}

func subsystemListURL(ctx context.Context, ns string) string {
	if getNsConfig(ctx, ns).Subsystems.Service == nil {
		return ""
	}
	return fmt.Sprintf("%v/%v/subsystems?all=true", appURL(ctx), ns)
}
