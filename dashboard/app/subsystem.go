// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/subsystem"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// reassignBugSubsystems is expected to be periodically called to refresh old automatic
// subsystem assignments.
func reassignBugSubsystems(c context.Context, ns string, count int) error {
	service := getSubsystemService(c, ns)
	if service == nil {
		return nil
	}
	bugs, keys, err := bugsToUpdateSubsystems(c, ns, count)
	if err != nil {
		return err
	}
	log.Infof(c, "updating subsystems for %d bugs in %#v", len(keys), ns)
	rev := getSubsystemRevision(c, ns)
	for i, bugKey := range keys {
		if bugs[i].hasUserSubsystems() {
			// It might be that the user-set subsystem no longer exists.
			// For now let's just log an error in this case.
			checkOutdatedSubsystems(c, service, bugs[i])
			// If we don't set the latst revision, we'll have to update this
			// bug over and over again.
			err = updateBugSubsystems(c, bugKey, nil, updateRevision(rev))
		} else {
			var list []*subsystem.Subsystem
			list, err = inferSubsystems(c, bugs[i], bugKey)
			if err != nil {
				return fmt.Errorf("failed to infer subsystems: %w", err)
			}
			err = updateBugSubsystems(c, bugKey, list, autoInference(rev))
		}
		if err != nil {
			return fmt.Errorf("failed to save subsystems: %w", err)
		}
	}
	return nil
}

func bugsToUpdateSubsystems(c context.Context, ns string, count int) ([]*Bug, []*db.Key, error) {
	now := timeNow(c)
	rev := getSubsystemRevision(c, ns)
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
		// And, finally, let's consider the update of closed bugs.
		db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusFixed).
			Filter("SubsystemsRev<", rev),
	}
	var bugs []*Bug
	var keys []*db.Key
	for i, query := range queries {
		if count <= 0 {
			break
		}
		var tmpBugs []*Bug
		tmpKeys, err := query.Limit(count).GetAll(c, &tmpBugs)
		if err != nil {
			return nil, nil, fmt.Errorf("query %d failed: %s", i, err)
		}
		bugs = append(bugs, tmpBugs...)
		keys = append(keys, tmpKeys...)
		count -= len(tmpKeys)
	}
	return bugs, keys, nil
}

func checkOutdatedSubsystems(c context.Context, service *subsystem.Service, bug *Bug) {
	for _, item := range bug.Tags.Subsystems {
		if service.ByName(item.Name) == nil {
			log.Errorf(c, "ns=%s bug=%s subsystem %s no longer exists", bug.Namespace, bug.Title, item.Name)
		}
	}
}

type (
	autoInference  int
	userAssignment string
	updateRevision int
)

func updateBugSubsystems(c context.Context, bugKey *db.Key,
	list []*subsystem.Subsystem, info interface{}) error {
	now := timeNow(c)
	tx := func(c context.Context) error {
		bug := new(Bug)
		if err := db.Get(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to get bug: %v", err)
		}
		switch v := info.(type) {
		case autoInference:
			bug.SetAutoSubsystems(list, now, int(v))
		case userAssignment:
			bug.SetUserSubsystems(list, now, string(v))
		case updateRevision:
			bug.SubsystemsRev = int(v)
			bug.SubsystemsTime = now
		}
		if _, err := db.Put(c, bugKey, bug); err != nil {
			return fmt.Errorf("failed to put bug: %v", err)
		}
		return nil
	}
	return db.RunInTransaction(c, tx, &db.TransactionOptions{Attempts: 10})
}

const (
	// We load the top crashesForInference crashes to determine the bug subsystem(s).
	crashesForInference = 5
	// How often we update open bugs.
	openBugsUpdateTime = time.Hour * 24 * 30
)

// inferSubsystems determines the best yet possible estimate of the bug's subsystems.
func inferSubsystems(c context.Context, bug *Bug, bugKey *db.Key) ([]*subsystem.Subsystem, error) {
	service := getSubsystemService(c, bug.Namespace)
	if service == nil {
		// There's nothing we can do.
		return nil, nil
	}
	dbCrashes, dbCrashKeys, err := queryCrashesForBug(c, bugKey, crashesForInference)
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
			crash.SyzRepro, _, err = getText(c, textReproSyz, dbCrash.ReproSyz)
			if err != nil {
				return nil, fmt.Errorf("failed to load syz repro for %s: %w",
					dbCrashKeys[i], err)
			}
		}
		crashes = append(crashes, crash)
	}
	return service.Extract(crashes), nil
}

// subsystemMaintainers queries the list of emails to send the bug to.
func subsystemMaintainers(c context.Context, ns, subsystemName string) []string {
	service := getSubsystemService(c, ns)
	if service == nil {
		return nil
	}
	item := service.ByName(subsystemName)
	if item == nil {
		return nil
	}
	return item.Emails()
}

var subsystemsListKey = "custom list of kernel subsystems"

type customSubsystemList struct {
	ns       string
	list     []*subsystem.Subsystem
	revision int
}

func contextWithSubsystems(c context.Context, custom *customSubsystemList) context.Context {
	return context.WithValue(c, &subsystemsListKey, custom)
}

func getSubsystemService(c context.Context, ns string) *subsystem.Service {
	// This is needed to emulate changes to the subsystem list over time during testing.
	if val, ok := c.Value(&subsystemsListKey).(*customSubsystemList); ok && val.ns == ns {
		if len(val.list) == 0 {
			return nil
		} else {
			return subsystem.MustMakeService(val.list)
		}
	}
	return config.Namespaces[ns].Subsystems.Service
}

func getSubsystemRevision(c context.Context, ns string) int {
	if val, ok := c.Value(&subsystemsListKey).(*customSubsystemList); ok && val.ns == ns {
		return val.revision
	}
	return config.Namespaces[ns].Subsystems.Revision
}
