// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/google/syzkaller/pkg/subsystem"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
)

const (
	// We load the top crashesForInference crashes to determine the bug subsystem(s).
	crashesForInference = 5
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

func getSubsystemService(c context.Context, ns string) *subsystem.Service {
	return config.Namespaces[ns].Subsystems.Service
}
