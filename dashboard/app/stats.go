// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/stats/syzbotstats"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
)

// bugInput structure contains the information for collecting all bug-related statistics.
type bugInput struct {
	bug           *Bug
	bugReporting  *BugReporting
	reportedCrash *Crash
	build         *Build
}

func (bi *bugInput) fixedAt() time.Time {
	closeTime := time.Time{}
	if bi.bug.Status == BugStatusFixed {
		closeTime = bi.bug.Closed
	}
	for _, commit := range bi.bug.CommitInfo {
		if closeTime.IsZero() || closeTime.After(commit.Date) {
			closeTime = commit.Date
		}
	}
	return closeTime
}

func (bi *bugInput) bugStatus() (syzbotstats.BugStatus, error) {
	if bi.bug.Status == BugStatusFixed ||
		bi.bug.Closed.IsZero() && len(bi.bug.Commits) > 0 {
		return syzbotstats.BugFixed, nil
	} else if bi.bug.Closed.IsZero() {
		return syzbotstats.BugPending, nil
	} else if bi.bug.Status == BugStatusDup {
		return syzbotstats.BugDup, nil
	} else if bi.bug.Status == BugStatusInvalid {
		if bi.bugReporting.Auto {
			return syzbotstats.BugAutoInvalidated, nil
		} else {
			return syzbotstats.BugInvalidated, nil
		}
	}
	return "", fmt.Errorf("cannot determine status")
}

// allBugInputs queries the raw data about all bugs from a namespace.
func allBugInputs(c context.Context, ns string) ([]*bugInput, error) {
	filter := func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns)
	}
	inputs := []*bugInput{}
	bugs, bugKeys, err := loadAllBugs(c, filter)
	if err != nil {
		return nil, err
	}

	crashKeys := []*db.Key{}
	crashToInput := map[*db.Key]*bugInput{}
	for i, bug := range bugs {
		bugReporting := lastReportedReporting(bug)
		input := &bugInput{
			bug:          bug,
			bugReporting: bugReporting,
		}
		if bugReporting.CrashID != 0 {
			crashKey := db.NewKey(c, "Crash", "", bugReporting.CrashID, bugKeys[i])
			crashKeys = append(crashKeys, crashKey)
			crashToInput[crashKey] = input
		}
		inputs = append(inputs, input)
	}
	// Fetch crashes.
	buildKeys := []*db.Key{}
	buildToInput := map[*db.Key]*bugInput{}
	if len(crashKeys) > 0 {
		crashes := make([]*Crash, len(crashKeys))
		if badKey, err := getAllMulti(c, crashKeys, crashes); err != nil {
			return nil, fmt.Errorf("failed to fetch crashes for %v: %w", badKey, err)
		}
		for i, crash := range crashes {
			if crash == nil {
				continue
			}
			input := crashToInput[crashKeys[i]]
			input.reportedCrash = crash

			buildKey := buildKey(c, ns, crash.BuildID)
			buildKeys = append(buildKeys, buildKey)
			buildToInput[buildKey] = input
		}
	}
	// Fetch builds.
	if len(buildKeys) > 0 {
		builds := make([]*Build, len(buildKeys))
		if badKey, err := getAllMulti(c, buildKeys, builds); err != nil {
			return nil, fmt.Errorf("failed to fetch builds for %v: %w", badKey, err)
		}
		for i, build := range builds {
			if build != nil {
				buildToInput[buildKeys[i]].build = build
			}
		}
	}
	return inputs, nil
}

// Circumventing the datastore's multi query limitation.
func getAllMulti[T any](c context.Context, keys []*db.Key, objects []*T) (*db.Key, error) {
	const step = 1000
	for from := 0; from < len(keys); from += step {
		to := from + step
		if to > len(keys) {
			to = len(keys)
		}
		err := db.GetMulti(c, keys[from:to], objects[from:to])
		if err == nil {
			continue
		}
		var merr appengine.MultiError
		if errors.As(err, &merr) {
			for i, objErr := range merr {
				if objErr != nil {
					return keys[from+i], objErr
				}
			}
		}
		return nil, err
	}
	return nil, nil
}

// getBugSummaries extracts the list of BugStatSummary objects among bugs
// that reached the specific reporting stage.
func getBugSummaries(c context.Context, ns, stage string) ([]*syzbotstats.BugStatSummary, error) {
	inputs, err := allBugInputs(c, ns)
	if err != nil {
		return nil, err
	}
	var ret []*syzbotstats.BugStatSummary
	for _, input := range inputs {
		bug, crash := input.bug, input.reportedCrash
		if crash == nil {
			continue
		}
		targetStage := bugReportingByName(bug, stage)
		if targetStage == nil || targetStage.Reported.IsZero() {
			continue
		}
		obj := &syzbotstats.BugStatSummary{
			Title:        bug.Title,
			FirstTime:    bug.FirstTime,
			ReleasedTime: targetStage.Reported,
			ResolvedTime: bug.Closed,
			HappenedOn:   bug.HappenedOn,
			Strace:       dashapi.CrashFlags(crash.Flags)&dashapi.CrashUnderStrace > 0,
		}
		for _, stage := range bug.Reporting {
			if stage.ID != "" {
				obj.IDs = append(obj.IDs, stage.ID)
			}
		}
		for _, commit := range bug.CommitInfo {
			obj.FixHashes = append(obj.FixHashes, commit.Hash)
		}
		if crash.ReproSyz > 0 {
			obj.ReproTime = crash.Time
		}
		if bug.BisectCause == BisectYes {
			causeBisect, err := queryBestBisection(c, bug, JobBisectCause)
			if err != nil {
				return nil, err
			}
			if causeBisect != nil {
				obj.CauseBisectTime = causeBisect.job.Finished
			}
		}
		fixTime := input.fixedAt()
		if !fixTime.IsZero() && (obj.ResolvedTime.IsZero() || fixTime.Before(obj.ResolvedTime)) {
			// Take the date of the fixing commit, if it's earlier.
			obj.ResolvedTime = fixTime
		}
		obj.Status, err = input.bugStatus()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", bug.Title, err)
		}

		const minAvgHitCrashes = 5
		const minAvgHitPeriod = time.Hour * 24
		if bug.NumCrashes >= minAvgHitCrashes ||
			bug.LastTime.Sub(bug.FirstTime) < minAvgHitPeriod {
			// If there are only a few crashes or they all happened within a single day,
			// it's hard to make any accurate frequency estimates.
			timeSpan := bug.LastTime.Sub(bug.FirstTime)
			obj.HitsPerDay = float64(bug.NumCrashes) / (timeSpan.Hours() / 24)
		}

		for _, label := range bug.LabelValues(SubsystemLabel) {
			obj.Subsystems = append(obj.Subsystems, label.Value)
		}

		ret = append(ret, obj)
	}
	return ret, nil
}
