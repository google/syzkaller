// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
)

type stats interface {
	Record(input *bugInput)
	Collect() interface{}
}

// statsFilterStruct allows to embed input filtering to stats collection.
type statsFilterStruct struct {
	nested  stats
	filters []statsFilter
}

type statsFilter func(input *bugInput) bool

func newStatsFilter(nested stats, filters ...statsFilter) stats {
	return &statsFilterStruct{nested: nested, filters: filters}
}

func (sf *statsFilterStruct) Record(input *bugInput) {
	for _, filter := range sf.filters {
		if !filter(input) {
			return
		}
	}
	sf.nested.Record(input)
}

func (sf *statsFilterStruct) Collect() interface{} {
	return sf.nested.Collect()
}

// bugInput structure contains the information for collecting all bug-related statistics.
type bugInput struct {
	bug           *Bug
	bugReporting  *BugReporting
	reportedCrash *Crash
	build         *Build
}

func (bi *bugInput) foundAt() time.Time {
	return bi.bug.FirstTime
}

func (bi *bugInput) reportedAt() time.Time {
	if bi.bugReporting == nil {
		return time.Time{}
	}
	return bi.bugReporting.Reported
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

type statsBugState int

const (
	stateOpen statsBugState = iota
	stateDecisionMade
	stateAutoInvalidated
)

func (bi *bugInput) stateAt(date time.Time) statsBugState {
	bug := bi.bug
	closeTime := bug.Closed
	closeStatus := stateDecisionMade
	if at := bi.fixedAt(); !at.IsZero() {
		closeTime = at
	} else if bug.Status == BugStatusInvalid {
		if bi.bugReporting.Auto {
			closeStatus = stateAutoInvalidated
		}
	}
	if closeTime.IsZero() || date.Before(closeTime) {
		return stateOpen
	}
	return closeStatus
}

// Some common bug input filters.

func bugsNoEarlier(since time.Time) statsFilter {
	return func(input *bugInput) bool {
		return input.reportedAt().After(since)
	}
}

func bugsNoLater(now time.Time, days int) statsFilter {
	return func(input *bugInput) bool {
		return now.Sub(input.foundAt()) > time.Hour*24*time.Duration(days)
	}
}

func bugsInReportingStage(name string) statsFilter {
	return func(input *bugInput) bool {
		return input.bugReporting.Name == name
	}
}

func bugsHaveRepro(input *bugInput) bool {
	return input.bug.ReproLevel > 0
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
		if err := getAllMulti(c, crashKeys, func(i, j int) interface{} {
			return crashes[i:j]
		}); err != nil {
			return nil, err
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
		if err := getAllMulti(c, buildKeys, func(i, j int) interface{} {
			return builds[i:j]
		}); err != nil {
			return nil, err
		}
		for i, build := range builds {
			if build != nil {
				buildToInput[buildKeys[i]].build = build
			}
		}
	}
	return inputs, nil
}

func getAllMulti(c context.Context, key []*db.Key, getDst func(from, to int) interface{}) error {
	// Circumventing the datastore multi query limitation.
	const step = 1000
	for from := 0; from < len(key); from += step {
		to := from + step
		if to > len(key) {
			to = len(key)
		}
		if err := db.GetMulti(c, key[from:to], getDst(from, to)); err != nil {
			return err
		}
	}
	return nil
}

type statsCounter struct {
	total int
	match int
}

func (sc *statsCounter) Record(match bool) {
	sc.total++
	if match {
		sc.match++
	}
}

func (sc statsCounter) String() string {
	percent := 0.0
	if sc.total != 0 {
		percent = float64(sc.match) / float64(sc.total) * 100.0
	}
	return fmt.Sprintf("%.2f%% (%d/%d)", percent, sc.match, sc.total)
}

// reactionFactor represents the generic stats collector that measures the effect
// of a single variable on the how it affected the chances of the bug status
// becoming statusDecisionMade in `days` days after reporting.
type reactionFactor struct {
	factorTrue  statsCounter
	factorFalse statsCounter
	days        int
	factorName  string
	factor      statsFilter
}

func newReactionFactor(days int, name string, factor statsFilter) *reactionFactor {
	return &reactionFactor{
		days:       days,
		factorName: name,
		factor:     factor,
	}
}

func (rf *reactionFactor) Record(input *bugInput) {
	reported := input.reportedAt()
	state := input.stateAt(reported.Add(time.Hour * time.Duration(24*rf.days)))
	match := state == stateDecisionMade
	if rf.factor(input) {
		rf.factorTrue.Record(match)
	} else {
		rf.factorFalse.Record(match)
	}
}

func (rf *reactionFactor) Collect() interface{} {
	return [][]string{
		{"", rf.factorName, "No " + rf.factorName},
		{
			fmt.Sprintf("Resolved in %d days", rf.days),
			rf.factorTrue.String(),
			rf.factorFalse.String(),
		},
	}
}

// Some common factors affecting the attention to the bug.

func newStraceEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Strace", func(bi *bugInput) bool {
		if bi.reportedCrash == nil {
			return false
		}
		return dashapi.CrashFlags(bi.reportedCrash.Flags)&dashapi.CrashUnderStrace > 0
	})
}

func newReproEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Repro", func(bi *bugInput) bool {
		return bi.bug.ReproLevel > 0
	})
}

func newAssetEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Build Assets", func(bi *bugInput) bool {
		if bi.build == nil {
			return false
		}
		return len(bi.build.Assets) > 0
	})
}

func newBisectCauseEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Successful Cause Bisection", func(bi *bugInput) bool {
		return bi.bug.BisectCause == BisectYes
	})
}
