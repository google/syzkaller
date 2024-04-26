// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/hash"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// reportingPollBugLists is called by backends to get bug lists that need to be reported.
func reportingPollBugLists(c context.Context, typ string) []*dashapi.BugListReport {
	state, err := loadReportingState(c)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	registry, err := makeSubsystemReportRegistry(c)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	ret := []*dashapi.BugListReport{}
	for ns, nsConfig := range getConfig(c).Namespaces {
		rConfig := nsConfig.Subsystems.Reminder
		if rConfig == nil {
			continue
		}
		reporting := nsConfig.ReportingByName(rConfig.SourceReporting)
		stateEntry := state.getEntry(timeNow(c), ns, reporting.Name)
		// The DB might well contain info about stale entities, but by querying the latest
		// list of subsystems from the configuration, we make sure we only consider what's
		// currently relevant.
		rawSubsystems := nsConfig.Subsystems.Service.List()
		// Sort to keep output stable.
		sort.Slice(rawSubsystems, func(i, j int) bool {
			return rawSubsystems[i].Name < rawSubsystems[j].Name
		})
		for _, entry := range rawSubsystems {
			if entry.NoReminders {
				continue
			}
			for _, dbReport := range registry.get(ns, entry.Name) {
				if stateEntry.Sent >= reporting.DailyLimit {
					break
				}
				report, err := reportingBugListReport(c, dbReport, ns, entry.Name, typ)
				if err != nil {
					log.Errorf(c, "%v", err)
					return nil
				}
				if report != nil {
					ret = append(ret, report)
					stateEntry.Sent++
				}
			}
		}
	}
	return ret
}

const maxNewListsPerNs = 5

// handleSubsystemReports is periodically invoked to construct fresh SubsystemReport objects.
func handleSubsystemReports(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	registry, err := makeSubsystemRegistry(c)
	if err != nil {
		log.Errorf(c, "failed to load subsystems: %v", err)
		return
	}
	for ns, nsConfig := range getConfig(c).Namespaces {
		rConfig := nsConfig.Subsystems.Reminder
		if rConfig == nil {
			continue
		}
		minPeriod := 24 * time.Hour * time.Duration(rConfig.PeriodDays)
		reporting := nsConfig.ReportingByName(rConfig.SourceReporting)
		var subsystems []*Subsystem
		for _, entry := range nsConfig.Subsystems.Service.List() {
			if entry.NoReminders {
				continue
			}
			subsystems = append(subsystems, registry.get(ns, entry.Name))
		}
		// Poll subsystems in a round-robin manner.
		sort.Slice(subsystems, func(i, j int) bool {
			return subsystems[i].ListsQueried.Before(subsystems[j].ListsQueried)
		})
		updateLimit := maxNewListsPerNs
		for _, subsystem := range subsystems {
			if updateLimit == 0 {
				break
			}
			if timeNow(c).Before(subsystem.LastBugList.Add(minPeriod)) {
				continue
			}
			report, err := querySubsystemReport(c, subsystem, reporting, rConfig)
			if err != nil {
				log.Errorf(c, "failed to query bug lists: %v", err)
				return
			}
			if err := registry.updatePoll(c, subsystem, report != nil); err != nil {
				log.Errorf(c, "failed to update subsystem: %v", err)
				return
			}
			if report == nil {
				continue
			}
			updateLimit--
			if err := storeSubsystemReport(c, subsystem, report); err != nil {
				log.Errorf(c, "failed to save subsystem: %v", err)
				return
			}
		}
	}
}

func reportingBugListCommand(c context.Context, cmd *dashapi.BugListUpdate) (string, error) {
	// We have to execute it outside of the transacation, otherwise we get the
	// "Only ancestor queries are allowed inside transactions." error.
	subsystem, rawReport, _, err := findSubsystemReportByID(c, cmd.ID)
	if err != nil {
		return "", err
	}
	if subsystem == nil {
		return "", fmt.Errorf("the bug list was not found")
	}
	reply := ""
	tx := func(c context.Context) error {
		subsystemKey := subsystemKey(c, subsystem)
		reportKey := subsystemReportKey(c, subsystemKey, rawReport)
		report := new(SubsystemReport)
		if err := db.Get(c, reportKey, report); err != nil {
			return fmt.Errorf("failed to query SubsystemReport (%v): %w", reportKey, err)
		}
		stage := report.findStage(cmd.ID)
		if stage.ExtID == "" {
			stage.ExtID = cmd.ExtID
		}
		if stage.Link == "" {
			stage.Link = cmd.Link
		}
		// It might e.g. happen that we skipped a stage in reportingBugListReport.
		// Make sure all skipped stages have non-nil Closed.
		for i := range report.Stages {
			item := &report.Stages[i]
			if cmd.Command != dashapi.BugListRegenerateCmd && item == stage {
				break
			}
			item.Closed = timeNow(c)
		}
		switch cmd.Command {
		case dashapi.BugListSentCmd:
			if !stage.Reported.IsZero() {
				return fmt.Errorf("the reporting stage was already reported")
			}
			stage.Reported = timeNow(c)

			state, err := loadReportingState(c)
			if err != nil {
				return fmt.Errorf("failed to query state: %w", err)
			}
			stateEnt := state.getEntry(timeNow(c), subsystem.Namespace,
				getConfig(c).Namespaces[subsystem.Namespace].Subsystems.Reminder.SourceReporting)
			stateEnt.Sent++
			if err := saveReportingState(c, state); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		case dashapi.BugListUpstreamCmd:
			if !stage.Moderation {
				reply = `The report cannot be sent further upstream.
It's already at the last reporting stage.`
				return nil
			}
			if !stage.Closed.IsZero() {
				reply = `The bug list was already upstreamed.
Please visit the new discussion thread.`
				return nil
			}
			stage.Closed = timeNow(c)
		case dashapi.BugListRegenerateCmd:
			dbSubsystem := new(Subsystem)
			err := db.Get(c, subsystemKey, dbSubsystem)
			if err != nil {
				return fmt.Errorf("failed to get subsystem: %w", err)
			}
			dbSubsystem.LastBugList = time.Time{}
			_, err = db.Put(c, subsystemKey, dbSubsystem)
			if err != nil {
				return fmt.Errorf("failed to save subsystem: %w", err)
			}
		}
		_, err = db.Put(c, reportKey, report)
		if err != nil {
			return fmt.Errorf("failed to save the object: %w", err)
		}
		return nil
	}
	return reply, db.RunInTransaction(c, tx, &db.TransactionOptions{
		XG:       true,
		Attempts: 10,
	})
}

func findSubsystemReportByID(c context.Context, ID string) (*Subsystem,
	*SubsystemReport, *SubsystemReportStage, error) {
	var subsystemReports []*SubsystemReport
	reportKeys, err := db.NewQuery("SubsystemReport").
		Filter("Stages.ID=", ID).
		Limit(1).
		GetAll(c, &subsystemReports)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to query subsystem reports: %w", err)
	}
	if len(subsystemReports) == 0 {
		return nil, nil, nil, nil
	}
	stage := subsystemReports[0].findStage(ID)
	if stage == nil {
		// This should never happen (provided that all the code is correct).
		return nil, nil, nil, fmt.Errorf("bug list is found, but the stage is missing")
	}
	subsystem := new(Subsystem)
	if err := db.Get(c, reportKeys[0].Parent(), subsystem); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to query subsystem: %w", err)
	}
	return subsystem, subsystemReports[0], stage, nil
}

// querySubsystemReport queries the open bugs and constructs a new SubsystemReport object.
func querySubsystemReport(c context.Context, subsystem *Subsystem, reporting *Reporting,
	config *BugListReportingConfig) (*SubsystemReport, error) {
	rawOpenBugs, fixedBugs, err := queryMatchingBugs(c, subsystem.Namespace,
		subsystem.Name, reporting)
	if err != nil {
		return nil, err
	}
	withRepro, noRepro := []*Bug{}, []*Bug{}
	for _, bug := range rawOpenBugs {
		const possiblyFixedTimespan = 24 * time.Hour * 14
		if bug.LastTime.Before(timeNow(c).Add(-possiblyFixedTimespan)) {
			// The bug didn't happen recently, possibly it was already fixed.
			// Let's not display such bugs in reminders.
			continue
		}
		if bug.FirstTime.After(timeNow(c).Add(-config.MinBugAge)) {
			// Don't take bugs which are too new -- they're still fresh in memory.
			continue
		}
		if bug.prio() == LowPrioBug {
			// Don't include low priority bugs in reports because the community
			// actually perceives them as non-actionable.
			continue
		}
		discussions := bug.discussionSummary()
		if discussions.ExternalMessages > 0 &&
			discussions.LastMessage.After(timeNow(c).Add(-config.UserReplyFrist)) {
			// Don't take bugs with recent user replies.
			// As we don't keep exactly the date of the last user message, approximate it.
			continue
		}
		if bug.HasLabel(NoRemindersLabel, "") {
			// The bug was intentionally excluded from monthly reminders.
			continue
		}
		if bug.ReproLevel == dashapi.ReproLevelNone {
			noRepro = append(noRepro, bug)
		} else {
			withRepro = append(withRepro, bug)
		}
	}
	// Let's reduce noise and don't remind about just one bug.
	if len(noRepro)+len(withRepro) < config.MinBugsCount {
		return nil, nil
	}
	// Even if we have enough bugs with a reproducer, there might still be bugs
	// without a reproducer that have a lot of crashes. So let's take a small number
	// of such bugs and give them a chance to be present in the final list.
	takeNoRepro := 2
	if takeNoRepro+len(withRepro) < config.BugsInReport {
		takeNoRepro = config.BugsInReport - len(withRepro)
	}
	if takeNoRepro > len(noRepro) {
		takeNoRepro = len(noRepro)
	}
	sort.Slice(noRepro, func(i, j int) bool {
		return noRepro[i].NumCrashes > noRepro[j].NumCrashes
	})
	takeBugs := append(withRepro, noRepro[:takeNoRepro]...)
	sort.Slice(takeBugs, func(i, j int) bool {
		firstPrio, secondPrio := takeBugs[i].prio(), takeBugs[j].prio()
		if firstPrio != secondPrio {
			return !firstPrio.LessThan(secondPrio)
		}
		if takeBugs[i].NumCrashes != takeBugs[j].NumCrashes {
			return takeBugs[i].NumCrashes > takeBugs[j].NumCrashes
		}
		return takeBugs[i].Title < takeBugs[j].Title
	})
	keys := []*db.Key{}
	for _, bug := range takeBugs {
		keys = append(keys, bug.key(c))
	}
	if len(keys) > config.BugsInReport {
		keys = keys[:config.BugsInReport]
	}
	report := makeSubsystemReport(c, config, keys)
	report.TotalStats = makeSubsystemReportStats(c, rawOpenBugs, fixedBugs, 0)
	report.PeriodStats = makeSubsystemReportStats(c, rawOpenBugs, fixedBugs, config.PeriodDays)
	return report, nil
}

func makeSubsystemReportStats(c context.Context, open, fixed []*Bug, days int) SubsystemReportStats {
	after := timeNow(c).Add(-time.Hour * 24 * time.Duration(days))
	ret := SubsystemReportStats{}
	for _, bug := range open {
		if days > 0 && bug.FirstTime.Before(after) {
			continue
		}
		if bug.prio() == LowPrioBug {
			ret.LowPrio++
		} else {
			ret.Reported++
		}
	}
	for _, bug := range fixed {
		if len(bug.CommitInfo) == 0 {
			continue
		}
		if days > 0 && bug.CommitInfo[0].Date.Before(after) {
			continue
		}
		ret.Fixed++
	}
	return ret
}

func queryMatchingBugs(c context.Context, ns, name string, reporting *Reporting) ([]*Bug, []*Bug, error) {
	allOpenBugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("Labels.Label=", SubsystemLabel).
			Filter("Labels.Value=", name)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query open bugs for subsystem: %w", err)
	}
	allFixedBugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns).
			Filter("Status=", BugStatusFixed).
			Filter("Labels.Label=", SubsystemLabel).
			Filter("Labels.Value=", name)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query fixed bugs for subsystem: %w", err)
	}
	open, fixed := []*Bug{}, []*Bug{}
	for _, bug := range append(allOpenBugs, allFixedBugs...) {
		if len(bug.Commits) != 0 || bug.Status == BugStatusFixed {
			// This bug is no longer really open.
			fixed = append(fixed, bug)
			continue
		}
		currReporting, _, _, _, err := currentReporting(c, bug)
		if err != nil {
			continue
		}
		if reporting.Name != currReporting.Name {
			// The bug is not at the expected reporting stage.
			continue
		}
		if currReporting.AccessLevel > reporting.AccessLevel {
			continue
		}
		open = append(open, bug)
	}
	return open, fixed, nil
}

// makeSubsystemReport creates a new SubsystemReminder object.
func makeSubsystemReport(c context.Context, config *BugListReportingConfig,
	keys []*db.Key) *SubsystemReport {
	ret := &SubsystemReport{
		Created: timeNow(c),
	}
	for _, key := range keys {
		ret.BugKeys = append(ret.BugKeys, key.Encode())
	}
	baseID := hash.String([]byte(fmt.Sprintf("%v-%v", timeNow(c), ret.BugKeys)))
	if config.ModerationConfig != nil {
		ret.Stages = append(ret.Stages, SubsystemReportStage{
			ID:         bugListReportingHash(baseID, "moderation"),
			Moderation: true,
		})
	}
	ret.Stages = append(ret.Stages, SubsystemReportStage{
		ID: bugListReportingHash(baseID, "public"),
	})
	return ret
}

const bugListHashPrefix = "list"

func bugListReportingHash(base, name string) string {
	return bugListHashPrefix + bugReportingHash(base, name)
}

func isBugListHash(hash string) bool {
	return strings.HasPrefix(hash, bugListHashPrefix)
}

func reportingBugListReport(c context.Context, subsystemReport *SubsystemReport,
	ns, name, targetReportingType string) (*dashapi.BugListReport, error) {
	for _, stage := range subsystemReport.Stages {
		if !stage.Closed.IsZero() {
			continue
		}
		repConfig := bugListReportingConfig(c, ns, &stage)
		if repConfig == nil {
			// It might happen if e.g. Moderation was set to nil.
			// Just skip the stage then.
			continue
		}
		if !stage.Reported.IsZero() || repConfig.Type() != targetReportingType {
			break
		}
		configJSON, err := json.Marshal(repConfig)
		if err != nil {
			return nil, err
		}
		ret := &dashapi.BugListReport{
			ID:          stage.ID,
			Created:     subsystemReport.Created,
			Config:      configJSON,
			Link:        fmt.Sprintf("%v/%s/s/%s", appURL(c), ns, name),
			Subsystem:   name,
			Maintainers: subsystemMaintainers(c, ns, name),
			Moderation:  stage.Moderation,
			TotalStats:  subsystemReport.TotalStats.toDashapi(),
			PeriodStats: subsystemReport.PeriodStats.toDashapi(),
			PeriodDays:  getNsConfig(c, ns).Subsystems.Reminder.PeriodDays,
		}
		bugKeys, err := subsystemReport.getBugKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to get bug keys: %w", err)
		}
		bugs := make([]*Bug, len(bugKeys))
		err = db.GetMulti(c, bugKeys, bugs)
		if err != nil {
			return nil, fmt.Errorf("failed to get bugs: %w", err)
		}
		for _, bug := range bugs {
			bugReporting := bugReportingByName(bug,
				getNsConfig(c, ns).Subsystems.Reminder.SourceReporting)
			ret.Bugs = append(ret.Bugs, dashapi.BugListItem{
				Title:      bug.displayTitle(),
				Link:       fmt.Sprintf("%v/bug?extid=%v", appURL(c), bugReporting.ID),
				ReproLevel: bug.ReproLevel,
				Hits:       bug.NumCrashes,
			})
		}
		return ret, nil
	}
	return nil, nil
}

func bugListReportingConfig(c context.Context, ns string, stage *SubsystemReportStage) ReportingType {
	cfg := getNsConfig(c, ns).Subsystems.Reminder
	if stage.Moderation {
		return cfg.ModerationConfig
	}
	return cfg.Config
}

func makeSubsystem(ns, name string) *Subsystem {
	return &Subsystem{
		Namespace: ns,
		Name:      name,
	}
}

func subsystemKey(c context.Context, s *Subsystem) *db.Key {
	return db.NewKey(c, "Subsystem", fmt.Sprintf("%v-%v", s.Namespace, s.Name), 0, nil)
}

func subsystemReportKey(c context.Context, subsystemKey *db.Key, r *SubsystemReport) *db.Key {
	return db.NewKey(c, "SubsystemReport", r.Created.UTC().Format(time.RFC822), 0, subsystemKey)
}

type subsystemsRegistry struct {
	entities map[string]map[string]*Subsystem
}

func makeSubsystemRegistry(c context.Context) (*subsystemsRegistry, error) {
	var subsystems []*Subsystem
	if _, err := db.NewQuery("Subsystem").GetAll(c, &subsystems); err != nil {
		return nil, err
	}
	ret := &subsystemsRegistry{
		entities: map[string]map[string]*Subsystem{},
	}
	for _, item := range subsystems {
		ret.store(item)
	}
	return ret, nil
}

func (sr *subsystemsRegistry) get(ns, name string) *Subsystem {
	ret := sr.entities[ns][name]
	if ret == nil {
		ret = makeSubsystem(ns, name)
	}
	return ret
}

func (sr *subsystemsRegistry) store(item *Subsystem) {
	if sr.entities[item.Namespace] == nil {
		sr.entities[item.Namespace] = map[string]*Subsystem{}
	}
	sr.entities[item.Namespace][item.Name] = item
}

func (sr *subsystemsRegistry) updatePoll(c context.Context, s *Subsystem, success bool) error {
	key := subsystemKey(c, s)
	return db.RunInTransaction(c, func(c context.Context) error {
		dbSubsystem := new(Subsystem)
		err := db.Get(c, key, dbSubsystem)
		if err == db.ErrNoSuchEntity {
			dbSubsystem = s
		} else if err != nil {
			return fmt.Errorf("failed to get Subsystem '%v': %w", key, err)
		}
		dbSubsystem.ListsQueried = timeNow(c)
		if success {
			dbSubsystem.LastBugList = timeNow(c)
		}
		if _, err := db.Put(c, key, dbSubsystem); err != nil {
			return fmt.Errorf("failed to save Subsystem: %w", err)
		}
		sr.store(dbSubsystem)
		return nil
	}, nil)
}

type subsystemReportRegistry struct {
	entities map[string]map[string][]*SubsystemReport
}

func makeSubsystemReportRegistry(c context.Context) (*subsystemReportRegistry, error) {
	var reports []*SubsystemReport
	reportKeys, err := db.NewQuery("SubsystemReport").GetAll(c, &reports)
	if err != nil {
		return nil, err
	}
	var subsystemKeys []*db.Key
	for _, key := range reportKeys {
		subsystemKeys = append(subsystemKeys, key.Parent())
	}
	subsystems := make([]*Subsystem, len(subsystemKeys))
	if err := db.GetMulti(c, subsystemKeys, subsystems); err != nil {
		return nil, fmt.Errorf("failed to query subsystems: %w", err)
	}
	ret := &subsystemReportRegistry{
		entities: map[string]map[string][]*SubsystemReport{},
	}
	for i, item := range reports {
		ret.store(subsystems[i].Namespace, subsystems[i].Name, item)
	}
	return ret, nil
}

func (srr *subsystemReportRegistry) get(ns, name string) []*SubsystemReport {
	return srr.entities[ns][name]
}

func (srr *subsystemReportRegistry) store(ns, name string, item *SubsystemReport) {
	if srr.entities[ns] == nil {
		srr.entities[ns] = map[string][]*SubsystemReport{}
	}
	srr.entities[ns][name] = append(srr.entities[ns][name], item)
}

func storeSubsystemReport(c context.Context, s *Subsystem, report *SubsystemReport) error {
	key := subsystemKey(c, s)
	return db.RunInTransaction(c, func(c context.Context) error {
		// First close all previouly active per-subsystem reports.
		var previous []*SubsystemReport
		prevKeys, err := db.NewQuery("SubsystemReport").
			Ancestor(key).
			Filter("Stages.Closed=", time.Time{}).
			GetAll(c, &previous)
		if err != nil {
			return fmt.Errorf("failed to query old subsystem reports: %w", err)
		}
		for i, subsystem := range previous {
			for i := range subsystem.Stages {
				subsystem.Stages[i].Closed = timeNow(c)
			}
			if _, err := db.Put(c, prevKeys[i], subsystem); err != nil {
				return fmt.Errorf("failed to save SubsystemReport: %w", err)
			}
		}
		// Now save a new one.
		reportKey := subsystemReportKey(c, key, report)
		if _, err := db.Put(c, reportKey, report); err != nil {
			return fmt.Errorf("failed to store new SubsystemReport: %w", err)
		}
		return nil
	}, nil)
}
