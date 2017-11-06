// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// Backend-independent reporting logic.
// Two main entry points:
//  - reportingPoll is called by backends to get list of bugs that need to be reported.
//  - incomingCommand is called by backends to update bug statuses.

const (
	maxMailLogLen    = 1 << 20
	maxMailReportLen = 64 << 10
	internalError    = "internal error"
)

// reportingPoll is called by backends to get list of bugs that need to be reported.
func reportingPoll(c context.Context, typ string) []*dashapi.BugReport {
	state, err := loadReportingState(c)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	var bugs []*Bug
	_, err = datastore.NewQuery("Bug").
		Filter("Status<", BugStatusFixed).
		GetAll(c, &bugs)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	log.Infof(c, "fetched %v bugs", len(bugs))
	sort.Sort(bugReportSorter(bugs))
	var reports []*dashapi.BugReport
	for _, bug := range bugs {
		rep, err := handleReportBug(c, typ, state, bug)
		if err != nil {
			log.Errorf(c, "%v: failed to report bug %v: %v", bug.Namespace, bug.Title, err)
			continue
		}
		if rep == nil {
			continue
		}
		reports = append(reports, rep)
	}
	return reports
}

func handleReportBug(c context.Context, typ string, state *ReportingState, bug *Bug) (*dashapi.BugReport, error) {
	reporting, bugReporting, crash, _, _, _, err := needReport(c, typ, state, bug)
	if err != nil || reporting == nil {
		return nil, err
	}
	rep, err := createBugReport(c, bug, crash, bugReporting, reporting.Config)
	if err != nil {
		return nil, err
	}
	log.Infof(c, "bug %q: reporting to %v", bug.Title, reporting.Name)
	return rep, nil
}

func needReport(c context.Context, typ string, state *ReportingState, bug *Bug) (reporting *Reporting, bugReporting *BugReporting, crash *Crash, reportingIdx int, status, link string, err error) {
	reporting, bugReporting, reportingIdx, status, err = currentReporting(c, bug)
	if err != nil || reporting == nil {
		return
	}
	if typ != "" && typ != reporting.Config.Type() {
		status = "on a different reporting"
		reporting, bugReporting = nil, nil
		return
	}
	link = bugReporting.Link
	if !bugReporting.Reported.IsZero() && bugReporting.ReproLevel >= bug.ReproLevel {
		status = fmt.Sprintf("%v: reported%v on %v",
			reporting.Name, reproStr(bugReporting.ReproLevel),
			formatTime(bugReporting.Reported))
		reporting, bugReporting = nil, nil
		return
	}
	ent := state.getEntry(timeNow(c), bug.Namespace, reporting.Name)
	cfg := config.Namespaces[bug.Namespace]
	if bug.ReproLevel < ReproLevelC && timeSince(c, bug.FirstTime) < cfg.WaitForRepro {
		status = fmt.Sprintf("%v: waiting for C repro", reporting.Name)
		reporting, bugReporting = nil, nil
		return
	}
	if !cfg.MailWithoutReport && !bug.HasReport {
		status = fmt.Sprintf("%v: no report", reporting.Name)
		reporting, bugReporting = nil, nil
		return
	}

	crash, err = findCrashForBug(c, bug)
	if err != nil {
		status = fmt.Sprintf("%v: no crashes!", reporting.Name)
		reporting, bugReporting = nil, nil
		return
	}
	if reporting.Config.NeedMaintainers() && len(crash.Maintainers) == 0 {
		status = fmt.Sprintf("%v: no maintainers", reporting.Name)
		reporting, bugReporting = nil, nil
		return
	}

	// Limit number of reports sent per day,
	// but don't limit sending repros to already reported bugs.
	if bugReporting.Reported.IsZero() && reporting.DailyLimit != 0 &&
		ent.Sent >= reporting.DailyLimit {
		status = fmt.Sprintf("%v: out of quota for today", reporting.Name)
		reporting, bugReporting = nil, nil
		return
	}

	// Ready to be reported.
	if bugReporting.Reported.IsZero() {
		// This update won't be committed, but it will prevent us from
		// reporting too many bugs in a single poll.
		ent.Sent++
	}
	status = fmt.Sprintf("%v: ready to report", reporting.Name)
	if !bugReporting.Reported.IsZero() {
		status += fmt.Sprintf(" (reported%v on %v)",
			reproStr(bugReporting.ReproLevel), formatTime(bugReporting.Reported))
	}
	return
}

func currentReporting(c context.Context, bug *Bug) (*Reporting, *BugReporting, int, string, error) {
	for i := range bug.Reporting {
		bugReporting := &bug.Reporting[i]
		if !bugReporting.Closed.IsZero() {
			continue
		}
		reporting := config.Namespaces[bug.Namespace].ReportingByName(bugReporting.Name)
		if reporting == nil {
			return nil, nil, 0, "", fmt.Errorf("%v: missing in config", bugReporting.Name)
		}
		if reporting.Status == ReportingDisabled {
			continue
		}
		if reporting.Status == ReportingSuspended {
			return nil, nil, 0, fmt.Sprintf("%v: reporting suspended", bugReporting.Name), nil
		}
		return reporting, bugReporting, i, "", nil
	}
	return nil, nil, 0, "", fmt.Errorf("no reporting left")
}

func reproStr(level dashapi.ReproLevel) string {
	switch level {
	case ReproLevelSyz:
		return " syz repro"
	case ReproLevelC:
		return " C repro"
	default:
		return ""
	}
}

func createBugReport(c context.Context, bug *Bug, crash *Crash, bugReporting *BugReporting, config interface{}) (*dashapi.BugReport, error) {
	reportingConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	crashLog, err := getText(c, "CrashLog", crash.Log)
	if err != nil {
		return nil, err
	}
	if len(crashLog) > maxMailLogLen {
		crashLog = crashLog[len(crashLog)-maxMailLogLen:]
	}
	report, err := getText(c, "CrashReport", crash.Report)
	if err != nil {
		return nil, err
	}
	if len(report) > maxMailReportLen {
		report = report[:maxMailReportLen]
	}
	reproC, err := getText(c, "ReproC", crash.ReproC)
	if err != nil {
		return nil, err
	}
	reproSyz, err := getText(c, "ReproSyz", crash.ReproSyz)
	if err != nil {
		return nil, err
	}
	if len(reproSyz) != 0 && len(crash.ReproOpts) != 0 {
		tmp := append([]byte{'#'}, crash.ReproOpts...)
		tmp = append(tmp, '\n')
		tmp = append(tmp, reproSyz...)
		reproSyz = tmp
	}
	build, err := loadBuild(c, bug.Namespace, crash.BuildID)
	if err != nil {
		return nil, err
	}
	kernelConfig, err := getText(c, "KernelConfig", build.KernelConfig)
	if err != nil {
		return nil, err
	}

	rep := &dashapi.BugReport{
		Namespace:    bug.Namespace,
		Config:       reportingConfig,
		ID:           bugReporting.ID,
		ExtID:        bugReporting.ExtID,
		First:        bugReporting.Reported.IsZero(),
		Title:        bug.displayTitle(),
		Log:          crashLog,
		Report:       report,
		Maintainers:  crash.Maintainers,
		OS:           build.OS,
		Arch:         build.Arch,
		VMArch:       build.VMArch,
		CompilerID:   build.CompilerID,
		KernelRepo:   build.KernelRepo,
		KernelBranch: build.KernelBranch,
		KernelCommit: build.KernelCommit,
		KernelConfig: kernelConfig,
		ReproC:       reproC,
		ReproSyz:     reproSyz,
	}
	if bugReporting.CC != "" {
		rep.CC = strings.Split(bugReporting.CC, "|")
	}
	return rep, nil
}

// incomingCommand is entry point to bug status updates.
func incomingCommand(c context.Context, cmd *dashapi.BugUpdate) (bool, string, error) {
	log.Infof(c, "got command: %+q", cmd)
	ok, reason, err := incomingCommandImpl(c, cmd)
	if !ok {
		log.Errorf(c, "%v", reason)
	}
	if err != nil {
		log.Errorf(c, "%v", err)
	}
	if !ok {
		log.Warningf(c, "invalid update: %v", reason)
	}
	return ok, reason, err
}

func incomingCommandImpl(c context.Context, cmd *dashapi.BugUpdate) (bool, string, error) {
	bug, bugKey, err := findBugByReportingID(c, cmd.ID)
	if err != nil {
		return false, internalError, err
	}
	now := timeNow(c)
	dupHash := ""
	if cmd.Status == dashapi.BugStatusDup {
		bugReporting, _ := bugReportingByID(bug, cmd.ID, now)
		dup, dupKey, err := findBugByReportingID(c, cmd.DupOf)
		if err != nil {
			// Email reporting passes bug title in cmd.DupOf, try to find bug by title.
			dup, dupKey, err = findDupByTitle(c, bug.Namespace, cmd.DupOf)
			if err != nil {
				return false, "can't find the dup bug", err
			}
			cmd.DupOf = ""
			for i := range dup.Reporting {
				if dup.Reporting[i].Name == bugReporting.Name {
					cmd.DupOf = dup.Reporting[i].ID
					break
				}
			}
			if cmd.DupOf == "" {
				return false, "can't find the dup bug",
					fmt.Errorf("dup does not have reporting %q", bugReporting.Name)
			}
		}
		dupReporting, _ := bugReportingByID(dup, cmd.DupOf, now)
		if bugReporting == nil || dupReporting == nil {
			return false, internalError, fmt.Errorf("can't find bug reporting")
		}
		if bugKey.StringID() == dupKey.StringID() {
			if bugReporting.Name == dupReporting.Name {
				return false, "Can't dup bug to itself.", nil
			}
			return false, fmt.Sprintf("Can't dup bug to itself in different reporting (%v->%v).\n"+
				"Please dup syzbot bugs only onto syzbot bugs for the same kernel/reporting.",
				bugReporting.Name, dupReporting.Name), nil
		}
		if bug.Namespace != dup.Namespace {
			return false, fmt.Sprintf("Duplicate bug corresponds to a different kernel (%v->%v).\n"+
				"Please dup syzbot bugs only onto syzbot bugs for the same kernel.",
				bug.Namespace, dup.Namespace), nil
		}
		if bugReporting.Name != dupReporting.Name {
			return false, fmt.Sprintf("Can't dup bug to a bug in different reporting (%v->%v)."+
				"Please dup syzbot bugs only onto syzbot bugs for the same kernel/reporting.",
				bugReporting.Name, dupReporting.Name), nil
		}
		dupCanon, err := canonicalBug(c, dup)
		if err != nil {
			return false, internalError, fmt.Errorf("failed to get canonical bug for dup: %v", err)
		}
		if !dupReporting.Closed.IsZero() && dupCanon.Status == BugStatusOpen {
			return false, "Dup bug is already upstreamed.", nil
		}
		dupHash = bugKeyHash(dup.Namespace, dup.Title, dup.Seq)
	}

	ok, reply := false, ""
	tx := func(c context.Context) error {
		var err error
		ok, reply, err = incomingCommandTx(c, now, cmd, bugKey, dupHash)
		return err
	}
	err = datastore.RunInTransaction(c, tx, &datastore.TransactionOptions{
		XG: true,
		// Default is 3 which fails sometimes.
		// We don't want incoming bug updates to fail,
		// because for e.g. email we won't have an external retry.
		Attempts: 30,
	})
	if err != nil {
		return false, internalError, err
	}
	return ok, reply, nil
}

func incomingCommandTx(c context.Context, now time.Time, cmd *dashapi.BugUpdate, bugKey *datastore.Key, dupHash string) (bool, string, error) {
	bug := new(Bug)
	if err := datastore.Get(c, bugKey, bug); err != nil {
		return false, internalError, fmt.Errorf("can't find the corresponding bug: %v", err)
	}
	switch bug.Status {
	case BugStatusOpen:
	case BugStatusDup:
		canon, err := canonicalBug(c, bug)
		if err != nil {
			return false, internalError, err
		}
		if canon.Status != BugStatusOpen {
			// We used to reject updates to closed bugs,
			// but this is confusing and non-actionable for users.
			// So now we fail the update, but give empty reason,
			// which means "don't notify user".
			log.Warningf(c, "Dup bug is already closed")
			return false, "", nil
		}
	case BugStatusFixed, BugStatusInvalid:
		log.Warningf(c, "This bug is already closed")
		return false, "", nil
	default:
		return false, internalError, fmt.Errorf("unknown bug status %v", bug.Status)
	}
	bugReporting, final := bugReportingByID(bug, cmd.ID, now)
	if bugReporting == nil {
		return false, internalError, fmt.Errorf("can't find bug reporting")
	}
	if !bugReporting.Closed.IsZero() {
		log.Warningf(c, "This bug reporting is already closed")
		return false, "", nil
	}
	state, err := loadReportingState(c)
	if err != nil {
		return false, internalError, err
	}
	stateEnt := state.getEntry(now, bug.Namespace, bugReporting.Name)
	switch cmd.Status {
	case dashapi.BugStatusOpen:
		bug.Status = BugStatusOpen
		bug.Closed = time.Time{}
		if bugReporting.Reported.IsZero() {
			bugReporting.Reported = now
			stateEnt.Sent++ // sending repro does not count against the quota
		}
		if bug.ReproLevel < cmd.ReproLevel {
			return false, internalError,
				fmt.Errorf("bug update with invalid repro level: %v/%v",
					bug.ReproLevel, cmd.ReproLevel)
		}
	case dashapi.BugStatusUpstream:
		if final {
			return false, "Can't upstream, this is final destination.", nil
		}
		if len(bug.Commits) != 0 {
			// We could handle this case, but how/when it will occur
			// in real life is unclear now.
			return false, "Can't upstream this bug, the bug has fixing commits.", nil
		}
		bug.Status = BugStatusOpen
		bug.Closed = time.Time{}
		bugReporting.Closed = now
	case dashapi.BugStatusInvalid:
		bugReporting.Closed = now
		bug.Closed = now
		bug.Status = BugStatusInvalid
	case dashapi.BugStatusDup:
		bug.Status = BugStatusDup
		bug.Closed = now
		bug.DupOf = dupHash
	case dashapi.BugStatusUpdate:
		// Just update Link, Commits, etc below.
	default:
		return false, internalError, fmt.Errorf("unknown bug status %v", cmd.Status)
	}
	if len(cmd.FixCommits) != 0 && (bug.Status == BugStatusOpen || bug.Status == BugStatusDup) {
		m := make(map[string]bool)
		for _, com := range cmd.FixCommits {
			m[com] = true
		}
		same := false
		if len(bug.Commits) == len(m) {
			same = true
			for _, com := range bug.Commits {
				if !m[com] {
					same = false
					break
				}
			}
		}
		if !same {
			commits := make([]string, 0, len(m))
			for com := range m {
				if len(com) < 3 {
					return false, fmt.Sprintf("bad commit title: %q", com), nil
				}
				commits = append(commits, com)
			}
			sort.Strings(commits)
			bug.Commits = commits
			bug.PatchedOn = nil
		}
	}
	if bugReporting.ExtID == "" {
		bugReporting.ExtID = cmd.ExtID
	}
	if bugReporting.Link == "" {
		bugReporting.Link = cmd.Link
	}
	if len(cmd.CC) != 0 {
		merged := email.MergeEmailLists(strings.Split(bugReporting.CC, "|"), cmd.CC)
		bugReporting.CC = strings.Join(merged, "|")
	}
	if bugReporting.ReproLevel < cmd.ReproLevel {
		bugReporting.ReproLevel = cmd.ReproLevel
	}
	if bug.Status != BugStatusDup {
		bug.DupOf = ""
	}
	if _, err := datastore.Put(c, bugKey, bug); err != nil {
		return false, internalError, fmt.Errorf("failed to put bug: %v", err)
	}
	if err := saveReportingState(c, state); err != nil {
		return false, internalError, err
	}
	return true, "", nil
}

func findBugByReportingID(c context.Context, id string) (*Bug, *datastore.Key, error) {
	var bugs []*Bug
	keys, err := datastore.NewQuery("Bug").
		Filter("Reporting.ID=", id).
		Limit(2).
		GetAll(c, &bugs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch bugs: %v", err)
	}
	if len(bugs) == 0 {
		return nil, nil, fmt.Errorf("failed to find bug by reporting id %q", id)
	}
	if len(bugs) > 1 {
		return nil, nil, fmt.Errorf("multiple bugs for reporting id %q", id)
	}
	return bugs[0], keys[0], nil
}

func findDupByTitle(c context.Context, ns, title string) (*Bug, *datastore.Key, error) {
	title, seq, err := splitDisplayTitle(title)
	if err != nil {
		return nil, nil, err
	}
	bugHash := bugKeyHash(ns, title, seq)
	bugKey := datastore.NewKey(c, "Bug", bugHash, 0, nil)
	bug := new(Bug)
	if err := datastore.Get(c, bugKey, bug); err != nil {
		return nil, nil, fmt.Errorf("failed to get dup: %v", err)
	}
	return bug, bugKey, nil
}

func bugReportingByID(bug *Bug, id string, now time.Time) (*BugReporting, bool) {
	for i := range bug.Reporting {
		if bug.Reporting[i].ID == id {
			return &bug.Reporting[i], i == len(bug.Reporting)-1
		}
		bug.Reporting[i].Closed = now
	}
	return nil, false
}

func queryCrashesForBug(c context.Context, bugKey *datastore.Key, limit int) ([]*Crash, error) {
	var crashes []*Crash
	_, err := datastore.NewQuery("Crash").
		Ancestor(bugKey).
		Order("-ReproC").
		Order("-ReproSyz").
		Order("-ReportLen").
		Order("-Time").
		Limit(limit).
		GetAll(c, &crashes)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch crashes: %v", err)
	}
	return crashes, nil
}

func findCrashForBug(c context.Context, bug *Bug) (*Crash, error) {
	bugKey := datastore.NewKey(c, "Bug", bugKeyHash(bug.Namespace, bug.Title, bug.Seq), 0, nil)
	crashes, err := queryCrashesForBug(c, bugKey, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch crashes: %v", err)
	}
	if len(crashes) < 1 {
		return nil, fmt.Errorf("no crashes")
	}
	crash := crashes[0]
	if bug.ReproLevel == ReproLevelC {
		if crash.ReproC == 0 {
			log.Errorf(c, "bug '%v': has C repro, but crash without C repro", bug.Title)
		}
	} else if bug.ReproLevel == ReproLevelSyz {
		if crash.ReproSyz == 0 {
			log.Errorf(c, "bug '%v': has syz repro, but crash without syz repro", bug.Title)
		}
	} else if bug.HasReport {
		if crash.Report == 0 {
			log.Errorf(c, "bug '%v': has report, but crash without report", bug.Title)
		}
	}
	return crash, nil
}

func loadReportingState(c context.Context) (*ReportingState, error) {
	state := new(ReportingState)
	key := datastore.NewKey(c, "ReportingState", "", 1, nil)
	if err := datastore.Get(c, key, state); err != nil && err != datastore.ErrNoSuchEntity {
		return nil, fmt.Errorf("failed to get reporting state: %v", err)
	}
	return state, nil
}

func saveReportingState(c context.Context, state *ReportingState) error {
	key := datastore.NewKey(c, "ReportingState", "", 1, nil)
	if _, err := datastore.Put(c, key, state); err != nil {
		return fmt.Errorf("failed to put reporting state: %v", err)
	}
	return nil
}

func (state *ReportingState) getEntry(now time.Time, namespace, name string) *ReportingStateEntry {
	if namespace == "" || name == "" {
		panic(fmt.Sprintf("requesting reporting state for %v/%v", namespace, name))
	}
	// Convert time to date of the form 20170125.
	year, month, day := now.Date()
	date := year*10000 + int(month)*100 + day
	for i := range state.Entries {
		ent := &state.Entries[i]
		if ent.Namespace == namespace && ent.Name == name {
			if ent.Date != date {
				ent.Date = date
				ent.Sent = 0
			}
			return ent
		}
	}
	state.Entries = append(state.Entries, ReportingStateEntry{
		Namespace: namespace,
		Name:      name,
		Date:      date,
		Sent:      0,
	})
	return &state.Entries[len(state.Entries)-1]
}

// bugReportSorter sorts bugs by priority we want to report them.
// E.g. we want to report bugs with reproducers before bugs without reproducers.
type bugReportSorter []*Bug

func (a bugReportSorter) Len() int      { return len(a) }
func (a bugReportSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a bugReportSorter) Less(i, j int) bool {
	if a[i].ReproLevel != a[j].ReproLevel {
		return a[i].ReproLevel > a[j].ReproLevel
	}
	if a[i].HasReport != a[j].HasReport {
		return a[i].HasReport
	}
	if a[i].NumCrashes != a[j].NumCrashes {
		return a[i].NumCrashes > a[j].NumCrashes
	}
	return a[i].FirstTime.Before(a[j].FirstTime)
}
