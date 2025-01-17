// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/sys/targets"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// Backend-independent reporting logic.
// Two main entry points:
//  - reportingPoll is called by backends to get list of bugs that need to be reported.
//  - incomingCommand is called by backends to update bug statuses.

const (
	maxMailReportLen           = 64 << 10
	maxInlineError             = 16 << 10
	notifyResendPeriod         = 14 * 24 * time.Hour
	notifyAboutBadCommitPeriod = 90 * 24 * time.Hour
	never                      = 100 * 365 * 24 * time.Hour
	internalError              = "internal error"
	// This is embedded as first line of syzkaller reproducer files.
	syzReproPrefix = "# See https://goo.gl/kgGztJ for information about syzkaller reproducers.\n"
)

// reportingPoll is called by backends to get list of bugs that need to be reported.
func reportingPollBugs(c context.Context, typ string) []*dashapi.BugReport {
	state, err := loadReportingState(c)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	bugs, _, err := loadOpenBugs(c)
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
			log.Errorf(c, "%v: failed to report bug '%v': %v", bug.Namespace, bug.Title, err)
			continue
		}
		if rep == nil {
			continue
		}
		reports = append(reports, rep)
		// Trying to report too many at once is known to cause OOMs.
		// But new bugs appear incrementally and polling is frequent enough,
		// so reporting lots of bugs at once is also not necessary.
		if len(reports) == 3 {
			break
		}
	}
	return reports
}

func handleReportBug(c context.Context, typ string, state *ReportingState, bug *Bug) (
	*dashapi.BugReport, error) {
	reporting, bugReporting, _, _, _, err := needReport(c, typ, state, bug)
	if err != nil || reporting == nil {
		return nil, err
	}
	crash, crashKey, err := findCrashForBug(c, bug)
	if err != nil {
		return nil, err
	} else if crash == nil {
		return nil, fmt.Errorf("no crashes")
	}
	rep, err := createBugReport(c, bug, crash, crashKey, bugReporting, reporting)
	if err != nil {
		return nil, err
	}
	log.Infof(c, "bug %q: reporting to %v", bug.Title, reporting.Name)
	return rep, nil
}

func needReport(c context.Context, typ string, state *ReportingState, bug *Bug) (
	reporting *Reporting, bugReporting *BugReporting, reportingIdx int,
	status, link string, err error) {
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
	if !bugReporting.Reported.IsZero() && bugReporting.ReproLevel >= bug.HeadReproLevel {
		status = fmt.Sprintf("%v: reported%v on %v",
			reporting.DisplayTitle, reproStr(bugReporting.ReproLevel),
			html.FormatTime(bugReporting.Reported))
		reporting, bugReporting = nil, nil
		return
	}
	ent := state.getEntry(timeNow(c), bug.Namespace, reporting.Name)
	cfg := getNsConfig(c, bug.Namespace)
	if timeSince(c, bug.FirstTime) < cfg.ReportingDelay {
		status = fmt.Sprintf("%v: initial reporting delay", reporting.DisplayTitle)
		reporting, bugReporting = nil, nil
		return
	}
	if crashNeedsRepro(bug.Title) && bug.ReproLevel < ReproLevelC &&
		timeSince(c, bug.FirstTime) < cfg.WaitForRepro {
		status = fmt.Sprintf("%v: waiting for C repro", reporting.DisplayTitle)
		reporting, bugReporting = nil, nil
		return
	}
	if !cfg.MailWithoutReport && !bug.HasReport {
		status = fmt.Sprintf("%v: no report", reporting.DisplayTitle)
		reporting, bugReporting = nil, nil
		return
	}
	if bug.NumCrashes == 0 {
		status = fmt.Sprintf("%v: no crashes!", reporting.DisplayTitle)
		reporting, bugReporting = nil, nil
		return
	}

	// Limit number of reports sent per day.
	if ent.Sent >= reporting.DailyLimit {
		status = fmt.Sprintf("%v: out of quota for today", reporting.DisplayTitle)
		reporting, bugReporting = nil, nil
		return
	}

	// Ready to be reported.
	// This update won't be committed, but it is useful as a best effort measure
	// so that we don't overflow the limit in a single poll.
	ent.Sent++

	status = fmt.Sprintf("%v: ready to report", reporting.DisplayTitle)
	if !bugReporting.Reported.IsZero() {
		status += fmt.Sprintf(" (reported%v on %v)",
			reproStr(bugReporting.ReproLevel), html.FormatTime(bugReporting.Reported))
	}
	return
}

func reportingPollNotifications(c context.Context, typ string) []*dashapi.BugNotification {
	bugs, _, err := loadOpenBugs(c)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	log.Infof(c, "fetched %v bugs", len(bugs))
	var notifs []*dashapi.BugNotification
	for _, bug := range bugs {
		if getNsConfig(c, bug.Namespace).Decommissioned {
			continue
		}
		notif, err := handleReportNotif(c, typ, bug)
		if err != nil {
			log.Errorf(c, "%v: failed to create bug notif %v: %v", bug.Namespace, bug.Title, err)
			continue
		}
		if notif == nil {
			continue
		}
		notifs = append(notifs, notif)
		if len(notifs) >= 10 {
			break // don't send too many at once just in case
		}
	}
	return notifs
}

func handleReportNotif(c context.Context, typ string, bug *Bug) (*dashapi.BugNotification, error) {
	reporting, bugReporting, _, _, err := currentReporting(c, bug)
	if err != nil || reporting == nil {
		return nil, nil
	}
	if typ != "" && typ != reporting.Config.Type() {
		return nil, nil
	}
	if bug.Status != BugStatusOpen || bugReporting.Reported.IsZero() {
		return nil, nil
	}
	for _, f := range notificationGenerators {
		notif, err := f(c, bug, reporting, bugReporting)
		if notif != nil || err != nil {
			return notif, err
		}
	}
	return nil, nil
}

var notificationGenerators = []func(context.Context, *Bug, *Reporting,
	*BugReporting) (*dashapi.BugNotification, error){
	// Embargo upstreaming.
	func(c context.Context, bug *Bug, reporting *Reporting,
		bugReporting *BugReporting) (*dashapi.BugNotification, error) {
		if reporting.moderation &&
			reporting.Embargo != 0 &&
			len(bug.Commits) == 0 &&
			bugReporting.OnHold.IsZero() &&
			timeSince(c, bugReporting.Reported) > reporting.Embargo {
			log.Infof(c, "%v: upstreaming (embargo): %v", bug.Namespace, bug.Title)
			return createNotification(c, dashapi.BugNotifUpstream, true, "", bug, reporting, bugReporting)
		}
		return nil, nil
	},
	// Upstreaming.
	func(c context.Context, bug *Bug, reporting *Reporting,
		bugReporting *BugReporting) (*dashapi.BugNotification, error) {
		if reporting.moderation &&
			len(bug.Commits) == 0 &&
			bugReporting.OnHold.IsZero() &&
			reporting.Filter(bug) == FilterSkip {
			log.Infof(c, "%v: upstreaming (skip): %v", bug.Namespace, bug.Title)
			return createNotification(c, dashapi.BugNotifUpstream, true, "", bug, reporting, bugReporting)
		}
		return nil, nil
	},
	// Obsoleting.
	func(c context.Context, bug *Bug, reporting *Reporting,
		bugReporting *BugReporting) (*dashapi.BugNotification, error) {
		if len(bug.Commits) == 0 &&
			bug.canBeObsoleted(c) &&
			timeSince(c, bug.LastActivity) > notifyResendPeriod &&
			timeSince(c, bug.LastTime) > bug.obsoletePeriod(c) {
			log.Infof(c, "%v: obsoleting: %v", bug.Namespace, bug.Title)
			why := bugObsoletionReason(bug)
			return createNotification(c, dashapi.BugNotifObsoleted, false, string(why), bug, reporting, bugReporting)
		}
		return nil, nil
	},
	// Bad commit.
	func(c context.Context, bug *Bug, reporting *Reporting,
		bugReporting *BugReporting) (*dashapi.BugNotification, error) {
		if len(bug.Commits) > 0 &&
			len(bug.PatchedOn) == 0 &&
			timeSince(c, bug.LastActivity) > notifyResendPeriod &&
			timeSince(c, bug.FixTime) > notifyAboutBadCommitPeriod {
			log.Infof(c, "%v: bad fix commit: %v", bug.Namespace, bug.Title)
			commits := strings.Join(bug.Commits, "\n")
			return createNotification(c, dashapi.BugNotifBadCommit, true, commits, bug, reporting, bugReporting)
		}
		return nil, nil
	},
	// Label notifications.
	func(c context.Context, bug *Bug, reporting *Reporting,
		bugReporting *BugReporting) (*dashapi.BugNotification, error) {
		for _, label := range bug.Labels {
			if label.SetBy != "" {
				continue
			}
			str := label.String()
			if reporting.Labels[str] == "" {
				continue
			}
			if stringInList(bugReporting.GetLabels(), str) {
				continue
			}
			return createLabelNotification(c, label, bug, reporting, bugReporting)
		}
		return nil, nil
	},
}

func createLabelNotification(c context.Context, label BugLabel, bug *Bug, reporting *Reporting,
	bugReporting *BugReporting) (*dashapi.BugNotification, error) {
	labelStr := label.String()
	notif, err := createNotification(c, dashapi.BugNotifLabel, true, reporting.Labels[labelStr],
		bug, reporting, bugReporting)
	if err != nil {
		return nil, err
	}
	notif.Label = labelStr
	// For some labels also attach job results.
	if label.Label == OriginLabel {
		var err error
		notif.TreeJobs, err = treeTestJobs(c, bug)
		if err != nil {
			log.Errorf(c, "failed to extract jobs for %s: %v", bug.keyHash(c), err)
			return nil, fmt.Errorf("failed to fetch jobs: %w", err)
		}
	}
	return notif, nil
}

func bugObsoletionReason(bug *Bug) dashapi.BugStatusReason {
	if bug.HeadReproLevel == ReproLevelNone && bug.ReproLevel != ReproLevelNone {
		return dashapi.InvalidatedByRevokedRepro
	}
	return dashapi.InvalidatedByNoActivity
}

var noObsoletionsKey = "Temporarily disable bug obsoletions"

func contextWithNoObsoletions(c context.Context) context.Context {
	return context.WithValue(c, &noObsoletionsKey, struct{}{})
}

func getNoObsoletions(c context.Context) bool {
	return c.Value(&noObsoletionsKey) != nil
}

// TODO: this is what we would like to do, but we need to figure out
// KMSAN story: we don't do fix bisection on it (rebased),
// do we want to close all old KMSAN bugs with repros?
// For now we only enable this in tests.
var obsoleteWhatWontBeFixBisected = false

func (bug *Bug) canBeObsoleted(c context.Context) bool {
	if getNoObsoletions(c) {
		return false
	}
	if bug.HeadReproLevel == ReproLevelNone {
		return true
	}
	if obsoleteWhatWontBeFixBisected {
		cfg := getNsConfig(c, bug.Namespace)
		for _, mgr := range bug.HappenedOn {
			if !cfg.Managers[mgr].FixBisectionDisabled {
				return false
			}
		}
		return true
	}
	return false
}

func (bug *Bug) obsoletePeriod(c context.Context) time.Duration {
	period := never
	config := getConfig(c)
	if config.Obsoleting.MinPeriod == 0 {
		return period
	}

	// Let's assume that crashes follow the Possion distribution with rate r=crashes/days.
	// Then, the chance of seeing a crash within t days is p=1-e^(-r*t).
	// Solving it for t, we get t=log(1/(1-p))/r.
	// Since our rate is also only an estimate, let's require p=0.99.

	// Before we have at least 10 crashes, any estimation of frequency is too imprecise.
	// In such case we conservatively assume it still happens.
	if bug.NumCrashes >= 10 {
		bugDays := bug.LastTime.Sub(bug.FirstTime).Hours() / 24.0
		rate := float64(bug.NumCrashes-1) / bugDays

		const probability = 0.99
		// For 1 crash/day, this will be ~4.6 days.
		days := math.Log(1.0/(1.0-probability)) / rate
		// Let's be conservative and multiply it by 3.
		days = days * 3
		period = time.Hour * time.Duration(24*days)
	}
	minVal, maxVal := config.Obsoleting.MinPeriod, config.Obsoleting.MaxPeriod
	if config.Obsoleting.NonFinalMinPeriod != 0 &&
		bug.Reporting[len(bug.Reporting)-1].Reported.IsZero() {
		minVal, maxVal = config.Obsoleting.NonFinalMinPeriod, config.Obsoleting.NonFinalMaxPeriod
	}
	if mgr := bug.managerConfig(c); mgr != nil && mgr.ObsoletingMinPeriod != 0 {
		minVal, maxVal = mgr.ObsoletingMinPeriod, mgr.ObsoletingMaxPeriod
	}
	period = max(period, minVal)
	period = min(period, maxVal)
	return period
}

func (bug *Bug) managerConfig(c context.Context) *ConfigManager {
	if len(bug.HappenedOn) != 1 {
		return nil
	}
	mgr := getNsConfig(c, bug.Namespace).Managers[bug.HappenedOn[0]]
	return &mgr
}

func createNotification(c context.Context, typ dashapi.BugNotif, public bool, text string, bug *Bug,
	reporting *Reporting, bugReporting *BugReporting) (*dashapi.BugNotification, error) {
	reportingConfig, err := json.Marshal(reporting.Config)
	if err != nil {
		return nil, err
	}
	crash, _, err := findCrashForBug(c, bug)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, bug.Namespace, crash.BuildID)
	if err != nil {
		return nil, err
	}
	kernelRepo := kernelRepoInfo(c, build)
	notif := &dashapi.BugNotification{
		Type:      typ,
		Namespace: bug.Namespace,
		Config:    reportingConfig,
		ID:        bugReporting.ID,
		ExtID:     bugReporting.ExtID,
		Title:     bug.displayTitle(),
		Text:      text,
		Public:    public,
		Link:      fmt.Sprintf("%v/bug?extid=%v", appURL(c), bugReporting.ID),
		CC:        kernelRepo.CC.Always,
	}
	if public {
		notif.Maintainers = append(crash.Maintainers, kernelRepo.CC.Maintainers...)
	}
	if (public || reporting.moderation) && bugReporting.CC != "" {
		notif.CC = append(notif.CC, strings.Split(bugReporting.CC, "|")...)
	}
	if mgr := bug.managerConfig(c); mgr != nil {
		notif.CC = append(notif.CC, mgr.CC.Always...)
		if public {
			notif.Maintainers = append(notif.Maintainers, mgr.CC.Maintainers...)
		}
	}
	return notif, nil
}

func currentReporting(c context.Context, bug *Bug) (*Reporting, *BugReporting, int, string, error) {
	if bug.NumCrashes == 0 {
		// This is possible during the short window when we already created a bug,
		// but did not attach the first crash to it yet. We need to avoid reporting this bug yet
		// and wait for the crash. Otherwise reporting filter may mis-classify it as e.g.
		// not having a report or something else.
		return nil, nil, 0, "no crashes yet", nil
	}
	for i := range bug.Reporting {
		bugReporting := &bug.Reporting[i]
		if !bugReporting.Closed.IsZero() {
			continue
		}
		reporting := getNsConfig(c, bug.Namespace).ReportingByName(bugReporting.Name)
		if reporting == nil {
			return nil, nil, 0, "", fmt.Errorf("%v: missing in config", bugReporting.Name)
		}
		if reporting.DailyLimit == 0 {
			return nil, nil, 0, fmt.Sprintf("%v: reporting has daily limit 0", reporting.DisplayTitle), nil
		}
		switch reporting.Filter(bug) {
		case FilterSkip:
			if bugReporting.Reported.IsZero() {
				continue
			}
			fallthrough
		case FilterReport:
			return reporting, bugReporting, i, "", nil
		case FilterHold:
			return nil, nil, 0, fmt.Sprintf("%v: reporting suspended", reporting.DisplayTitle), nil
		}
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

// nolint: gocyclo
func createBugReport(c context.Context, bug *Bug, crash *Crash, crashKey *db.Key,
	bugReporting *BugReporting, reporting *Reporting) (*dashapi.BugReport, error) {
	var job *Job
	if bug.BisectCause == BisectYes || bug.BisectCause == BisectInconclusive || bug.BisectCause == BisectHorizont {
		// If we have bisection results, report the crash/repro used for bisection.
		causeBisect, err := queryBestBisection(c, bug, JobBisectCause)
		if err != nil {
			return nil, err
		}
		if causeBisect != nil {
			err := causeBisect.loadCrash(c)
			if err != nil {
				return nil, err
			}
		}
		// If we didn't check whether the bisect is unreliable, even though it would not be
		// reported anyway, we could still eventually Cc people from those commits later
		// (e.g. when we did bisected with a syz repro and then notified about a C repro).
		if causeBisect != nil && !causeBisect.job.isUnreliableBisect() {
			job = causeBisect.job
			if causeBisect.crash.ReproC != 0 || crash.ReproC == 0 {
				// Don't override the crash in this case,
				// otherwise we will always think that we haven't reported the C repro.
				crash, crashKey = causeBisect.crash, causeBisect.crashKey
			}
		}
	}
	rep, err := crashBugReport(c, bug, crash, crashKey, bugReporting, reporting)
	if err != nil {
		return nil, err
	}
	if job != nil {
		cause, emails := bisectFromJob(c, job)
		rep.BisectCause = cause
		rep.Maintainers = append(rep.Maintainers, emails...)
	}
	return rep, nil
}

// crashBugReport fills in crash and build related fields into *dashapi.BugReport.
func crashBugReport(c context.Context, bug *Bug, crash *Crash, crashKey *db.Key,
	bugReporting *BugReporting, reporting *Reporting) (*dashapi.BugReport, error) {
	reportingConfig, err := json.Marshal(reporting.Config)
	if err != nil {
		return nil, err
	}
	crashLog, _, err := getText(c, textCrashLog, crash.Log)
	if err != nil {
		return nil, err
	}
	report, _, err := getText(c, textCrashReport, crash.Report)
	if err != nil {
		return nil, err
	}
	if len(report) > maxMailReportLen {
		report = report[:maxMailReportLen]
	}
	machineInfo, _, err := getText(c, textMachineInfo, crash.MachineInfo)
	if err != nil {
		return nil, err
	}
	build, err := loadBuild(c, bug.Namespace, crash.BuildID)
	if err != nil {
		return nil, err
	}
	typ := dashapi.ReportNew
	if !bugReporting.Reported.IsZero() {
		typ = dashapi.ReportRepro
	}
	assetList := createAssetList(c, build, crash, true)
	kernelRepo := kernelRepoInfo(c, build)
	rep := &dashapi.BugReport{
		Type:            typ,
		Config:          reportingConfig,
		ExtID:           bugReporting.ExtID,
		First:           bugReporting.Reported.IsZero(),
		Moderation:      reporting.moderation,
		Log:             crashLog,
		LogLink:         externalLink(c, textCrashLog, crash.Log),
		LogHasStrace:    dashapi.CrashFlags(crash.Flags)&dashapi.CrashUnderStrace > 0,
		Report:          report,
		ReportLink:      externalLink(c, textCrashReport, crash.Report),
		CC:              kernelRepo.CC.Always,
		Maintainers:     append(crash.Maintainers, kernelRepo.CC.Maintainers...),
		ReproOpts:       crash.ReproOpts,
		MachineInfo:     machineInfo,
		MachineInfoLink: externalLink(c, textMachineInfo, crash.MachineInfo),
		CrashID:         crashKey.IntID(),
		CrashTime:       crash.Time,
		NumCrashes:      bug.NumCrashes,
		HappenedOn:      managersToRepos(c, bug.Namespace, bug.HappenedOn),
		Manager:         crash.Manager,
		Assets:          assetList,
		ReportElements:  &dashapi.ReportElements{GuiltyFiles: crash.ReportElements.GuiltyFiles},
	}
	if !crash.ReproIsRevoked {
		rep.ReproCLink = externalLink(c, textReproC, crash.ReproC)
		rep.ReproC, _, err = getText(c, textReproC, crash.ReproC)
		if err != nil {
			return nil, err
		}
		rep.ReproSyzLink = externalLink(c, textReproSyz, crash.ReproSyz)
		rep.ReproSyz, err = loadReproSyz(c, crash)
		if err != nil {
			return nil, err
		}
	}
	if bugReporting.CC != "" {
		rep.CC = append(rep.CC, strings.Split(bugReporting.CC, "|")...)
	}
	if build.Type == BuildFailed {
		rep.Maintainers = append(rep.Maintainers, kernelRepo.CC.BuildMaintainers...)
	}
	if mgr := bug.managerConfig(c); mgr != nil {
		rep.CC = append(rep.CC, mgr.CC.Always...)
		rep.Maintainers = append(rep.Maintainers, mgr.CC.Maintainers...)
		if build.Type == BuildFailed {
			rep.Maintainers = append(rep.Maintainers, mgr.CC.BuildMaintainers...)
		}
	}
	for _, label := range bug.Labels {
		text, ok := reporting.Labels[label.String()]
		if !ok {
			continue
		}
		if rep.LabelMessages == nil {
			rep.LabelMessages = map[string]string{}
		}
		rep.LabelMessages[label.String()] = text
	}
	if err := fillBugReport(c, rep, bug, bugReporting, build); err != nil {
		return nil, err
	}
	return rep, nil
}

func loadReproSyz(c context.Context, crash *Crash) ([]byte, error) {
	reproSyz, _, err := getText(c, textReproSyz, crash.ReproSyz)
	if err != nil || len(reproSyz) == 0 {
		return nil, err
	}
	buf := new(bytes.Buffer)
	buf.WriteString(syzReproPrefix)
	if len(crash.ReproOpts) != 0 {
		fmt.Fprintf(buf, "#%s\n", crash.ReproOpts)
	}
	buf.Write(reproSyz)
	return buf.Bytes(), nil
}

// fillBugReport fills common report fields for bug and job reports.
func fillBugReport(c context.Context, rep *dashapi.BugReport, bug *Bug, bugReporting *BugReporting,
	build *Build) error {
	kernelConfig, _, err := getText(c, textKernelConfig, build.KernelConfig)
	if err != nil {
		return err
	}
	creditEmail, err := email.AddAddrContext(ownEmail(c), bugReporting.ID)
	if err != nil {
		return err
	}
	rep.BugStatus, err = bug.dashapiStatus()
	if err != nil {
		return err
	}
	rep.Namespace = bug.Namespace
	rep.ID = bugReporting.ID
	rep.Title = bug.displayTitle()
	rep.Link = fmt.Sprintf("%v/bug?extid=%v", appURL(c), bugReporting.ID)
	rep.CreditEmail = creditEmail
	rep.OS = build.OS
	rep.Arch = build.Arch
	rep.VMArch = build.VMArch
	rep.UserSpaceArch = kernelArch(build.Arch)
	rep.BuildID = build.ID
	rep.BuildTime = build.Time
	rep.CompilerID = build.CompilerID
	rep.KernelRepo = build.KernelRepo
	rep.KernelRepoAlias = kernelRepoInfo(c, build).Alias
	rep.KernelBranch = build.KernelBranch
	rep.KernelCommit = build.KernelCommit
	rep.KernelCommitTitle = build.KernelCommitTitle
	rep.KernelCommitDate = build.KernelCommitDate
	rep.KernelConfig = kernelConfig
	rep.KernelConfigLink = externalLink(c, textKernelConfig, build.KernelConfig)
	rep.SyzkallerCommit = build.SyzkallerCommit
	rep.NoRepro = build.Type == BuildFailed
	for _, item := range bug.LabelValues(SubsystemLabel) {
		rep.Subsystems = append(rep.Subsystems, dashapi.BugSubsystem{
			Name:  item.Value,
			SetBy: item.SetBy,
			Link:  fmt.Sprintf("%v/%s/s/%s", appURL(c), bug.Namespace, item.Value),
		})
		rep.Maintainers = email.MergeEmailLists(rep.Maintainers,
			subsystemMaintainers(c, rep.Namespace, item.Value))
	}
	for _, addr := range bug.UNCC {
		rep.CC = email.RemoveFromEmailList(rep.CC, addr)
		rep.Maintainers = email.RemoveFromEmailList(rep.Maintainers, addr)
	}
	return nil
}

func managersToRepos(c context.Context, ns string, managers []string) []string {
	var repos []string
	dedup := make(map[string]bool)
	for _, manager := range managers {
		build, err := lastManagerBuild(c, ns, manager)
		if err != nil {
			log.Errorf(c, "failed to get manager %q build: %v", manager, err)
			continue
		}
		repo := kernelRepoInfo(c, build).Alias
		if dedup[repo] {
			continue
		}
		dedup[repo] = true
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	return repos
}

func queryCrashesForBug(c context.Context, bugKey *db.Key, limit int) (
	[]*Crash, []*db.Key, error) {
	var crashes []*Crash
	keys, err := db.NewQuery("Crash").
		Ancestor(bugKey).
		Order("-ReportLen").
		Order("-Time").
		Limit(limit).
		GetAll(c, &crashes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch crashes: %w", err)
	}
	return crashes, keys, nil
}

func loadAllBugs(c context.Context, filter func(*db.Query) *db.Query) ([]*Bug, []*db.Key, error) {
	var bugs []*Bug
	var keys []*db.Key
	err := foreachBug(c, filter, func(bug *Bug, key *db.Key) error {
		bugs = append(bugs, bug)
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return bugs, keys, nil
}

func loadNamespaceBugs(c context.Context, ns string) ([]*Bug, []*db.Key, error) {
	return loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns)
	})
}

func loadOpenBugs(c context.Context) ([]*Bug, []*db.Key, error) {
	return loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Status<", BugStatusFixed)
	})
}

func foreachBug(c context.Context, filter func(*db.Query) *db.Query, fn func(bug *Bug, key *db.Key) error) error {
	const batchSize = 2000
	var cursor *db.Cursor
	for {
		query := db.NewQuery("Bug").Limit(batchSize)
		if filter != nil {
			query = filter(query)
		}
		if cursor != nil {
			query = query.Start(*cursor)
		}
		iter := query.Run(c)
		for i := 0; ; i++ {
			bug := new(Bug)
			key, err := iter.Next(bug)
			if err == db.Done {
				if i < batchSize {
					return nil
				}
				break
			}
			if err != nil {
				return fmt.Errorf("failed to fetch bugs: %w", err)
			}
			if err := fn(bug, key); err != nil {
				return err
			}
		}
		cur, err := iter.Cursor()
		if err != nil {
			return fmt.Errorf("cursor failed while fetching bugs: %w", err)
		}
		cursor = &cur
	}
}

func filterBugs(bugs []*Bug, keys []*db.Key, filter func(*Bug) bool) ([]*Bug, []*db.Key) {
	var retBugs []*Bug
	var retKeys []*db.Key
	for i, bug := range bugs {
		if filter(bug) {
			retBugs = append(retBugs, bugs[i])
			retKeys = append(retKeys, keys[i])
		}
	}
	return retBugs, retKeys
}

// reportingPollClosed is called by backends to get list of closed bugs.
func reportingPollClosed(c context.Context, ids []string) ([]string, error) {
	idMap := make(map[string]bool, len(ids))
	for _, id := range ids {
		idMap[id] = true
	}
	var closed []string
	err := foreachBug(c, nil, func(bug *Bug, _ *db.Key) error {
		for i := range bug.Reporting {
			bugReporting := &bug.Reporting[i]
			if !idMap[bugReporting.ID] {
				continue
			}
			var err error
			bug, err = canonicalBug(c, bug)
			if err != nil {
				log.Errorf(c, "%v", err)
				break
			}
			if bug.Status >= BugStatusFixed || !bugReporting.Closed.IsZero() ||
				getNsConfig(c, bug.Namespace).Decommissioned {
				closed = append(closed, bugReporting.ID)
			}
			break
		}
		return nil
	})
	return closed, err
}

// incomingCommand is entry point to bug status updates.
func incomingCommand(c context.Context, cmd *dashapi.BugUpdate) (bool, string, error) {
	log.Infof(c, "got command: %+v", cmd)
	ok, reason, err := incomingCommandImpl(c, cmd)
	if err != nil {
		log.Errorf(c, "%v (%v)", reason, err)
	} else if !ok && reason != "" {
		log.Errorf(c, "invalid update: %v", reason)
	}
	return ok, reason, err
}

func incomingCommandImpl(c context.Context, cmd *dashapi.BugUpdate) (bool, string, error) {
	for i, com := range cmd.FixCommits {
		if len(com) >= 2 && com[0] == '"' && com[len(com)-1] == '"' {
			com = com[1 : len(com)-1]
			cmd.FixCommits[i] = com
		}
		if len(com) < 3 {
			return false, fmt.Sprintf("bad commit title: %q", com), nil
		}
	}
	bug, bugKey, err := findBugByReportingID(c, cmd.ID)
	if err != nil {
		return false, internalError, err
	}
	var dupKey *db.Key
	if cmd.Status == dashapi.BugStatusDup {
		if looksLikeReportingHash(cmd.DupOf) {
			_, dupKey, _ = findBugByReportingID(c, cmd.DupOf)
		}
		if dupKey == nil {
			// Email reporting passes bug title in cmd.DupOf, try to find bug by title.
			var dup *Bug
			dup, dupKey, err = findDupByTitle(c, bug.Namespace, cmd.DupOf)
			if err != nil || dup == nil {
				return false, "can't find the dup bug", err
			}
			dupReporting := lastReportedReporting(dup)
			if dupReporting == nil {
				return false, "can't find the dup bug", fmt.Errorf("dup does not have reporting")
			}
			cmd.DupOf = dupReporting.ID
		}
	}
	now := timeNow(c)
	ok, reply := false, ""
	tx := func(c context.Context) error {
		var err error
		ok, reply, err = incomingCommandTx(c, now, cmd, bugKey, dupKey)
		return err
	}
	err = runInTransaction(c, tx, &db.TransactionOptions{
		XG: true,
		// We don't want incoming bug updates to fail,
		// because for e.g. email we won't have an external retry.
		Attempts: 30,
	})
	if err != nil {
		return false, internalError, err
	}
	return ok, reply, nil
}

func checkDupBug(c context.Context, cmd *dashapi.BugUpdate, bug *Bug, bugKey, dupKey *db.Key) (
	*Bug, bool, string, error) {
	dup := new(Bug)
	if err := db.Get(c, dupKey, dup); err != nil {
		return nil, false, internalError, fmt.Errorf("can't find the dup by key: %w", err)
	}
	bugReporting, _ := bugReportingByID(bug, cmd.ID)
	dupReporting, _ := bugReportingByID(dup, cmd.DupOf)
	if bugReporting == nil || dupReporting == nil {
		return nil, false, internalError, fmt.Errorf("can't find bug reporting")
	}
	if bugKey.StringID() == dupKey.StringID() {
		if bugReporting.Name == dupReporting.Name {
			return nil, false, "Can't dup bug to itself.", nil
		}
		return nil, false, fmt.Sprintf("Can't dup bug to itself in different reporting (%v->%v).\n"+
			"Please dup syzbot bugs only onto syzbot bugs for the same kernel/reporting.",
			bugReporting.Name, dupReporting.Name), nil
	}
	if bug.Namespace != dup.Namespace {
		return nil, false, fmt.Sprintf("Duplicate bug corresponds to a different kernel (%v->%v).\n"+
			"Please dup syzbot bugs only onto syzbot bugs for the same kernel.",
			bug.Namespace, dup.Namespace), nil
	}
	if !allowCrossReportingDup(c, bug, dup, bugReporting, dupReporting) {
		return nil, false, fmt.Sprintf("Can't dup bug to a bug in different reporting (%v->%v)."+
			"Please dup syzbot bugs only onto syzbot bugs for the same kernel/reporting.",
			bugReporting.Name, dupReporting.Name), nil
	}
	dupCanon, err := canonicalBug(c, dup)
	if err != nil {
		return nil, false, internalError, fmt.Errorf("failed to get canonical bug for dup: %w", err)
	}
	if !dupReporting.Closed.IsZero() && dupCanon.Status == BugStatusOpen {
		return nil, false, "Dup bug is already upstreamed.", nil
	}
	if dupCanon.keyHash(c) == bugKey.StringID() {
		return nil, false, "Setting this dup would lead to a bug cycle, cycles are not allowed.", nil
	}
	return dup, true, "", nil
}

func allowCrossReportingDup(c context.Context, bug, dup *Bug,
	bugReporting, dupReporting *BugReporting) bool {
	bugIdx := getReportingIdx(c, bug, bugReporting)
	dupIdx := getReportingIdx(c, dup, dupReporting)
	if bugIdx < 0 || dupIdx < 0 {
		return false
	}
	if bugIdx == dupIdx {
		return true
	}
	// We generally allow duping only within the same reporting.
	// But there is one exception: we also allow duping from last but one
	// reporting to the last one (which is stable, final destination)
	// provided that these two reportings have the same access level and type.
	// The rest of the combinations can lead to surprising states and
	// information hiding, so we don't allow them.
	cfg := getNsConfig(c, bug.Namespace)
	bugConfig := &cfg.Reporting[bugIdx]
	dupConfig := &cfg.Reporting[dupIdx]
	lastIdx := len(cfg.Reporting) - 1
	return bugIdx == lastIdx-1 && dupIdx == lastIdx &&
		bugConfig.AccessLevel == dupConfig.AccessLevel &&
		bugConfig.Config.Type() == dupConfig.Config.Type()
}

func getReportingIdx(c context.Context, bug *Bug, bugReporting *BugReporting) int {
	for i := range bug.Reporting {
		if bug.Reporting[i].Name == bugReporting.Name {
			return i
		}
	}
	log.Errorf(c, "failed to find bug reporting by name: %q/%q", bug.Title, bugReporting.Name)
	return -1
}

func incomingCommandTx(c context.Context, now time.Time, cmd *dashapi.BugUpdate, bugKey, dupKey *db.Key) (
	bool, string, error) {
	bug := new(Bug)
	if err := db.Get(c, bugKey, bug); err != nil {
		return false, internalError, fmt.Errorf("can't find the corresponding bug: %w", err)
	}
	var dup *Bug
	if cmd.Status == dashapi.BugStatusDup {
		dup1, ok, reason, err := checkDupBug(c, cmd, bug, bugKey, dupKey)
		if !ok || err != nil {
			return ok, reason, err
		}
		dup = dup1
	}
	state, err := loadReportingState(c)
	if err != nil {
		return false, internalError, err
	}
	ok, reason, err := incomingCommandUpdate(c, now, cmd, bugKey, bug, dup, state)
	if !ok || err != nil {
		return ok, reason, err
	}
	if _, err := db.Put(c, bugKey, bug); err != nil {
		return false, internalError, fmt.Errorf("failed to put bug: %w", err)
	}
	if err := saveReportingState(c, state); err != nil {
		return false, internalError, err
	}
	return true, "", nil
}

func incomingCommandUpdate(c context.Context, now time.Time, cmd *dashapi.BugUpdate, bugKey *db.Key,
	bug, dup *Bug, state *ReportingState) (bool, string, error) {
	bugReporting, final := bugReportingByID(bug, cmd.ID)
	if bugReporting == nil {
		return false, internalError, fmt.Errorf("can't find bug reporting")
	}
	if ok, reply, err := checkBugStatus(c, cmd, bug, bugReporting); !ok {
		return false, reply, err
	}
	stateEnt := state.getEntry(now, bug.Namespace, bugReporting.Name)
	if ok, reply, err := incomingCommandCmd(c, now, cmd, bug, dup, bugReporting, final, stateEnt); !ok {
		return false, reply, err
	}
	if (len(cmd.FixCommits) != 0 || cmd.ResetFixCommits) &&
		(bug.Status == BugStatusOpen || bug.Status == BugStatusDup) {
		sort.Strings(cmd.FixCommits)
		if !reflect.DeepEqual(bug.Commits, cmd.FixCommits) {
			bug.updateCommits(cmd.FixCommits, now)
		}
	}
	toReport := append([]int64{}, cmd.ReportCrashIDs...)
	if cmd.CrashID != 0 {
		bugReporting.CrashID = cmd.CrashID
		toReport = append(toReport, cmd.CrashID)
	}
	newRef := CrashReference{CrashReferenceReporting, bugReporting.Name, now}
	for _, crashID := range toReport {
		err := addCrashReference(c, crashID, bugKey, newRef)
		if err != nil {
			return false, internalError, err
		}
	}
	for _, crashID := range cmd.UnreportCrashIDs {
		err := removeCrashReference(c, crashID, bugKey, CrashReferenceReporting, bugReporting.Name)
		if err != nil {
			return false, internalError, err
		}
	}
	if bugReporting.ExtID == "" {
		bugReporting.ExtID = cmd.ExtID
	}
	if bugReporting.Link == "" {
		bugReporting.Link = cmd.Link
	}
	if len(cmd.CC) != 0 && cmd.Status != dashapi.BugStatusUnCC {
		merged := email.MergeEmailLists(strings.Split(bugReporting.CC, "|"), cmd.CC)
		bugReporting.CC = strings.Join(merged, "|")
	}
	bugReporting.ReproLevel = max(bugReporting.ReproLevel, cmd.ReproLevel)
	if bug.Status != BugStatusDup {
		bug.DupOf = ""
	}
	if cmd.Status != dashapi.BugStatusOpen || !cmd.OnHold {
		bugReporting.OnHold = time.Time{}
	}
	if cmd.Status != dashapi.BugStatusUpdate || cmd.ExtID != "" {
		// Update LastActivity only on important events.
		// Otherwise it impedes bug obsoletion.
		bug.LastActivity = now
	}
	return true, "", nil
}

func incomingCommandCmd(c context.Context, now time.Time, cmd *dashapi.BugUpdate, bug, dup *Bug,
	bugReporting *BugReporting, final bool, stateEnt *ReportingStateEntry) (bool, string, error) {
	switch cmd.Status {
	case dashapi.BugStatusOpen:
		bug.Status = BugStatusOpen
		bug.Closed = time.Time{}
		stateEnt.Sent++
		if bugReporting.Reported.IsZero() {
			bugReporting.Reported = now
		}
		if bugReporting.OnHold.IsZero() && cmd.OnHold {
			bugReporting.OnHold = now
		}
		// Close all previous reporting if they are not closed yet
		// (can happen due to Status == ReportingDisabled).
		for i := range bug.Reporting {
			if bugReporting == &bug.Reporting[i] {
				break
			}
			if bug.Reporting[i].Closed.IsZero() {
				bug.Reporting[i].Closed = now
			}
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
		bugReporting.Auto = cmd.Notification
	case dashapi.BugStatusInvalid:
		bug.Closed = now
		bug.Status = BugStatusInvalid
		bugReporting.Closed = now
		bugReporting.Auto = cmd.Notification
	case dashapi.BugStatusDup:
		bug.Status = BugStatusDup
		bug.Closed = now
		bug.DupOf = dup.keyHash(c)
	case dashapi.BugStatusUpdate:
		// Just update Link, Commits, etc below.
	case dashapi.BugStatusUnCC:
		bug.UNCC = email.MergeEmailLists(bug.UNCC, cmd.CC)
	default:
		return false, internalError, fmt.Errorf("unknown bug status %v", cmd.Status)
	}
	if cmd.StatusReason != "" {
		bug.StatusReason = cmd.StatusReason
	}
	for _, label := range cmd.Labels {
		bugReporting.AddLabel(label)
	}
	return true, "", nil
}

func checkBugStatus(c context.Context, cmd *dashapi.BugUpdate, bug *Bug, bugReporting *BugReporting) (
	bool, string, error) {
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
			if cmd.Status == dashapi.BugStatusUpdate {
				// This happens when people discuss old bugs.
				log.Infof(c, "Dup bug is already closed")
			} else {
				log.Warningf(c, "incoming command %v: dup bug is already closed", cmd.ID)
			}
			return false, "", nil
		}
	case BugStatusFixed, BugStatusInvalid:
		if cmd.Status != dashapi.BugStatusUpdate {
			log.Errorf(c, "incoming command %v: bug is already closed", cmd.ID)
		}
		return false, "", nil
	default:
		return false, internalError, fmt.Errorf("unknown bug status %v", bug.Status)
	}
	if !bugReporting.Closed.IsZero() {
		if cmd.Status != dashapi.BugStatusUpdate {
			log.Errorf(c, "incoming command %v: bug reporting is already closed", cmd.ID)
		}
		return false, "", nil
	}
	return true, "", nil
}

func findBugByReportingID(c context.Context, id string) (*Bug, *db.Key, error) {
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").
		Filter("Reporting.ID=", id).
		Limit(2).
		GetAll(c, &bugs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch bugs: %w", err)
	}
	if len(bugs) == 0 {
		return nil, nil, fmt.Errorf("failed to find bug by reporting id %q", id)
	}
	if len(bugs) > 1 {
		return nil, nil, fmt.Errorf("multiple bugs for reporting id %q", id)
	}
	return bugs[0], keys[0], nil
}

func findDupByTitle(c context.Context, ns, title string) (*Bug, *db.Key, error) {
	title, seq, err := splitDisplayTitle(title)
	if err != nil {
		return nil, nil, err
	}
	bugHash := bugKeyHash(c, ns, title, seq)
	bugKey := db.NewKey(c, "Bug", bugHash, 0, nil)
	bug := new(Bug)
	if err := db.Get(c, bugKey, bug); err != nil {
		if err == db.ErrNoSuchEntity {
			return nil, nil, nil // This is not really an error, we should notify the user instead.
		}
		return nil, nil, fmt.Errorf("failed to get dup: %w", err)
	}
	return bug, bugKey, nil
}

func bugReportingByID(bug *Bug, id string) (*BugReporting, bool) {
	for i := range bug.Reporting {
		if bug.Reporting[i].ID == id {
			return &bug.Reporting[i], i == len(bug.Reporting)-1
		}
	}
	return nil, false
}

func bugReportingByName(bug *Bug, name string) *BugReporting {
	for i := range bug.Reporting {
		if bug.Reporting[i].Name == name {
			return &bug.Reporting[i]
		}
	}
	return nil
}

func lastReportedReporting(bug *Bug) *BugReporting {
	for i := len(bug.Reporting) - 1; i >= 0; i-- {
		if !bug.Reporting[i].Reported.IsZero() {
			return &bug.Reporting[i]
		}
	}
	return nil
}

// The updateReporting method is supposed to be called both to fully initialize a new
// Bug object and also to adjust it to the updated namespace configuration.
func (bug *Bug) updateReportings(c context.Context, cfg *Config, now time.Time) error {
	oldReportings := map[string]BugReporting{}
	oldPositions := map[string]int{}
	for i, rep := range bug.Reporting {
		oldReportings[rep.Name] = rep
		oldPositions[rep.Name] = i
	}
	maxPos := 0
	bug.Reporting = nil
	for _, rep := range cfg.Reporting {
		if oldRep, ok := oldReportings[rep.Name]; ok {
			oldPos := oldPositions[rep.Name]
			if oldPos < maxPos {
				// At the moment we only support insertions and deletions of reportings.
				// TODO: figure out what exactly can go wrong if we also allow reordering.
				return fmt.Errorf("the order of reportings is changed, before: %v", oldPositions)
			}
			maxPos = oldPos
			bug.Reporting = append(bug.Reporting, oldRep)
		} else {
			bug.Reporting = append(bug.Reporting, BugReporting{
				Name: rep.Name,
				ID:   bugReportingHash(bug.keyHash(c), rep.Name),
			})
		}
	}
	// We might have added new BugReporting objects between/before the ones that were
	// already reported. To let syzbot continue from the same reporting stage where it
	// stopped, close such outliers.
	seenProcessed := false
	minTime := now
	for i := len(bug.Reporting) - 1; i >= 0; i-- {
		rep := &bug.Reporting[i]
		if !rep.Reported.IsZero() || !rep.Closed.IsZero() || !rep.OnHold.IsZero() {
			if !rep.Reported.IsZero() && rep.Reported.Before(minTime) {
				minTime = rep.Reported
			}
			seenProcessed = true
		} else if seenProcessed {
			rep.Dummy = true
		}
	}
	// Yet another stage -- we set Closed and Reported to dummy objects in non-decreasing order.
	currTime := minTime
	for i := range bug.Reporting {
		rep := &bug.Reporting[i]
		if rep.Dummy {
			rep.Closed = currTime
			rep.Reported = currTime
		} else if rep.Reported.After(currTime) {
			currTime = rep.Reported
		}
	}
	return nil
}

func findCrashForBug(c context.Context, bug *Bug) (*Crash, *db.Key, error) {
	bugKey := bug.key(c)
	crashes, keys, err := queryCrashesForBug(c, bugKey, 1)
	if err != nil {
		return nil, nil, err
	}
	if len(crashes) < 1 {
		return nil, nil, fmt.Errorf("no crashes")
	}
	crash, key := crashes[0], keys[0]
	if bug.HeadReproLevel == ReproLevelC {
		if crash.ReproC == 0 {
			log.Errorf(c, "bug '%v': has C repro, but crash without C repro", bug.Title)
		}
	} else if bug.HeadReproLevel == ReproLevelSyz {
		if crash.ReproSyz == 0 {
			log.Errorf(c, "bug '%v': has syz repro, but crash without syz repro", bug.Title)
		}
	}
	return crash, key, nil
}

func loadReportingState(c context.Context) (*ReportingState, error) {
	state := new(ReportingState)
	key := db.NewKey(c, "ReportingState", "", 1, nil)
	if err := db.Get(c, key, state); err != nil && err != db.ErrNoSuchEntity {
		return nil, fmt.Errorf("failed to get reporting state: %w", err)
	}
	return state, nil
}

func saveReportingState(c context.Context, state *ReportingState) error {
	key := db.NewKey(c, "ReportingState", "", 1, nil)
	if _, err := db.Put(c, key, state); err != nil {
		return fmt.Errorf("failed to put reporting state: %w", err)
	}
	return nil
}

func (state *ReportingState) getEntry(now time.Time, namespace, name string) *ReportingStateEntry {
	if namespace == "" || name == "" {
		panic(fmt.Sprintf("requesting reporting state for %v/%v", namespace, name))
	}
	// Convert time to date of the form 20170125.
	date := timeDate(now)
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

func loadFullBugInfo(c context.Context, bug *Bug, bugKey *db.Key,
	bugReporting *BugReporting) (*dashapi.FullBugInfo, error) {
	reporting := getNsConfig(c, bug.Namespace).ReportingByName(bugReporting.Name)
	if reporting == nil {
		return nil, fmt.Errorf("failed to find the reporting object")
	}
	ret := &dashapi.FullBugInfo{}
	// Query bisections.
	var err error
	if bug.BisectCause > BisectPending {
		ret.BisectCause, err = prepareBisectionReport(c, bug, JobBisectCause, reporting)
		if err != nil {
			return nil, err
		}
	}
	if bug.BisectFix > BisectPending {
		ret.BisectFix, err = prepareBisectionReport(c, bug, JobBisectFix, reporting)
		if err != nil {
			return nil, err
		}
	}
	// Query the fix candidate.
	if bug.FixCandidateJob != "" {
		ret.FixCandidate, err = prepareFixCandidateReport(c, bug, reporting)
		if err != nil {
			return nil, err
		}
	}
	// Query similar bugs.
	similar, err := loadSimilarBugs(c, bug)
	if err != nil {
		return nil, err
	}
	for _, similarBug := range similar {
		_, bugReporting, _, _, _ := currentReporting(c, similarBug)
		if bugReporting == nil {
			continue
		}
		status, err := similarBug.dashapiStatus()
		if err != nil {
			return nil, err
		}
		ret.SimilarBugs = append(ret.SimilarBugs, &dashapi.SimilarBugInfo{
			Title:      similarBug.displayTitle(),
			Status:     status,
			Namespace:  similarBug.Namespace,
			ReproLevel: similarBug.ReproLevel,
			Link:       fmt.Sprintf("%v/bug?extid=%v", appURL(c), bugReporting.ID),
			ReportLink: bugReporting.Link,
			Closed:     similarBug.Closed,
		})
	}
	// Query crashes.
	crashes, err := representativeCrashes(c, bugKey)
	if err != nil {
		return nil, err
	}
	for _, crash := range crashes {
		rep, err := crashBugReport(c, bug, crash.crash, crash.key, bugReporting, reporting)
		if err != nil {
			return nil, fmt.Errorf("crash %d: %w", crash.key.IntID(), err)
		}
		ret.Crashes = append(ret.Crashes, rep)
	}
	// Query tree testing jobs.
	ret.TreeJobs, err = treeTestJobs(c, bug)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func prepareFixCandidateReport(c context.Context, bug *Bug, reporting *Reporting) (*dashapi.BugReport, error) {
	job, jobKey, err := fetchJob(c, bug.FixCandidateJob)
	if err != nil {
		return nil, err
	}
	ret, err := createBugReportForJob(c, job, jobKey, reporting.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create the job bug report: %w", err)
	}
	return ret, nil
}

func prepareBisectionReport(c context.Context, bug *Bug, jobType JobType,
	reporting *Reporting) (*dashapi.BugReport, error) {
	bisectionJob, err := queryBestBisection(c, bug, jobType)
	if bisectionJob == nil || err != nil {
		return nil, err
	}
	job, jobKey := bisectionJob.job, bisectionJob.key
	if job.Reporting != "" {
		ret, err := createBugReportForJob(c, job, jobKey, reporting.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create the job bug report: %w", err)
		}
		return ret, nil
	}
	return nil, nil
}

type crashWithKey struct {
	crash *Crash
	key   *db.Key
}

func representativeCrashes(c context.Context, bugKey *db.Key) ([]*crashWithKey, error) {
	// There should generally be no need to query lots of crashes.
	const fetchCrashes = 50
	allCrashes, allCrashKeys, err := queryCrashesForBug(c, bugKey, fetchCrashes)
	if err != nil {
		return nil, err
	}
	// Let's consider a crash fresh if it happened within the last week.
	const recentDuration = time.Hour * 24 * 7
	now := timeNow(c)

	var bestCrash, recentCrash, straceCrash *crashWithKey
	for id, crash := range allCrashes {
		key := allCrashKeys[id]
		if bestCrash == nil {
			bestCrash = &crashWithKey{crash, key}
		}
		if now.Sub(crash.Time) < recentDuration && recentCrash == nil {
			recentCrash = &crashWithKey{crash, key}
		}
		if dashapi.CrashFlags(crash.Flags)&dashapi.CrashUnderStrace > 0 &&
			straceCrash == nil {
			straceCrash = &crashWithKey{crash, key}
		}
	}
	// It's possible that there are so many crashes with reproducers that
	// we do not get to see the recent crashes without them.
	// Give it one more try.
	if recentCrash == nil {
		var crashes []*Crash
		keys, err := db.NewQuery("Crash").
			Ancestor(bugKey).
			Order("-Time").
			Limit(1).
			GetAll(c, &crashes)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch the latest crash: %w", err)
		}
		if len(crashes) > 0 {
			recentCrash = &crashWithKey{crashes[0], keys[0]}
		}
	}
	dedup := map[int64]bool{}
	crashes := []*crashWithKey{}
	for _, item := range []*crashWithKey{recentCrash, bestCrash, straceCrash} {
		if item == nil || dedup[item.key.IntID()] {
			continue
		}
		crashes = append(crashes, item)
		dedup[item.key.IntID()] = true
	}
	// Sort by Time in desc order.
	sort.Slice(crashes, func(i, j int) bool {
		return crashes[i].crash.Time.After(crashes[j].crash.Time)
	})
	return crashes, nil
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

// kernelArch returns arch as kernel developers know it (rather than Go names).
// Currently Linux-specific.
func kernelArch(arch string) string {
	switch arch {
	case targets.I386:
		return "i386"
	default:
		return arch
	}
}
