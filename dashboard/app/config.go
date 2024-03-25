// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/net/context"
)

// There are multiple configurable aspects of the app (namespaces, reporting, API clients, etc).
// The exact config is stored in a global config variable and is read-only.
// Also see config_stub.go.
type GlobalConfig struct {
	// Min access levels specified hierarchically throughout the config.
	AccessLevel AccessLevel
	// Email suffix of authorized users (e.g. "@foobar.com").
	AuthDomain string
	// Google Analytics Tracking ID.
	AnalyticsTrackingID string
	// URL prefix of source coverage reports.
	// Dashboard will append manager_name.html to that prefix.
	// syz-ci can upload these reports to GCS.
	CoverPath string
	// Global API clients that work across namespaces (e.g. external reporting).
	// The keys are client identities (names), the values are their passwords.
	Clients map[string]string
	// List of emails blocked from issuing test requests.
	EmailBlocklist []string
	// Bug obsoleting settings. See ObsoletingConfig for details.
	Obsoleting ObsoletingConfig
	// Namespace that is shown by default (no namespace selected yet).
	DefaultNamespace string
	// Per-namespace config.
	// Namespaces are a mechanism to separate groups of different kernels.
	// E.g. Debian 4.4 kernels and Ubuntu 4.9 kernels.
	// Each namespace has own reporting config, own API clients
	// and bugs are not merged across namespaces.
	Namespaces map[string]*Config
	// app's own email address which will appear in FROM field of mails sent by the app.
	OwnEmailAddress string
	// List of email addresses which are considered app's own email addresses.
	// All emails sent from one of these email addresses shall be ignored by the app on reception.
	ExtraOwnEmailAddresses []string
	// Main part of the URL at which the app is reachable.
	// This URL is used e.g. to construct HTML links contained in the emails sent by the app.
	AppURL string
	// The email address to display on all web pages.
	ContactEmail string
	// Emails received via the addresses below will be attributed to the corresponding
	// kind of Discussion.
	DiscussionEmails []DiscussionEmailConfig
	// Incoming request throttling.
	Throttle ThrottleConfig
}

// Per-namespace config.
type Config struct {
	// See GlobalConfig.AccessLevel.
	AccessLevel AccessLevel
	// If set, this namespace is not actively tested, no notifications are sent, etc.
	// It's kept mostly read-only for historical reference.
	Decommissioned bool
	// Name used in UI.
	DisplayTitle string
	// Unique string that allows to show "similar bugs" across different namespaces.
	// Similar bugs are shown only across namespaces with the same value of SimilarityDomain.
	SimilarityDomain string
	// Per-namespace clients that act only on a particular namespace.
	// The keys are client identities (names), the values are their passwords.
	Clients map[string]string
	// A random string used for hashing, can be anything, but once fixed it can't
	// be changed as it becomes a part of persistent bug identifiers.
	Key string
	// Mail bugs without reports (e.g. "no output").
	MailWithoutReport bool
	// How long should we wait before reporting a bug.
	ReportingDelay time.Duration
	// How long should we wait for a C repro before reporting a bug.
	WaitForRepro time.Duration
	// If set, successful fix bisections will auto-close the bug.
	FixBisectionAutoClose bool
	// If set, dashboard will periodically request repros and revoke no longer working ones.
	RetestRepros bool
	// If set, dashboard will create patch testing jobs to determine bug origin trees.
	FindBugOriginTrees bool
	// Managers contains some special additional info about syz-manager instances.
	Managers map[string]ConfigManager
	// Reporting config.
	Reporting []Reporting
	// TransformCrash hook is called when a manager uploads a crash.
	// The hook can transform the crash or discard the crash by returning false.
	TransformCrash func(build *Build, crash *dashapi.Crash) bool `json:"-"`
	// NeedRepro hook can be used to prevent reproduction of some bugs.
	NeedRepro func(bug *Bug) bool `json:"-"`
	// List of kernel repositories for this namespace.
	// The first repo considered the "main" repo (e.g. fixing commit info is shown against this repo).
	// Other repos are secondary repos, they may be tested or not.
	// If not tested they are used to poll for fixing commits.
	Repos []KernelRepo
	// If not nil, bugs in this namespace will be exported to the specified Kcidb.
	Kcidb *KcidbConfig
	// Subsystems config.
	Subsystems SubsystemsConfig
	// Instead of Last acitivity, display Discussions on the main page.
	DisplayDiscussions bool
	// Cache what we display on the web dashboard.
	CacheUIPages bool
}

// DiscussionEmailConfig defines the correspondence between an email and a DiscussionSource.
type DiscussionEmailConfig struct {
	// The address at which syzbot has received the message.
	ReceiveAddress string
	// The associated DiscussionSource.
	Source dashapi.DiscussionSource
}

// SubsystemsConfig describes where to take the list of subsystems and how to infer them.
type SubsystemsConfig struct {
	// If Service is set, dashboard will use it to infer and recalculate subsystems.
	Service *subsystem.Service
	// If all existing subsystem labels must be recalculated, increase this integer.
	Revision int
	// Periodic per-subsystem reminders about open bugs.
	Reminder *BugListReportingConfig
	// Maps old subsystem names to new ones.
	Redirect map[string]string
}

// BugListReportingConfig describes how aggregated reminders about open bugs should be processed.
type BugListReportingConfig struct {
	// Reports are sent every PeriodDays days (30 by default).
	PeriodDays int
	// Reports will include details about BugsInReport bugs (10 by default).
	BugsInReport int
	// Bugs that were first discovered less than MinBugAge ago, will not be included.
	// The default value is 1 weeks.
	MinBugAge time.Duration
	// Don't include a bug in the report if there has been a human reply to one of the
	// discussions involving the bug during the last UserReplyFrist units of time.
	// The default value is 2 weeks.
	UserReplyFrist time.Duration
	// Reports will only be sent if there are at least MinBugsCount bugs to notify about.
	// The default value is 2.
	MinBugsCount int
	// SourceReporting is the name of the reporting stage from which bugs should be taken.
	SourceReporting string
	// If ModerationConfig is set, bug lists will be first sent there for human confirmation.
	// For now, only EmailConfig is supported.
	ModerationConfig ReportingType
	// Config specifies how exactly such notifications should be delivered.
	// For now, only EmailConfig is supported.
	Config ReportingType
}

// ObsoletingConfig describes how bugs should be obsoleted.
// First, for each bug we conservatively estimate period since the last crash
// when we consider it stopped happenning. This estimation is based on the first/last time
// and number and rate of crashes. Then this period is capped by MinPeriod/MaxPeriod.
// Then if the period has elapsed since the last crash, we obsolete the bug.
// NonFinalMinPeriod/NonFinalMaxPeriod (if specified) are used to cap bugs in non-final reportings.
// Additionally ConfigManager.ObsoletingMin/MaxPeriod override the cap settings
// for bugs that happen only on that manager.
// If no periods are specified, no bugs are obsoleted.
type ObsoletingConfig struct {
	MinPeriod         time.Duration
	MaxPeriod         time.Duration
	NonFinalMinPeriod time.Duration
	NonFinalMaxPeriod time.Duration
	// Reproducers are retested every ReproRetestPeriod.
	// If the period is zero, not retesting is performed.
	ReproRetestPeriod time.Duration
	// Reproducer retesting begins after there have been no crashes during
	// the ReproRetestStart period.
	// By default, it's 14 days.
	ReproRetestStart time.Duration
}

// ConfigManager describes a single syz-manager instance.
// Dashboard does not generally need to know about all of them,
// but in some special cases it needs to know some additional information.
type ConfigManager struct {
	Decommissioned bool   // The instance is no longer active.
	DelegatedTo    string // If Decommissioned, test requests should go to this instance instead.
	// Normally instances can test patches on any tree.
	// However, some (e.g. non-upstreamed KMSAN) can test only on a fixed tree.
	// RestrictedTestingRepo contains the repo for such instances
	// and RestrictedTestingReason contains a human readable reason for the restriction.
	RestrictedTestingRepo   string
	RestrictedTestingReason string
	// If a bug happens only on this manager, this overrides global obsoleting settings.
	// See ObsoletingConfig for details.
	ObsoletingMinPeriod time.Duration
	ObsoletingMaxPeriod time.Duration
	// Determines if fix bisection should be disabled on this manager.
	FixBisectionDisabled bool
	// CC for all bugs that happened only on this manager.
	CC CCConfig
	// Other parameters being equal, Priority helps to order bug's crashes.
	// Priority is an integer in the range [-3;3].
	Priority int
}

const (
	MinManagerPriority = -3
	MaxManagerPriority = 3
)

// One reporting stage.
type Reporting struct {
	// See GlobalConfig.AccessLevel.
	AccessLevel AccessLevel
	// A unique name (the app does not care about exact contents).
	Name string
	// Name used in UI.
	DisplayTitle string
	// Filter can be used to conditionally skip this reporting or hold off reporting.
	Filter ReportingFilter `json:"-"`
	// How many new bugs report per day.
	DailyLimit int
	// Upstream reports into next reporting after this period.
	Embargo time.Duration
	// Type of reporting and its configuration.
	// The app has one built-in type, EmailConfig, which reports bugs by email.
	// And ExternalConfig which can be used to attach any external reporting system (e.g. Bugzilla).
	Config ReportingType
	// List of labels to notify about (keys are strings of form "label:value").
	// The value is the string that will be included in the notification message.
	// Notifications will only be sent for automatically assigned labels.
	Labels map[string]string
	// Set for all but last reporting stages.
	moderation bool
}

type ReportingType interface {
	// Type returns a unique string that identifies this reporting type (e.g. "email").
	Type() string
	// Validate validates the current object, this is called only during init.
	Validate() error
}

type KernelRepo struct {
	URL    string
	Branch string
	// Alias is a short, readable name of a kernel repository.
	Alias string
	// ReportingPriority says if we need to prefer to report crashes in this
	// repo over crashes in repos with lower value. Must be in [0-9] range.
	ReportingPriority int
	// CC for all bugs reported on this repo.
	CC CCConfig
	// This repository should not be polled for commits, e.g. because it's no longer active.
	NoPoll bool
	// LabelIntroduced is assigned to a bug if it was supposedly introduced
	// in this particular tree (i.e. no other tree from CommitInflow has it).
	LabelIntroduced string
	// LabelReached is assiged to a bug if it's the latest tree so far to which
	// the bug has spread (i.e. no other tree to which commits flow from this one
	// has this bug).
	LabelReached string
	// CommitInflow are the descriptions of commit sources of this tree.
	CommitInflow []KernelRepoLink
	// Enable the missing backport tracking feature for this tree.
	DetectMissingBackports bool
	// Append this string to the config file before running reproducers on this tree.
	AppendConfig string
}

type KernelRepoLink struct {
	// Alias of the repository from which commits flow into the current one.
	Alias string
	// Whether commits from the other repository merged or cherry-picked.
	Merge bool
	// Whether syzbot should try to fix bisect the bug in the Alias tree.
	BisectFixes bool
}

type CCConfig struct {
	// Additional CC list to add to bugs unconditionally.
	Always []string
	// Additional CC list to add to bugs if we are mailing maintainers.
	Maintainers []string
	// Additional CC list to add to build/boot bugs if we are mailing maintainers.
	BuildMaintainers []string
}

type KcidbConfig struct {
	// Origin is how this system identified in Kcidb, e.g. "syzbot_foobar".
	Origin string
	// Project is Kcidb GCE project name, e.g. "kernelci-production".
	Project string
	// Topic is pubsub topic to publish messages to, e.g. "playground_kernelci_new".
	Topic string
	// Credentials is Google application credentials file contents to use for authorization.
	Credentials []byte
}

// ThrottleConfig determines how many requests a single client can make in a period of time.
type ThrottleConfig struct {
	// The time period to be considered.
	Window time.Duration
	// No more than Limit requests are allowed within the time window.
	Limit int
}

func (t ThrottleConfig) Empty() bool {
	return t.Window == 0 || t.Limit == 0
}

var (
	namespaceNameRe = regexp.MustCompile("^[a-zA-Z0-9-_.]{4,32}$")
	clientNameRe    = regexp.MustCompile("^[a-zA-Z0-9-_.]{4,100}$")
	clientKeyRe     = regexp.MustCompile("^([a-zA-Z0-9]{16,128})|(" + regexp.QuoteMeta(auth.OauthMagic) + ".*)$")
)

type (
	FilterResult    int
	ReportingFilter func(bug *Bug) FilterResult
)

const (
	FilterReport FilterResult = iota // Report bug in this reporting (default).
	FilterSkip                       // Skip this reporting and proceed to the next one.
	FilterHold                       // Hold off with reporting this bug.
)

func ConstFilter(result FilterResult) ReportingFilter {
	return func(bug *Bug) FilterResult {
		return result
	}
}

func (cfg *Config) ReportingByName(name string) *Reporting {
	for i := range cfg.Reporting {
		reporting := &cfg.Reporting[i]
		if reporting.Name == name {
			return reporting
		}
	}
	return nil
}

// configDontUse holds the configuration object that is installed either by tests
// or from mainConfig in main function (a separate file should install mainConfig
// in an init function).
// Please access it via the getConfig(context.Context) method.
var (
	configDontUse *GlobalConfig
	mainConfig    *GlobalConfig
)

// To ensure config integrity during tests, we marshal config after it's installed
// and optionally verify it during execution.
var (
	ensureConfigImmutability = false
	marshaledConfig          = ""
)

func installConfig(cfg *GlobalConfig) {
	checkConfig(cfg)
	if configDontUse != nil {
		panic("another config is already installed")
	}
	configDontUse = cfg
	if ensureConfigImmutability {
		marshaledConfig = cfg.marshalJSON()
	}
	initEmailReporting()
	initHTTPHandlers()
	initAPIHandlers()
	initKcidb()
}

var contextConfigKey = "Updated config (to be used during tests). Use only in tests!"

func contextWithConfig(c context.Context, cfg *GlobalConfig) context.Context {
	return context.WithValue(c, &contextConfigKey, cfg)
}

func getConfig(c context.Context) *GlobalConfig {
	// Check point.
	validateGlobalConfig()

	if val, ok := c.Value(&contextConfigKey).(*GlobalConfig); ok {
		return val
	}
	return configDontUse // The base config was not overwriten.
}

func validateGlobalConfig() {
	if ensureConfigImmutability {
		currentConfig := configDontUse.marshalJSON()
		if diff := cmp.Diff(currentConfig, marshaledConfig); diff != "" {
			panic("global config changed during execution: " + diff)
		}
	}
}

func getNsConfig(c context.Context, ns string) *Config {
	return getConfig(c).Namespaces[ns]
}

func checkConfig(cfg *GlobalConfig) {
	if cfg == nil {
		panic("installing nil config")
	}
	if len(cfg.Namespaces) == 0 {
		panic("no namespaces found")
	}
	for i := range cfg.EmailBlocklist {
		cfg.EmailBlocklist[i] = email.CanonicalEmail(cfg.EmailBlocklist[i])
	}
	if cfg.Throttle.Limit < 0 {
		panic("throttle limit cannot be negative")
	}
	if (cfg.Throttle.Limit != 0) != (cfg.Throttle.Window != 0) {
		panic("throttling window and limit must be both set")
	}
	namespaces := make(map[string]bool)
	clientNames := make(map[string]bool)
	checkClients(clientNames, cfg.Clients)
	checkConfigAccessLevel(&cfg.AccessLevel, AccessPublic, "global")
	checkObsoleting(&cfg.Obsoleting)
	if cfg.Namespaces[cfg.DefaultNamespace] == nil {
		panic(fmt.Sprintf("default namespace %q is not found", cfg.DefaultNamespace))
	}
	for ns, cfg := range cfg.Namespaces {
		checkNamespace(ns, cfg, namespaces, clientNames)
	}
	checkDiscussionEmails(cfg.DiscussionEmails)
}

func checkDiscussionEmails(list []DiscussionEmailConfig) {
	dup := map[string]struct{}{}
	for _, item := range list {
		email := item.ReceiveAddress
		if _, ok := dup[email]; ok {
			panic(fmt.Sprintf("duplicate %s in DiscussionEmails", email))
		}
		dup[email] = struct{}{}
	}
}

func checkObsoleting(o *ObsoletingConfig) {
	if (o.MinPeriod == 0) != (o.MaxPeriod == 0) {
		panic("obsoleting: both or none of Min/MaxPeriod must be specified")
	}
	if o.MinPeriod > o.MaxPeriod {
		panic(fmt.Sprintf("obsoleting: Min > MaxPeriod (%v > %v)", o.MinPeriod, o.MaxPeriod))
	}
	if o.MinPeriod != 0 && o.MinPeriod < 24*time.Hour {
		panic(fmt.Sprintf("obsoleting: too low MinPeriod: %v, want at least %v", o.MinPeriod, 24*time.Hour))
	}
	if (o.NonFinalMinPeriod == 0) != (o.NonFinalMaxPeriod == 0) {
		panic("obsoleting: both or none of NonFinalMin/MaxPeriod must be specified")
	}
	if o.NonFinalMinPeriod > o.NonFinalMaxPeriod {
		panic(fmt.Sprintf("obsoleting: NonFinalMin > MaxPeriod (%v > %v)", o.NonFinalMinPeriod, o.NonFinalMaxPeriod))
	}
	if o.NonFinalMinPeriod != 0 && o.NonFinalMinPeriod < 24*time.Hour {
		panic(fmt.Sprintf("obsoleting: too low MinPeriod: %v, want at least %v", o.NonFinalMinPeriod, 24*time.Hour))
	}
	if o.MinPeriod == 0 && o.NonFinalMinPeriod != 0 {
		panic("obsoleting: NonFinalMinPeriod without MinPeriod")
	}
	if o.ReproRetestStart == 0 {
		o.ReproRetestStart = time.Hour * 24 * 14
	}
}

func checkNamespace(ns string, cfg *Config, namespaces, clientNames map[string]bool) {
	if !namespaceNameRe.MatchString(ns) {
		panic(fmt.Sprintf("bad namespace name: %q", ns))
	}
	if namespaces[ns] {
		panic(fmt.Sprintf("duplicate namespace %q", ns))
	}
	namespaces[ns] = true
	if cfg.DisplayTitle == "" {
		cfg.DisplayTitle = ns
	}
	if cfg.SimilarityDomain == "" {
		cfg.SimilarityDomain = ns
	}
	checkClients(clientNames, cfg.Clients)
	for name, mgr := range cfg.Managers {
		checkManager(ns, name, mgr)
	}
	if !clientKeyRe.MatchString(cfg.Key) {
		panic(fmt.Sprintf("bad namespace %q key: %q", ns, cfg.Key))
	}
	if len(cfg.Reporting) == 0 {
		panic(fmt.Sprintf("no reporting in namespace %q", ns))
	}
	if cfg.TransformCrash == nil {
		cfg.TransformCrash = func(build *Build, crash *dashapi.Crash) bool {
			return true
		}
	}
	if cfg.NeedRepro == nil {
		cfg.NeedRepro = func(bug *Bug) bool {
			return true
		}
	}
	if cfg.Kcidb != nil {
		checkKcidb(ns, cfg.Kcidb)
	}
	checkKernelRepos(ns, cfg, cfg.Repos)
	checkNamespaceReporting(ns, cfg)
	checkSubsystems(ns, cfg)
}

func checkSubsystems(ns string, cfg *Config) {
	if cfg.Subsystems.Reminder == nil {
		// Nothing to validate.
		return
	}
	if cfg.Subsystems.Service == nil {
		panic(fmt.Sprintf("%v: Subsystems.Reminder is set while Subsystems.Service is nil", ns))
	}
	reminder := cfg.Subsystems.Reminder
	if reminder.SourceReporting == "" {
		panic(fmt.Sprintf("%v: Reminder.SourceReporting must be set", ns))
	}
	if reminder.Config == nil {
		panic(fmt.Sprintf("%v: Reminder.Config must be set", ns))
	}
	reporting := cfg.ReportingByName(reminder.SourceReporting)
	if reporting == nil {
		panic(fmt.Sprintf("%v: Reminder.SourceReporting %v points to a non-existent reporting",
			ns, reminder.SourceReporting))
	}
	if reporting.AccessLevel != AccessPublic {
		panic(fmt.Sprintf("%v: Reminder.SourceReporting must point to a public reporting", ns))
	}
	if reminder.PeriodDays == 0 {
		reminder.PeriodDays = 30
	} else if reminder.PeriodDays < 0 {
		panic(fmt.Sprintf("%v: Reminder.PeriodDays must be > 0", ns))
	}
	if reminder.BugsInReport == 0 {
		reminder.BugsInReport = 10
	} else if reminder.BugsInReport < 0 {
		panic(fmt.Sprintf("%v: Reminder.BugsInReport must be > 0", ns))
	}
	if reminder.MinBugAge == 0 {
		reminder.MinBugAge = 24 * time.Hour * 7
	}
	if reminder.UserReplyFrist == 0 {
		reminder.UserReplyFrist = 24 * time.Hour * 7 * 2
	}
	if reminder.MinBugsCount == 0 {
		reminder.MinBugsCount = 2
	} else if reminder.MinBugsCount < 0 {
		panic(fmt.Sprintf("%v: Reminder.MinBugsCount must be > 0", ns))
	}
}

func checkKernelRepos(ns string, config *Config, repos []KernelRepo) {
	if len(repos) == 0 {
		panic(fmt.Sprintf("no repos in namespace %q", ns))
	}
	introduced, reached := map[string]bool{}, map[string]bool{}
	aliasMap := map[string]bool{}
	canBeLabels := false
	for _, repo := range repos {
		if !vcs.CheckRepoAddress(repo.URL) {
			panic(fmt.Sprintf("%v: bad repo URL %q", ns, repo.URL))
		}
		if !vcs.CheckBranch(repo.Branch) {
			panic(fmt.Sprintf("%v: bad repo branch %q", ns, repo.Branch))
		}
		if repo.Alias == "" {
			panic(fmt.Sprintf("%v: empty repo alias for %q", ns, repo.Alias))
		}
		if aliasMap[repo.Alias] {
			panic(fmt.Sprintf("%v: duplicate alias for %q", ns, repo.Alias))
		}
		aliasMap[repo.Alias] = true
		if prio := repo.ReportingPriority; prio < 0 || prio > 9 {
			panic(fmt.Sprintf("%v: bad kernel repo reporting priority %v for %q", ns, prio, repo.Alias))
		}
		checkCC(&repo.CC)
		if repo.LabelIntroduced != "" {
			introduced[repo.LabelIntroduced] = true
			if reached[repo.LabelIntroduced] {
				panic(fmt.Sprintf("%v: label %s is used for both introduced and reached", ns, repo.LabelIntroduced))
			}
		}
		if repo.LabelReached != "" {
			reached[repo.LabelReached] = true
			if introduced[repo.LabelReached] {
				panic(fmt.Sprintf("%v: label %s is used for both introduced and reached", ns, repo.LabelReached))
			}
		}
		canBeLabels = canBeLabels || repo.DetectMissingBackports
	}
	if len(introduced)+len(reached) > 0 {
		canBeLabels = true
	}
	if canBeLabels && !config.FindBugOriginTrees {
		panic(fmt.Sprintf("%v: repo labels are set, but FindBugOriginTrees is disabled", ns))
	}
	if !canBeLabels && config.FindBugOriginTrees {
		panic(fmt.Sprintf("%v: FindBugOriginTrees is enabled, but all repo labels are disabled", ns))
	}
	// And finally test links.
	_, err := makeRepoGraph(repos)
	if err != nil {
		panic(fmt.Sprintf("%v: %s", ns, err))
	}
}

func checkCC(cc *CCConfig) {
	emails := append(append(append([]string{}, cc.Always...), cc.Maintainers...), cc.BuildMaintainers...)
	for _, email := range emails {
		if _, err := mail.ParseAddress(email); err != nil {
			panic(fmt.Sprintf("bad email address %q: %v", email, err))
		}
	}
}

func checkNamespaceReporting(ns string, cfg *Config) {
	checkConfigAccessLevel(&cfg.AccessLevel, cfg.AccessLevel, fmt.Sprintf("namespace %q", ns))
	parentAccessLevel := cfg.AccessLevel
	reportingNames := make(map[string]bool)
	// Go backwards because access levels get stricter backwards.
	for ri := len(cfg.Reporting) - 1; ri >= 0; ri-- {
		reporting := &cfg.Reporting[ri]
		if reporting.Name == "" {
			panic(fmt.Sprintf("empty reporting name in namespace %q", ns))
		}
		if reportingNames[reporting.Name] {
			panic(fmt.Sprintf("duplicate reporting name %q", reporting.Name))
		}
		if reporting.DisplayTitle == "" {
			reporting.DisplayTitle = reporting.Name
		}
		reporting.moderation = ri < len(cfg.Reporting)-1
		if !reporting.moderation && reporting.Embargo != 0 {
			panic(fmt.Sprintf("embargo in the last reporting %v", reporting.Name))
		}
		checkConfigAccessLevel(&reporting.AccessLevel, parentAccessLevel,
			fmt.Sprintf("reporting %q/%q", ns, reporting.Name))
		parentAccessLevel = reporting.AccessLevel
		if reporting.DailyLimit < 0 || reporting.DailyLimit > 1000 {
			panic(fmt.Sprintf("reporting %v: bad daily limit %v", reporting.Name, reporting.DailyLimit))
		}
		if reporting.Filter == nil {
			reporting.Filter = ConstFilter(FilterReport)
		}
		reportingNames[reporting.Name] = true
		if reporting.Config.Type() == "" {
			panic(fmt.Sprintf("empty reporting type for %q", reporting.Name))
		}
		if err := reporting.Config.Validate(); err != nil {
			panic(err)
		}
		if _, err := json.Marshal(reporting.Config); err != nil {
			panic(fmt.Sprintf("failed to json marshal %q config: %v",
				reporting.Name, err))
		}
	}
}

func checkManager(ns, name string, mgr ConfigManager) {
	if mgr.Decommissioned && mgr.DelegatedTo == "" {
		panic(fmt.Sprintf("decommissioned manager %v/%v does not have delegate", ns, name))
	}
	if !mgr.Decommissioned && mgr.DelegatedTo != "" {
		panic(fmt.Sprintf("non-decommissioned manager %v/%v has delegate", ns, name))
	}
	if mgr.RestrictedTestingRepo != "" && mgr.RestrictedTestingReason == "" {
		panic(fmt.Sprintf("restricted manager %v/%v does not have restriction reason", ns, name))
	}
	if mgr.RestrictedTestingRepo == "" && mgr.RestrictedTestingReason != "" {
		panic(fmt.Sprintf("unrestricted manager %v/%v has restriction reason", ns, name))
	}
	if (mgr.ObsoletingMinPeriod == 0) != (mgr.ObsoletingMaxPeriod == 0) {
		panic(fmt.Sprintf("manager %v/%v obsoleting: both or none of Min/MaxPeriod must be specified", ns, name))
	}
	if mgr.ObsoletingMinPeriod > mgr.ObsoletingMaxPeriod {
		panic(fmt.Sprintf("manager %v/%v obsoleting: Min > MaxPeriod", ns, name))
	}
	if mgr.ObsoletingMinPeriod != 0 && mgr.ObsoletingMinPeriod < 24*time.Hour {
		panic(fmt.Sprintf("manager %v/%v obsoleting: too low MinPeriod", ns, name))
	}
	if mgr.Priority < MinManagerPriority && mgr.Priority > MaxManagerPriority {
		panic(fmt.Sprintf("manager %v/%v priority is not in the [%d;%d] range",
			ns, name, MinManagerPriority, MaxManagerPriority))
	}
	checkCC(&mgr.CC)
}

func checkKcidb(ns string, kcidb *KcidbConfig) {
	if !regexp.MustCompile("^[a-z0-9_]+$").MatchString(kcidb.Origin) {
		panic(fmt.Sprintf("%v: bad Kcidb origin %q", ns, kcidb.Origin))
	}
	if kcidb.Project == "" {
		panic(fmt.Sprintf("%v: empty Kcidb project", ns))
	}
	if kcidb.Topic == "" {
		panic(fmt.Sprintf("%v: empty Kcidb topic", ns))
	}
	if !bytes.Contains(kcidb.Credentials, []byte("private_key")) {
		panic(fmt.Sprintf("%v: empty Kcidb credentials", ns))
	}
}

func checkConfigAccessLevel(current *AccessLevel, parent AccessLevel, what string) {
	verifyAccessLevel(parent)
	if *current == 0 {
		*current = parent
	}
	verifyAccessLevel(*current)
	if *current < parent {
		panic(fmt.Sprintf("bad %v access level %v", what, *current))
	}
}

func checkClients(clientNames map[string]bool, clients map[string]string) {
	for name, key := range clients {
		if !clientNameRe.MatchString(name) {
			panic(fmt.Sprintf("bad client name: %v", name))
		}
		if !clientKeyRe.MatchString(key) {
			panic(fmt.Sprintf("bad client key: %v", key))
		}
		if clientNames[name] {
			panic(fmt.Sprintf("duplicate client name: %v", name))
		}
		clientNames[name] = true
	}
}

func (cfg *Config) lastActiveReporting() int {
	last := len(cfg.Reporting) - 1
	for last > 0 && cfg.Reporting[last].DailyLimit == 0 {
		last--
	}
	return last
}

func (gCfg *GlobalConfig) marshalJSON() string {
	ret, err := json.MarshalIndent(gCfg, "", " ")
	if err != nil {
		panic(err)
	}
	return string(ret)
}
