// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
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
	Clients map[string]string
	// A unique key for hashing, can be anything.
	Key string
	// Mail bugs without reports (e.g. "no output").
	MailWithoutReport bool
	// How long should we wait before reporting a bug.
	ReportingDelay time.Duration
	// How long should we wait for a C repro before reporting a bug.
	WaitForRepro time.Duration
	// If set, successful fix bisections will auto-close the bug.
	FixBisectionAutoClose bool
	// Managers contains some special additional info about syz-manager instances.
	Managers map[string]ConfigManager
	// Reporting config.
	Reporting []Reporting
	// TransformCrash hook is called when a manager uploads a crash.
	// The hook can transform the crash or discard the crash by returning false.
	TransformCrash func(build *Build, crash *dashapi.Crash) bool
	// NeedRepro hook can be used to prevent reproduction of some bugs.
	NeedRepro func(bug *Bug) bool
	// List of kernel repositories for this namespace.
	// The first repo considered the "main" repo (e.g. fixing commit info is shown against this repo).
	// Other repos are secondary repos, they may be tested or not.
	// If not tested they are used to poll for fixing commits.
	Repos []KernelRepo
}

// ObsoletingConfig describes how bugs without reproducer should be obsoleted.
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
}

// One reporting stage.
type Reporting struct {
	// See GlobalConfig.AccessLevel.
	AccessLevel AccessLevel
	// A unique name (the app does not care about exact contents).
	Name string
	// Name used in UI.
	DisplayTitle string
	// Filter can be used to conditionally skip this reporting or hold off reporting.
	Filter ReportingFilter
	// How many new bugs report per day.
	DailyLimit int
	// Upstream reports into next reporting after this period.
	Embargo time.Duration
	// Type of reporting and its configuration.
	// The app has one built-in type, EmailConfig, which reports bugs by email.
	// And ExternalConfig which can be used to attach any external reporting system (e.g. Bugzilla).
	Config ReportingType

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
	// Additional CC list to add to all bugs reported on this repo.
	CC []string
	// Additional CC list to add to bugs if we are mailing maintainers.
	Maintainers []string
	// Additional CC list to add to build/boot bugs if we are mailing maintainers.
	BuildMaintainers []string
}

var (
	namespaceNameRe = regexp.MustCompile("^[a-zA-Z0-9-_.]{4,32}$")
	clientNameRe    = regexp.MustCompile("^[a-zA-Z0-9-_.]{4,100}$")
	clientKeyRe     = regexp.MustCompile("^[a-zA-Z0-9]{16,128}$")
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

// config is installed either by tests or from mainConfig in main function
// (a separate file should install mainConfig in an init function).
var (
	config     *GlobalConfig
	mainConfig *GlobalConfig
)

func installConfig(cfg *GlobalConfig) {
	checkConfig(cfg)
	if config != nil {
		panic("another config is already installed")
	}
	config = cfg
	initEmailReporting()
	initHTTPHandlers()
	initAPIHandlers()
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
	namespaces := make(map[string]bool)
	clientNames := make(map[string]bool)
	checkClients(clientNames, cfg.Clients)
	checkConfigAccessLevel(&cfg.AccessLevel, AccessPublic, "global")
	checkObsoleting(cfg.Obsoleting)
	if cfg.Namespaces[cfg.DefaultNamespace] == nil {
		panic(fmt.Sprintf("default namespace %q is not found", cfg.DefaultNamespace))
	}
	for ns, cfg := range cfg.Namespaces {
		checkNamespace(ns, cfg, namespaces, clientNames)
	}
}

func checkObsoleting(o ObsoletingConfig) {
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
	checkKernelRepos(ns, cfg)
	checkNamespaceReporting(ns, cfg)
}

func checkKernelRepos(ns string, cfg *Config) {
	if len(cfg.Repos) == 0 {
		panic(fmt.Sprintf("no repos in namespace %q", ns))
	}
	for _, repo := range cfg.Repos {
		if !vcs.CheckRepoAddress(repo.URL) {
			panic(fmt.Sprintf("%v: bad repo URL %q", ns, repo.URL))
		}
		if !vcs.CheckBranch(repo.Branch) {
			panic(fmt.Sprintf("%v: bad repo branch %q", ns, repo.Branch))
		}
		if repo.Alias == "" {
			panic(fmt.Sprintf("%v: empty repo alias for %q", ns, repo.Alias))
		}
		if prio := repo.ReportingPriority; prio < 0 || prio > 9 {
			panic(fmt.Sprintf("%v: bad kernel repo reporting priority %v for %q", ns, prio, repo.Alias))
		}
		emails := append(append(append([]string{}, repo.CC...), repo.Maintainers...), repo.BuildMaintainers...)
		for _, email := range emails {
			if _, err := mail.ParseAddress(email); err != nil {
				panic(fmt.Sprintf("bad email address %q: %v", email, err))
			}
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
