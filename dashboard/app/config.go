// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/syzkaller/pkg/email"
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
	// Global API clients that work across namespaces (e.g. external reporting).
	Clients map[string]string
	// List of emails blacklisted from issuing test requests.
	EmailBlacklist []string
	// Per-namespace config.
	// Namespaces are a mechanism to separate groups of different kernels.
	// E.g. Debian 4.4 kernels and Ubuntu 4.9 kernels.
	// Each namespace has own reporting config, own API clients
	// and bugs are not merged across namespaces.
	Namespaces map[string]*Config
	// Maps full repository address/branch to description of this repo.
	KernelRepos map[string]KernelRepo
}

// Per-namespace config.
type Config struct {
	// See GlobalConfig.AccessLevel.
	AccessLevel AccessLevel
	// Name used in UI.
	DisplayTitle string
	// URL of a source coverage report for this namespace
	// (uploading/updating the report is out of scope of the system for now).
	CoverLink string
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
	// Managers contains some special additional info about syz-manager instances.
	Managers map[string]ConfigManager
	// Reporting config.
	Reporting []Reporting
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
	// Type of reporting and its configuration.
	// The app has one built-in type, EmailConfig, which reports bugs by email.
	// And ExternalConfig which can be used to attach any external reporting system (e.g. Bugzilla).
	Config ReportingType
}

type ReportingType interface {
	// Type returns a unique string that identifies this reporting type (e.g. "email").
	Type() string
	// NeedMaintainers says if this reporting requires non-empty maintainers list.
	NeedMaintainers() bool
	// Validate validates the current object, this is called only during init.
	Validate() error
}

type KernelRepo struct {
	// Alias is a short, readable name of a kernel repository.
	Alias string
	// ReportingPriority says if we need to prefer to report crashes in this
	// repo over crashes in repos with lower value. Must be in [0-9] range.
	ReportingPriority int
}

var (
	clientNameRe = regexp.MustCompile("^[a-zA-Z0-9-_]{4,100}$")
	clientKeyRe  = regexp.MustCompile("^[a-zA-Z0-9]{16,128}$")
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

func (cfg *Config) ReportingByName(name string) *Reporting {
	for i := range cfg.Reporting {
		reporting := &cfg.Reporting[i]
		if reporting.Name == name {
			return reporting
		}
	}
	return nil
}

// config is populated by installConfig which should be called either from tests
// or from a separate file that provides actual production config.
var config *GlobalConfig

func init() {
	// Prevents gometalinter from considering everything as dead code.
	if false {
		installConfig(nil)
	}
}

func installConfig(cfg *GlobalConfig) {
	if config != nil {
		panic("another config is already installed")
	}
	// Validate the global cfg.
	if len(cfg.Namespaces) == 0 {
		panic("no namespaces found")
	}
	for i := range cfg.EmailBlacklist {
		cfg.EmailBlacklist[i] = email.CanonicalEmail(cfg.EmailBlacklist[i])
	}
	namespaces := make(map[string]bool)
	clientNames := make(map[string]bool)
	checkClients(clientNames, cfg.Clients)
	checkConfigAccessLevel(&cfg.AccessLevel, AccessPublic, "global")
	for ns, cfg := range cfg.Namespaces {
		checkNamespace(ns, cfg, namespaces, clientNames)
	}
	for repo, info := range cfg.KernelRepos {
		if info.Alias == "" {
			panic(fmt.Sprintf("empty kernel repo alias for %q", repo))
		}
		if prio := info.ReportingPriority; prio < 0 || prio > 9 {
			panic(fmt.Sprintf("bad kernel repo reporting priority %v for %q", prio, repo))
		}
	}
	config = cfg
	initEmailReporting()
	initHTTPHandlers()
	initAPIHandlers()
}

func checkNamespace(ns string, cfg *Config, namespaces, clientNames map[string]bool) {
	if ns == "" {
		panic("empty namespace name")
	}
	if namespaces[ns] {
		panic(fmt.Sprintf("duplicate namespace %q", ns))
	}
	namespaces[ns] = true
	if cfg.DisplayTitle == "" {
		cfg.DisplayTitle = ns
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
		checkConfigAccessLevel(&reporting.AccessLevel, parentAccessLevel,
			fmt.Sprintf("reporting %q/%q", ns, reporting.Name))
		parentAccessLevel = reporting.AccessLevel
		if reporting.Filter == nil {
			reporting.Filter = func(bug *Bug) FilterResult { return FilterReport }
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
