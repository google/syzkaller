// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import "time"

type Series struct {
	ID          string
	PublishedAt time.Time
	Cc          []string
	Patches     [][]byte
}

type TriageResult struct {
	// If true, ignore the patch series completely.
	Skip *SkipRequest `json:"skip"`
	// Fuzzing configurations to try.
	Fuzz []*FuzzConfig `json:"fuzz"`
}

type SkipRequest struct {
	Reason string `json:"reason"`
}

// The data layout faclitates the simplicity of the workflow definition.
type FuzzConfig struct {
	Base    BuildRequest `json:"base"`
	Patched BuildRequest `json:"patched"`
	Config  string       `json:"config"` // Refers to workflow/configs/{}.
}

// The triage step of the workflow will request these from controller.
type Tree struct {
	Name       string   `json:"name"` // Primary key.
	URL        string   `json:"URL"`
	Branch     string   `json:"branch"`
	EmailLists []string `json:"email_lists"`
	Priority   int64    `json:"priority"` // Higher numbers mean higher priority.
	ConfigName string   `json:"config_name"`
}

type BuildRequest struct {
	Arch       string `json:"arch"`
	TreeName   string `json:"tree_name"`
	CommitHash string `json:"commit_hash"`
	ConfigName string `json:"config_name"` // These are known to both the triage and build steps.
	SeriesID   string `json:"series_id"`
}

// BuildResult is returned from the build workflow step.
type BuildResult struct {
	BuildID string `json:"build_id"`
	Success bool   `json:"success"`
}

type Build struct {
	Arch         string    `json:"arch"`
	TreeName     string    `json:"tree_name"`
	CommitHash   string    `json:"commit_hash"`
	CommitDate   time.Time `json:"commit_date"`
	ConfigName   string    `json:"config_name"`
	SeriesID     string    `json:"series_id"`
	BuildSuccess bool      `json:"build_success"`
}

const (
	TestRunning string = "running"
	TestPassed  string = "passed"
	TestFailed  string = "failed" // TODO: drop it? only mark completion?
	TestError   string = "error"
)

type TestResult struct {
	SessionID      string `json:"session_id"`
	BaseBuildID    string `json:"base_build_id"`
	PatchedBuildID string `json:"patched_build_id"`
	TestName       string `json:"test_name"`
	Result         string `json:"result"`
	Log            []byte `json:"log"`
}

type BootResult struct {
	Success bool `json:"success"`
}

// Finding is a kernel crash, boot error, etc. found during a test.
type Finding struct {
	SessionID string `json:"session_id"`
	TestName  string `json:"test_name"`
	Title     string `json:"title"`
	Report    []byte `json:"report"`
	Log       []byte `json:"log"`
}

// For now, there's no reason to obtain these really via a real API call.
var defaultTrees = []*Tree{
	{
		Name:       `torvalds`,
		URL:        `git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`,
		Branch:     `master`,
		Priority:   0,
		EmailLists: []string{},
		ConfigName: `upstream-apparmor-kasan.config`,
	},
}
