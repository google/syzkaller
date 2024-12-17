// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import "time"

type Series struct {
	PublishedAt time.Time
	Cc          []string
	Patches     [][]byte
}

type TriageResult struct {
	// If true, ignore the patch series completely.
	Skip bool `json:"skip"`
	// Fuzzing configurations to try.
	Fuzz []*FuzzConfig `json:"fuzz"`
}

// The data layout faclitates the simplicity of the workflow definition.
type FuzzConfig struct {
	Base    BuildRequest `json:"base"`
	Patched BuildRequest `json:"patched"`
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

type TestResult struct {
	SessionID      string `json:"session_id"`
	BaseBuildID    string `json:"base_build_id"`
	PatchedBuildID string `json:"patched_build_id"`
	TestName       string `json:"test_name"`
	Result         string `json:"result"`
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
