// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import "time"

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

// NewFinding is a kernel crash, boot error, etc. found during a test.
type NewFinding struct {
	SessionID string `json:"session_id"`
	TestName  string `json:"test_name"`
	Title     string `json:"title"`
	Report    []byte `json:"report"`
	Log       []byte `json:"log"`
}

type Series struct {
	ID          string        `json:"id"` // Only included in the reply.
	ExtID       string        `json:"ext_id"`
	Title       string        `json:"title"`
	AuthorEmail string        `json:"author_email"`
	Cc          []string      `json:"cc"`
	Version     int           `json:"version"`
	Link        string        `json:"link"`
	PublishedAt time.Time     `json:"published_at"`
	Patches     []SeriesPatch `json:"patches"`
}

func (s *Series) PatchBodies() [][]byte {
	var ret [][]byte
	for _, patch := range s.Patches {
		ret = append(ret, patch.Body)
	}
	return ret
}

type SeriesPatch struct {
	Seq   int    `json:"seq"`
	Title string `json:"title"`
	Link  string `json:"link"`
	Body  []byte `json:"body"`
}

type NewSession struct {
	ExtID string   `json:"ext_id"`
	Tags  []string `json:"tags"`
}

type SessionReport struct {
	ID         string `json:"id"`
	Moderation bool   `json:"moderation"`
	// TODO: add some session info?
	Series   *Series    `json:"series"`
	Findings []*Finding `json:"findings"`
	Link     string     `json:"link"` // URL to the web dashboard.
}

type Finding struct {
	Title  string `json:"title"`
	Report []byte `json:"report"`
	LogURL string `json:"log_url"`
}

// For now, there's no reason to obtain these really via a real API call.
var defaultTrees = []*Tree{
	{
		Name: `torvalds`,
		// TODO: consider https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.
		URL:        `git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`,
		Branch:     `master`,
		Priority:   0,
		EmailLists: []string{},
		ConfigName: `upstream-apparmor-kasan.config`,
	},
}
