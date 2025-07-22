// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import "time"

type TriageResult struct {
	// If set, ignore the patch series completely.
	Skip *SkipRequest `json:"skip"`
	// Fuzzing configuration to try (NULL if nothing).
	Fuzz *FuzzConfig `json:"fuzz"`
}

type SkipRequest struct {
	Reason    string `json:"reason"`
	TriageLog []byte `json:"log"`
}

// The data layout faclitates the simplicity of the workflow definition.
type FuzzConfig struct {
	Base      BuildRequest `json:"base"`
	Patched   BuildRequest `json:"patched"`
	Config    string       `json:"config"` // Refers to workflow/configs/{}.
	CorpusURL string       `json:"corpus_url"`
}

// The triage step of the workflow will request these from controller.
type Tree struct {
	Name         string   `json:"name"` // Primary key.
	URL          string   `json:"URL"`
	Branch       string   `json:"branch"`
	EmailLists   []string `json:"email_lists"`
	Priority     int64    `json:"priority"` // Higher numbers mean higher priority.
	KernelConfig string   `json:"kernel_config"`
	FuzzConfig   string   `json:"fuzz_config"`
}

// Select only if directly specified in the series subject.
const TreePriorityNever = -1

type BuildRequest struct {
	Arch       string `json:"arch"`
	TreeName   string `json:"tree_name"`
	TreeURL    string `json:"tree_url"`
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
	TreeURL      string    `json:"tree_url"`
	CommitHash   string    `json:"commit_hash"`
	CommitDate   time.Time `json:"commit_date"`
	ConfigName   string    `json:"config_name"`
	SeriesID     string    `json:"series_id"`
	Compiler     string    `json:"compiler"`
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
	SessionID    string `json:"session_id"`
	TestName     string `json:"test_name"`
	Title        string `json:"title"`
	Report       []byte `json:"report"`
	Log          []byte `json:"log"`
	SyzRepro     []byte `json:"syz_repro"`
	SyzReproOpts []byte `json:"syz_repro_opts"`
	CRepro       []byte `json:"c_repro"`
}

type Series struct {
	ID          string        `json:"id"` // Only included in the reply.
	ExtID       string        `json:"ext_id"`
	Title       string        `json:"title"`
	AuthorEmail string        `json:"author_email"`
	Cc          []string      `json:"cc"`
	Version     int           `json:"version"`
	Link        string        `json:"link"`
	SubjectTags []string      `json:"subject_tags"`
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
	ID         string     `json:"id"`
	Moderation bool       `json:"moderation"`
	Series     *Series    `json:"series"`
	Findings   []*Finding `json:"findings"`
	Link       string     `json:"link"` // URL to the web dashboard.
}

type Finding struct {
	Title        string    `json:"title"`
	Report       string    `json:"report"`
	LogURL       string    `json:"log_url"`
	Build        BuildInfo `json:"build"`
	LinkCRepro   string    `json:"c_repro"`
	LinkSyzRepro string    `json:"syz_repro"`
}

type BuildInfo struct {
	TreeName   string `json:"tree_name"`
	TreeURL    string `json:"tree_url"`
	BaseCommit string `json:"base_commit"`
	Arch       string `json:"arch"`
	Compiler   string `json:"compiler"`
	ConfigLink string `json:"config_link"`
}

// Let them stay here until we find a better place.
var DefaultTrees = []*Tree{
	{
		Name:         `torvalds`,
		URL:          `https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux`,
		Branch:       `master`,
		Priority:     0,
		EmailLists:   []string{},
		KernelConfig: `upstream-apparmor-kasan.config`,
		FuzzConfig:   `all`,
	},
	{
		Name:         `net`,
		URL:          `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net.git`,
		Branch:       `main`,
		Priority:     TreePriorityNever,
		EmailLists:   []string{`netdev@vger.kernel.org`},
		KernelConfig: `upstream-apparmor-kasan.config`,
		FuzzConfig:   `net`,
	},
	{
		Name:         `net-next`,
		URL:          `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net.git`,
		Branch:       `main`,
		Priority:     1,
		EmailLists:   []string{`netdev@vger.kernel.org`},
		KernelConfig: `upstream-apparmor-kasan.config`,
		FuzzConfig:   `net`,
	},
	{
		Name:         `nf`,
		URL:          `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netfilter/nf.git`,
		Branch:       `main`,
		Priority:     TreePriorityNever,
		EmailLists:   []string{`netfilter-devel@vger.kernel.org`},
		KernelConfig: `upstream-apparmor-kasan.config`,
		FuzzConfig:   `net`,
	},
	{
		Name:         `nf-next`,
		URL:          `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netfilter/nf-next.git`,
		Branch:       `main`,
		Priority:     2,
		EmailLists:   []string{`netfilter-devel@vger.kernel.org`},
		KernelConfig: `upstream-apparmor-kasan.config`,
		FuzzConfig:   `net`,
	},
}

const (
	netCorpusURL      = `https://storage.googleapis.com/syzkaller/corpus/ci-upstream-net-kasan-gce-corpus.db`
	corpusFallbackURL = `https://storage.googleapis.com/syzkaller/corpus/ci-upstream-kasan-gce-root-corpus.db`
)

// TODO: find a better place for it.
func (tree *Tree) CorpusURL() string {
	switch tree.FuzzConfig {
	case `net`, `net-next`, `nf`, `nf-next`:
		return netCorpusURL
	default:
		return corpusFallbackURL
	}
}
