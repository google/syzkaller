// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import "time"

// The output passed to other workflow steps.
type TriageResult struct {
	// If set, ignore the patch series completely.
	SkipReason string `json:"skip_reason"`
	// Fuzzing configuration to try (NULL if nothing).
	Fuzz []*FuzzTask `json:"fuzz"`
}

// The data layout faclitates the simplicity of the workflow definition.
type FuzzTask struct {
	Base    BuildRequest `json:"base"`
	Patched BuildRequest `json:"patched"`
	FuzzConfig
}

const (
	FocusNet     = "net"
	FocusKVM     = "kvm"
	FocusIoUring = "io_uring"
	FocusBPF     = "bpf"
	FocusFS      = "fs"
)

// FuzzConfig represents a set of parameters passed to the fuzz step.
// The triage step aggregates multiple KernelFuzzConfig to construct FuzzConfig.
type FuzzConfig struct {
	Track      string   `json:"track"` // E.g. KASAN.
	Focus      []string `json:"focus"`
	CorpusURLs []string `json:"corpus_urls"`
	// Don't expect kernel coverage for the patched area.
	SkipCoverCheck bool `json:"skip_cover_check"`
	// Only report the bugs that match the regexp.
	BugTitleRe string `json:"bug_title_re"`
}

// The triage step of the workflow will request these from controller.
type Tree struct {
	Name       string   `json:"name"` // Primary key.
	URL        string   `json:"URL"`
	Branch     string   `json:"branch"`
	EmailLists []string `json:"email_lists"`
}

// KernelFuzzConfig is a specific fuzzing assignment.
// Based on it, the triage step will construct FuzzTasks.
type KernelFuzzConfig struct {
	EmailLists     []string `json:"email_lists"`
	Track          string   `json:"track"` // E.g. KASAN.
	KernelConfig   string   `json:"kernel_config"`
	Focus          string   `json:"focus"`
	CorpusURL      string   `json:"corpus_url"`
	SkipCoverCheck bool     `json:"skip_cover_check"`
	BugTitleRe     string   `json:"bug_title_re"`
}

// FuzzTriageTarget is a single record in the list of supported fuzz configs.
type FuzzTriageTarget struct {
	EmailLists []string            `json:"email_lists"`
	Campaigns  []*KernelFuzzConfig `json:"campaigns"`
}

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
	TestSkipped string = "skipped"
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
// The list is ordered by decreasing importance.
var DefaultTrees = []*Tree{
	{
		Name:       `bpf-next`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf-next.git`,
		Branch:     `master`,
		EmailLists: []string{`bpf@vger.kernel.org`},
	},
	{
		Name:       `bpf`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf.git`,
		Branch:     `master`,
		EmailLists: []string{`bpf@vger.kernel.org`},
	},
	{
		Name:       `nf-next`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netfilter/nf-next.git`,
		Branch:     `main`,
		EmailLists: []string{`netfilter-devel@vger.kernel.org`},
	},
	{
		Name:       `nf`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netfilter/nf.git`,
		Branch:     `main`,
		EmailLists: []string{`netfilter-devel@vger.kernel.org`},
	},
	{
		Name:       `net-next`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net-next.git`,
		Branch:     `main`,
		EmailLists: []string{`netdev@vger.kernel.org`},
	},
	{
		Name:       `net`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net.git`,
		Branch:     `main`,
		EmailLists: []string{`netdev@vger.kernel.org`},
	},
	{
		Name:       `kvm-next`,
		URL:        `https://kernel.googlesource.com/pub/scm/virt/kvm/kvm/`,
		Branch:     `next`,
		EmailLists: []string{`kvm@vger.kernel.org`},
	},
	{
		Name:       `torvalds`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux`,
		Branch:     `master`,
		EmailLists: nil, // First fallback tree.
	},
	{
		Name:       `linux-next`,
		URL:        `https://kernel.googlesource.com/pub/scm/linux/kernel/git/next/linux-next`,
		Branch:     `master`,
		EmailLists: nil, // Second fallback tree. It's less stable, but more series can be applied.
	},
}

const (
	netCorpusURL = `https://storage.googleapis.com/syzkaller/corpus/ci-upstream-net-kasan-gce-corpus.db`
	bpfCorpusURL = `https://storage.googleapis.com/syzkaller/corpus/ci-upstream-bpf-kasan-gce-corpus.db`
	fsCorpusURL  = `https://storage.googleapis.com/syzkaller/corpus/ci2-upstream-fs-corpus.db`
	allCorpusURL = `https://storage.googleapis.com/syzkaller/corpus/ci-upstream-kasan-gce-root-corpus.db`
)

const kasanTrack = "KASAN"

// The list is ordered by decreasing importance.
var FuzzTargets = []*FuzzTriageTarget{
	{
		EmailLists: []string{`kvm@vger.kernel.org`},
		Campaigns: []*KernelFuzzConfig{
			{
				Track:        kasanTrack,
				KernelConfig: `upstream-apparmor-kasan.config`,
				Focus:        FocusKVM,
				CorpusURL:    allCorpusURL,
			},
		},
	},
	{
		EmailLists: []string{`io-uring@vger.kernel.org`},
		Campaigns: []*KernelFuzzConfig{
			{
				Track:        kasanTrack,
				KernelConfig: `upstream-apparmor-kasan.config`,
				Focus:        FocusIoUring,
				CorpusURL:    allCorpusURL,
			},
		},
	},
	{
		EmailLists: []string{`bpf@vger.kernel.org`},
		Campaigns: []*KernelFuzzConfig{
			{
				Track:        kasanTrack,
				KernelConfig: `upstream-apparmor-kasan.config`,
				Focus:        FocusBPF,
				CorpusURL:    bpfCorpusURL,
			},
		},
	},
	{
		EmailLists: []string{
			`netdev@vger.kernel.org`,
			`netfilter-devel@vger.kernel.org`,
			`linux-wireless@vger.kernel.org`,
		},
		Campaigns: []*KernelFuzzConfig{
			{
				Track:        kasanTrack,
				KernelConfig: `upstream-apparmor-kasan.config`,
				Focus:        FocusNet,
				CorpusURL:    netCorpusURL,
			},
		},
	},
	{
		EmailLists: []string{
			`linux-fsdevel@vger.kernel.org`,
			`linux-block@vger.kernel.org`,
			`linux-unionfs@vger.kernel.org`,
			`linux-ext4@vger.kernel.org`,
		},
		Campaigns: []*KernelFuzzConfig{
			{
				KernelConfig: `upstream-apparmor-kasan.config`,
				Track:        kasanTrack,
				Focus:        FocusFS,
				CorpusURL:    fsCorpusURL,
			},
		},
	},
	{
		EmailLists: []string{`linux-mm@kvack.org`},
		Campaigns: []*KernelFuzzConfig{
			{
				KernelConfig: `upstream-apparmor-kasan.config`,
				Track:        kasanTrack,
				CorpusURL:    allCorpusURL,
				// Not all mm/ code is instrumented with KCOV.
				SkipCoverCheck: true,
			},
		},
	},
	{
		EmailLists: nil, // A fallback option.
		Campaigns: []*KernelFuzzConfig{
			{
				KernelConfig: `upstream-apparmor-kasan.config`,
				Track:        kasanTrack,
				CorpusURL:    allCorpusURL,
			},
		},
	},
}
