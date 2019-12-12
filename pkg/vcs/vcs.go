// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vcs provides helper functions for working with various repositories (e.g. git).
package vcs

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type Repo interface {
	// Poll checkouts the specified repository/branch.
	// This involves fetching/resetting/cloning as necessary to recover from all possible problems.
	// Returns hash of the HEAD commit in the specified branch.
	Poll(repo, branch string) (*Commit, error)

	// CheckoutBranch checkouts the specified repository/branch.
	CheckoutBranch(repo, branch string) (*Commit, error)

	// CheckoutCommit checkouts the specified repository on the specified commit.
	CheckoutCommit(repo, commit string) (*Commit, error)

	// SwitchCommit checkouts the specified commit without fetching.
	SwitchCommit(commit string) (*Commit, error)

	// HeadCommit returns info about the HEAD commit of the current branch of git repository.
	HeadCommit() (*Commit, error)

	// GetCommitByTitle finds commit info by the title.
	// Remote is not fetched, the commit needs to be reachable from the current repo state
	// (e.g. do CheckoutBranch before). If the commit is not found, nil is returned.
	GetCommitByTitle(title string) (*Commit, error)

	// GetCommitsByTitles is a batch version of GetCommitByTitle.
	// Returns list of commits and titles of commits that are not found.
	GetCommitsByTitles(titles []string) ([]*Commit, []string, error)

	// ListRecentCommits returns list of recent commit titles starting from baseCommit.
	ListRecentCommits(baseCommit string) ([]string, error)

	// ExtractFixTagsFromCommits extracts fixing tags for bugs from git log.
	// Given email = "user@domain.com", it searches for tags of the form "user+tag@domain.com"
	// and returns commits with these tags.
	ExtractFixTagsFromCommits(baseCommit, email string) ([]*Commit, error)
}

// Bisecter may be optionally implemented by Repo.
type Bisecter interface {
	// Bisect bisects good..bad commit range against the provided predicate (wrapper around git bisect).
	// The predicate should return an error only if there is no way to proceed
	// (it will abort the process), if possible it should prefer to return BisectSkip.
	// Progress of the process is streamed to the provided trace.
	// Returns the first commit on which the predicate returns BisectBad,
	// or multiple commits if bisection is inconclusive due to BisectSkip.
	Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) ([]*Commit, error)

	// PreviousReleaseTags returns list of preceding release tags that are reachable from the given commit.
	PreviousReleaseTags(commit string) ([]string, error)

	IsRelease(commit string) (bool, error)

	EnvForCommit(binDir, commit string, kernelConfig []byte) (*BisectEnv, error)
}

type Commit struct {
	Hash       string
	Title      string
	Author     string
	AuthorName string
	CC         []string
	Tags       []string
	Parents    []string
	Date       time.Time
}

type BisectResult int

const (
	BisectBad BisectResult = iota
	BisectGood
	BisectSkip
)

type BisectEnv struct {
	Compiler     string
	KernelConfig []byte
}

func NewRepo(os, vm, dir string) (Repo, error) {
	switch os {
	case "linux":
		return newLinux(dir), nil
	case "akaros":
		return newAkaros(vm, dir), nil
	case "fuchsia":
		return newFuchsia(vm, dir), nil
	case "openbsd":
		return newOpenBSD(vm, dir), nil
	case "netbsd":
		return newNetBSD(vm, dir), nil
	case "freebsd":
		return newFreeBSD(vm, dir), nil
	case "test":
		return newTestos(dir), nil
	}
	return nil, fmt.Errorf("vcs is unsupported for %v", os)
}

func NewSyzkallerRepo(dir string) Repo {
	return newGit(dir, nil)
}

func Patch(dir string, patch []byte) error {
	// Do --dry-run first to not mess with partially consistent state.
	cmd := osutil.Command("patch", "-p1", "--force", "--ignore-whitespace", "--dry-run")
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return err
	}
	cmd.Stdin = bytes.NewReader(patch)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		// If it reverses clean, then it's already applied
		// (seems to be the easiest way to detect it).
		cmd = osutil.Command("patch", "-p1", "--force", "--ignore-whitespace", "--reverse", "--dry-run")
		if err := osutil.Sandbox(cmd, true, true); err != nil {
			return err
		}
		cmd.Stdin = bytes.NewReader(patch)
		cmd.Dir = dir
		if _, err := cmd.CombinedOutput(); err == nil {
			return fmt.Errorf("patch is already applied")
		}
		return fmt.Errorf("failed to apply patch:\n%s", output)
	}
	// Now apply for real.
	cmd = osutil.Command("patch", "-p1", "--force", "--ignore-whitespace")
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return err
	}
	cmd.Stdin = bytes.NewReader(patch)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply patch after dry run:\n%s", output)
	}
	return nil
}

// CheckRepoAddress does a best-effort approximate check of a git repo address.
func CheckRepoAddress(repo string) bool {
	return gitRepoRe.MatchString(repo)
}

// CheckBranch does a best-effort approximate check of a git branch name.
func CheckBranch(branch string) bool {
	return gitBranchRe.MatchString(branch)
}

func CheckCommitHash(hash string) bool {
	return gitHashRe.MatchString(hash)
}

func runSandboxed(dir, command string, args ...string) ([]byte, error) {
	return runSandboxedEnv(dir, command, nil, args...)
}

func runSandboxedEnv(dir, command string, env []string, args ...string) ([]byte, error) {
	cmd := osutil.Command(command, args...)
	cmd.Dir = dir
	cmd.Env = env
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return nil, err
	}
	return osutil.Run(time.Hour, cmd)
}

var (
	// nolint: lll
	gitRepoRe    = regexp.MustCompile(`^(git|ssh|http|https|ftp|ftps)://[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+(:[0-9]+)?(/[a-zA-Z0-9-_./]+)?(/)?$`)
	gitBranchRe  = regexp.MustCompile("^[a-zA-Z0-9-_/.]{2,200}$")
	gitHashRe    = regexp.MustCompile("^[a-f0-9]{8,40}$")
	releaseTagRe = regexp.MustCompile(`^v([0-9]+).([0-9]+)(?:\.([0-9]+))?$`)
	// CC: is intentionally not on this list, see #1441.
	ccRes = []*regexp.Regexp{
		regexp.MustCompile(`^Reviewed\-.*: (.*)$`),
		regexp.MustCompile(`^[A-Za-z-]+\-and\-[Rr]eviewed\-.*: (.*)$`),
		regexp.MustCompile(`^Acked\-.*: (.*)$`),
		regexp.MustCompile(`^[A-Za-z-]+\-and\-[Aa]cked\-.*: (.*)$`),
		regexp.MustCompile(`^Tested\-.*: (.*)$`),
		regexp.MustCompile(`^[A-Za-z-]+\-and\-[Tt]ested\-.*: (.*)$`),
		regexp.MustCompile(`^Signed-off-by: (.*)$`),
	}
)

// CanonicalizeCommit returns commit title that can be used when checking
// if a particular commit is present in a git tree.
// Some trees add prefixes to commit titles during backporting,
// so we want e.g. commit "foo bar" match "BACKPORT: foo bar".
func CanonicalizeCommit(title string) string {
	for _, prefix := range commitPrefixes {
		if strings.HasPrefix(title, prefix) {
			title = title[len(prefix):]
			break
		}
	}
	return strings.TrimSpace(title)
}

var commitPrefixes = []string{
	"UPSTREAM:",
	"CHROMIUM:",
	"FROMLIST:",
	"BACKPORT:",
	"FROMGIT:",
	"net-backports:",
}

const SyzkallerRepo = "https://github.com/google/syzkaller"

func CommitLink(url, hash string) string {
	return link(url, hash, 0)
}

func TreeLink(url, hash string) string {
	return link(url, hash, 1)
}

func LogLink(url, hash string) string {
	return link(url, hash, 2)
}

func link(url, hash string, typ int) string {
	if url == "" || hash == "" {
		return ""
	}
	switch url {
	case "https://fuchsia.googlesource.com":
		// We collect hashes from the fuchsia repo.
		return link(url+"/fuchsia", hash, typ)
	}
	if strings.HasPrefix(url, "https://github.com/") {
		url = strings.TrimSuffix(url, ".git")
		switch typ {
		case 1:
			return url + "/tree/" + hash
		case 2:
			return url + "/commits/" + hash
		default:
			return url + "/commit/" + hash
		}
	}
	if strings.HasPrefix(url, "https://git.kernel.org/pub/scm/") ||
		strings.HasPrefix(url, "git://git.kernel.org/pub/scm/") {
		url = strings.TrimPrefix(url, "git")
		url = strings.TrimPrefix(url, "https")
		switch typ {
		case 1:
			return "https" + url + "/tree/?id=" + hash
		case 2:
			return "https" + url + "/log/?id=" + hash
		default:
			return "https" + url + "/commit/?id=" + hash
		}
	}
	if strings.HasPrefix(url, "https://") && strings.Contains(url, ".googlesource.com") {
		switch typ {
		case 1:
			return url + "/+/" + hash + "/"
		case 2:
			return url + "/+log/" + hash
		default:
			return url + "/+/" + hash + "^!"
		}
	}
	return ""
}
