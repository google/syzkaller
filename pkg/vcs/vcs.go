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

	// ListRecentCommits returns list of recent commit titles starting from baseCommit.
	ListRecentCommits(baseCommit string) ([]string, error)

	// ExtractFixTagsFromCommits extracts fixing tags for bugs from git log.
	// Given email = "user@domain.com", it searches for tags of the form "user+tag@domain.com"
	// and return pairs {tag, commit title}.
	ExtractFixTagsFromCommits(baseCommit, email string) ([]FixCommit, error)

	// PreviousReleaseTags returns list of preceding release tags that are reachable from the given commit.
	PreviousReleaseTags(commit string) ([]string, error)

	// Bisect bisects good..bad commit range against the provided predicate (wrapper around git bisect).
	// The predicate should return an error only if there is no way to proceed
	// (it will abort the process), if possible it should prefer to return BisectSkip.
	// Progress of the process is streamed to the provided trace.
	// Returns the first commit on which the predicate returns BisectBad.
	Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error)
}

type Commit struct {
	Hash   string
	Title  string
	Author string
	CC     []string
	Date   time.Time
}

type FixCommit struct {
	Tag   string
	Title string
}

type BisectResult int

const (
	BisectBad BisectResult = iota
	BisectGood
	BisectSkip
)

func NewRepo(os, vm, dir string) (Repo, error) {
	switch os {
	case "linux":
		return newGit(os, vm, dir), nil
	case "akaros":
		return newAkaros(vm, dir), nil
	case "fuchsia":
		return newFuchsia(vm, dir), nil
	}
	return nil, fmt.Errorf("vcs is unsupported for %v", os)
}

func NewSyzkallerRepo(dir string) Repo {
	return newGit("syzkaller", "", dir)
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
	if !gitHashRe.MatchString(hash) {
		return false
	}
	ln := len(hash)
	return ln == 8 || ln == 10 || ln == 12 || ln == 16 || ln == 20 || ln == 40
}

func runSandboxed(dir, command string, args ...string) ([]byte, error) {
	cmd := osutil.Command(command, args...)
	cmd.Dir = dir
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return nil, err
	}
	return osutil.Run(time.Hour, cmd)
}

var (
	// nolint: lll
	gitRepoRe    = regexp.MustCompile(`^(git|ssh|http|https|ftp|ftps)://[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+(:[0-9]+)?/[a-zA-Z0-9-_./]+\.git(/)?$`)
	gitBranchRe  = regexp.MustCompile("^[a-zA-Z0-9-_/.]{2,200}$")
	gitHashRe    = regexp.MustCompile("^[a-f0-9]+$")
	releaseTagRe = regexp.MustCompile(`^v([0-9]+).([0-9]+)(?:\.([0-9]+))?$`)
	ccRes        = []*regexp.Regexp{
		regexp.MustCompile(`^Reviewed\-.*: (.*)$`),
		regexp.MustCompile(`^[A-Za-z-]+\-and\-[Rr]eviewed\-.*: (.*)$`),
		regexp.MustCompile(`^Acked\-.*: (.*)$`),
		regexp.MustCompile(`^[A-Za-z-]+\-and\-[Aa]cked\-.*: (.*)$`),
		regexp.MustCompile(`^Tested\-.*: (.*)$`),
		regexp.MustCompile(`^[A-Za-z-]+\-and\-[Tt]ested\-.*: (.*)$`),
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
