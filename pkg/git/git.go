// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package git provides helper functions for working with git repositories.
package git

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const (
	DateFormat = "Mon Jan 2 15:04:05 2006 -0700"
	timeout    = time.Hour // timeout for all git invocations
)

// Poll checkouts the specified repository/branch in dir.
// This involves fetching/resetting/cloning as necessary to recover from all possible problems.
// Returns hash of the HEAD commit in the specified branch.
func Poll(dir, repo, branch string) (*Commit, error) {
	runSandboxed(dir, "git", "reset", "--hard")
	origin, err := runSandboxed(dir, "git", "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(origin)) != repo {
		// The repo is here, but it has wrong origin (e.g. repo in config has changed), re-clone.
		if err := clone(dir, repo, branch); err != nil {
			return nil, err
		}
	}
	// Use origin/branch for the case the branch was force-pushed,
	// in such case branch is not the same is origin/branch and we will
	// stuck with the local version forever (git checkout won't fail).
	if _, err := runSandboxed(dir, "git", "checkout", "origin/"+branch); err != nil {
		// No such branch (e.g. branch in config has changed), re-clone.
		if err := clone(dir, repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := runSandboxed(dir, "git", "fetch", "--no-tags"); err != nil {
		// Something else is wrong, re-clone.
		if err := clone(dir, repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := runSandboxed(dir, "git", "checkout", "origin/"+branch); err != nil {
		return nil, err
	}
	return HeadCommit(dir)
}

// CheckoutBranch checkouts the specified repository/branch in dir.
func CheckoutBranch(dir, repo, branch string) (*Commit, error) {
	if _, err := runSandboxed(dir, "git", "reset", "--hard"); err != nil {
		if err := initRepo(dir); err != nil {
			return nil, err
		}
	}
	_, err := runSandboxed(dir, "git", "fetch", repo, branch)
	if err != nil {
		return nil, err
	}
	if _, err := runSandboxed(dir, "git", "checkout", "FETCH_HEAD"); err != nil {
		return nil, err
	}
	return HeadCommit(dir)
}

// CheckoutCommit checkouts the specified repository on the specified commit in dir.
func CheckoutCommit(dir, repo, commit string) (*Commit, error) {
	if _, err := runSandboxed(dir, "git", "reset", "--hard"); err != nil {
		if err := initRepo(dir); err != nil {
			return nil, err
		}
	}
	_, err := runSandboxed(dir, "git", "fetch", repo)
	if err != nil {
		return nil, err
	}
	if _, err := runSandboxed(dir, "git", "checkout", commit); err != nil {
		return nil, err
	}
	return HeadCommit(dir)
}

func clone(dir, repo, branch string) error {
	if err := initRepo(dir); err != nil {
		return err
	}
	if _, err := runSandboxed(dir, "git", "remote", "add", "origin", repo); err != nil {
		return err
	}
	if _, err := runSandboxed(dir, "git", "fetch", "origin", branch); err != nil {
		return err
	}
	return nil
}

func initRepo(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %v", err)
	}
	if err := osutil.MkdirAll(dir); err != nil {
		return fmt.Errorf("failed to create repo dir: %v", err)
	}
	if err := osutil.SandboxChown(dir); err != nil {
		return err
	}
	if _, err := runSandboxed(dir, "git", "init"); err != nil {
		return err
	}
	return nil
}

type Commit struct {
	Hash  string
	Title string
	Date  time.Time
}

// HeadCommit returns info about the HEAD commit of the current branch of git repository in dir.
func HeadCommit(dir string) (*Commit, error) {
	output, err := runSandboxed(dir, "git", "log", "--pretty=format:%H%n%s%n%ad", "-n", "1")
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(output, []byte{'\n'})
	if len(lines) != 3 || len(lines[0]) != 40 {
		return nil, fmt.Errorf("unexpected git log output: %q", output)
	}
	date, err := time.Parse(DateFormat, string(lines[2]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse date in git log output: %v\n%q", err, output)
	}
	com := &Commit{
		Hash:  string(lines[0]),
		Title: string(lines[1]),
		Date:  date,
	}
	return com, nil
}

// ListRecentCommits returns list of recent commit titles starting from baseCommit.
func ListRecentCommits(dir, baseCommit string) ([]string, error) {
	// On upstream kernel this produces ~11MB of output.
	// Somewhat inefficient to collect whole output in a slice
	// and then convert to string, but should be bearable.
	output, err := runSandboxed(dir, "git", "log",
		"--pretty=format:%s", "--no-merges", "-n", "200000", baseCommit)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), "\n"), nil
}

type FixCommit struct {
	Tag   string
	Title string
}

// ExtractFixTagsFromCommits extracts fixing tags for bugs from git log.
// Given email = "user@domain.com", it searches for tags of the form "user+tag@domain.com"
// and return pairs {tag, commit title}.
func ExtractFixTagsFromCommits(dir, baseCommit, email string) ([]FixCommit, error) {
	since := time.Now().Add(-time.Hour * 24 * 365).Format("01-02-2006")
	cmd := exec.Command("git", "log", "--no-merges", "--since", since, baseCommit)
	cmd.Dir = dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	return extractFixTags(stdout, email)
}

func extractFixTags(r io.Reader, email string) ([]FixCommit, error) {
	user, domain, err := splitEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email %q: %v", email, err)
	}
	var (
		s           = bufio.NewScanner(r)
		commits     []FixCommit
		commitTitle = ""
		commitStart = []byte("commit ")
		bodyPrefix  = []byte("    ")
		userBytes   = []byte(user + "+")
		domainBytes = []byte(domain)
	)
	for s.Scan() {
		ln := s.Bytes()
		if bytes.HasPrefix(ln, commitStart) {
			commitTitle = ""
			continue
		}
		if !bytes.HasPrefix(ln, bodyPrefix) {
			continue
		}
		ln = ln[len(bodyPrefix):]
		if len(ln) == 0 {
			continue
		}
		if commitTitle == "" {
			commitTitle = string(ln)
			continue
		}
		userPos := bytes.Index(ln, userBytes)
		if userPos == -1 {
			continue
		}
		domainPos := bytes.Index(ln[userPos+len(userBytes)+1:], domainBytes)
		if domainPos == -1 {
			continue
		}
		startPos := userPos + len(userBytes)
		endPos := userPos + len(userBytes) + domainPos + 1
		tag := string(ln[startPos:endPos])
		commits = append(commits, FixCommit{tag, commitTitle})
	}
	return commits, s.Err()
}

func splitEmail(email string) (user, domain string, err error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", "", err
	}
	at := strings.IndexByte(addr.Address, '@')
	if at == -1 {
		return "", "", fmt.Errorf("no @ in email address")
	}
	user = addr.Address[:at]
	domain = addr.Address[at:]
	if plus := strings.IndexByte(user, '+'); plus != -1 {
		user = user[:plus]
	}
	return
}

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

func runSandboxed(dir, command string, args ...string) ([]byte, error) {
	cmd := osutil.Command(command, args...)
	cmd.Dir = dir
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return nil, err
	}
	return osutil.Run(timeout, cmd)
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

var (
	gitRepoRe   = regexp.MustCompile(`^(git|ssh|http|https|ftp|ftps)://[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+(:[0-9]+)?/[a-zA-Z0-9-_./]+\.git(/)?$`)
	gitBranchRe = regexp.MustCompile("^[a-zA-Z0-9-_/.]{2,200}$")
	gitHashRe   = regexp.MustCompile("^[a-f0-9]+$")
)
