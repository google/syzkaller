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
	"sort"
	"strconv"
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
	runSandboxed(dir, "git", "bisect", "reset")
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
	runSandboxed(dir, "git", "bisect", "reset")
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
	runSandboxed(dir, "git", "bisect", "reset")
	if _, err := runSandboxed(dir, "git", "reset", "--hard"); err != nil {
		if err := initRepo(dir); err != nil {
			return nil, err
		}
	}
	_, err := runSandboxed(dir, "git", "fetch", repo)
	if err != nil {
		return nil, err
	}
	return SwitchCommit(dir, commit)
}

// SwitchCommit checkouts the specified commit without fetching.
func SwitchCommit(dir, commit string) (*Commit, error) {
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
	Hash   string
	Title  string
	Author string
	CC     []string
	Date   time.Time
}

// HeadCommit returns info about the HEAD commit of the current branch of git repository in dir.
func HeadCommit(dir string) (*Commit, error) {
	return GetCommit(dir, "HEAD")
}

func GetCommit(dir, commit string) (*Commit, error) {
	output, err := runSandboxed(dir, "git", "log", "--format=%H%n%s%n%ae%n%ad%n%b", "-n", "1", commit)
	if err != nil {
		return nil, err
	}
	return parseCommit(output)
}

func parseCommit(output []byte) (*Commit, error) {
	lines := bytes.Split(output, []byte{'\n'})
	if len(lines) < 4 || len(lines[0]) != 40 {
		return nil, fmt.Errorf("unexpected git log output: %q", output)
	}
	date, err := time.Parse(DateFormat, string(lines[3]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse date in git log output: %v\n%q", err, output)
	}
	cc := make(map[string]bool)
	cc[strings.ToLower(string(lines[2]))] = true
	for _, line := range lines[4:] {
		for _, re := range ccRes {
			matches := re.FindSubmatchIndex(line)
			if matches == nil {
				continue
			}
			addr, err := mail.ParseAddress(string(line[matches[2]:matches[3]]))
			if err != nil {
				break
			}
			cc[strings.ToLower(addr.Address)] = true
			break
		}
	}
	sortedCC := make([]string, 0, len(cc))
	for addr := range cc {
		sortedCC = append(sortedCC, addr)
	}
	sort.Strings(sortedCC)
	com := &Commit{
		Hash:   string(lines[0]),
		Title:  string(lines[1]),
		Author: string(lines[2]),
		CC:     sortedCC,
		Date:   date,
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

type BisectResult int

const (
	BisectBad BisectResult = iota
	BisectGood
	BisectSkip
)

// Bisect bisects good..bad commit range against the provided predicate (wrapper around git bisect).
// The predicate should return an error only if there is no way to proceed
// (it will abort the process), if possible it should prefer to return BisectSkip.
// Progress of the process is streamed to the provided trace.
// Returns the first commit on which the predicate returns BisectBad.
func Bisect(dir, bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	runSandboxed(dir, "git", "bisect", "reset")
	runSandboxed(dir, "git", "reset", "--hard")
	firstBad, err := GetCommit(dir, bad)
	if err != nil {
		return nil, err
	}
	output, err := runSandboxed(dir, "git", "bisect", "start", bad, good)
	if err != nil {
		return nil, err
	}
	defer runSandboxed(dir, "git", "bisect", "reset")
	fmt.Fprintf(trace, "# git bisect start %v %v\n%s", bad, good, output)
	current, err := HeadCommit(dir)
	if err != nil {
		return nil, err
	}
	var bisectTerms = [...]string{
		BisectBad:  "bad",
		BisectGood: "good",
		BisectSkip: "skip",
	}
	for {
		res, err := pred()
		if err != nil {
			return nil, err
		}
		if res == BisectBad {
			firstBad = current
		}
		output, err = runSandboxed(dir, "git", "bisect", bisectTerms[res])
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(trace, "# git bisect %v %v\n%s", bisectTerms[res], current.Hash, output)
		next, err := HeadCommit(dir)
		if err != nil {
			return nil, err
		}
		if current.Hash == next.Hash {
			return firstBad, nil
		}
		current = next
	}
}

// PreviousReleaseTags returns list of preceding release tags that are reachable from the given commit.
// Note: linux-specific.
func PreviousReleaseTags(dir, commit string) ([]string, error) {
	output, err := runSandboxed(dir, "git", "tag", "--no-contains", commit, "--merged", commit, "v*.*")
	if err != nil {
		return nil, err
	}
	return parseReleaseTags(output)
}

func parseReleaseTags(output []byte) ([]string, error) {
	var tags []string
	for _, tag := range bytes.Split(output, []byte{'\n'}) {
		if releaseTagRe.Match(tag) && releaseTagToInt(string(tag)) != 0 {
			tags = append(tags, string(tag))
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		return releaseTagToInt(tags[i]) > releaseTagToInt(tags[j])
	})
	return tags, nil
}

func releaseTagToInt(tag string) uint64 {
	matches := releaseTagRe.FindStringSubmatchIndex(tag)
	v1, err := strconv.ParseUint(tag[matches[2]:matches[3]], 10, 64)
	if err != nil {
		return 0
	}
	v2, err := strconv.ParseUint(tag[matches[4]:matches[5]], 10, 64)
	if err != nil {
		return 0
	}
	var v3 uint64
	if matches[6] != -1 {
		v3, err = strconv.ParseUint(tag[matches[6]:matches[7]], 10, 64)
		if err != nil {
			return 0
		}
	}
	return v1*1e6 + v2*1e3 + v3
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
