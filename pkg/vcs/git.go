// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type git struct {
	os  string
	vm  string
	dir string
}

func newGit(os, vm, dir string) *git {
	return &git{
		os:  os,
		vm:  vm,
		dir: dir,
	}
}

func (git *git) Poll(repo, branch string) (*Commit, error) {
	dir := git.dir
	runSandboxed(dir, "git", "bisect", "reset")
	runSandboxed(dir, "git", "reset", "--hard")
	origin, err := runSandboxed(dir, "git", "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(origin)) != repo {
		// The repo is here, but it has wrong origin (e.g. repo in config has changed), re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	// Use origin/branch for the case the branch was force-pushed,
	// in such case branch is not the same is origin/branch and we will
	// stuck with the local version forever (git checkout won't fail).
	if _, err := runSandboxed(dir, "git", "checkout", "origin/"+branch); err != nil {
		// No such branch (e.g. branch in config has changed), re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := runSandboxed(dir, "git", "fetch", "--no-tags"); err != nil {
		// Something else is wrong, re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := runSandboxed(dir, "git", "checkout", "origin/"+branch); err != nil {
		return nil, err
	}
	return git.HeadCommit()
}

func (git *git) CheckoutBranch(repo, branch string) (*Commit, error) {
	dir := git.dir
	runSandboxed(dir, "git", "bisect", "reset")
	if _, err := runSandboxed(dir, "git", "reset", "--hard"); err != nil {
		if err := git.initRepo(); err != nil {
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
	return git.HeadCommit()
}

func (git *git) CheckoutCommit(repo, commit string) (*Commit, error) {
	dir := git.dir
	runSandboxed(dir, "git", "bisect", "reset")
	if _, err := runSandboxed(dir, "git", "reset", "--hard"); err != nil {
		if err := git.initRepo(); err != nil {
			return nil, err
		}
	}
	_, err := runSandboxed(dir, "git", "fetch", repo)
	if err != nil {
		return nil, err
	}
	return git.SwitchCommit(commit)
}

func (git *git) SwitchCommit(commit string) (*Commit, error) {
	dir := git.dir
	if _, err := runSandboxed(dir, "git", "checkout", commit); err != nil {
		return nil, err
	}
	return git.HeadCommit()
}

func (git *git) clone(repo, branch string) error {
	if err := git.initRepo(); err != nil {
		return err
	}
	if _, err := runSandboxed(git.dir, "git", "remote", "add", "origin", repo); err != nil {
		return err
	}
	if _, err := runSandboxed(git.dir, "git", "fetch", "origin", branch); err != nil {
		return err
	}
	return nil
}

func (git *git) initRepo() error {
	if err := os.RemoveAll(git.dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %v", err)
	}
	if err := osutil.MkdirAll(git.dir); err != nil {
		return fmt.Errorf("failed to create repo dir: %v", err)
	}
	if err := osutil.SandboxChown(git.dir); err != nil {
		return err
	}
	if _, err := runSandboxed(git.dir, "git", "init"); err != nil {
		return err
	}
	return nil
}

func (git *git) HeadCommit() (*Commit, error) {
	return git.getCommit("HEAD")
}

func (git *git) getCommit(commit string) (*Commit, error) {
	output, err := runSandboxed(git.dir, "git", "log", "--format=%H%n%s%n%ae%n%ad%n%b", "-n", "1", commit)
	if err != nil {
		return nil, err
	}
	return gitParseCommit(output)
}

func gitParseCommit(output []byte) (*Commit, error) {
	lines := bytes.Split(output, []byte{'\n'})
	if len(lines) < 4 || len(lines[0]) != 40 {
		return nil, fmt.Errorf("unexpected git log output: %q", output)
	}
	const dateFormat = "Mon Jan 2 15:04:05 2006 -0700"
	date, err := time.Parse(dateFormat, string(lines[3]))
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

func (git *git) ListRecentCommits(baseCommit string) ([]string, error) {
	// On upstream kernel this produces ~11MB of output.
	// Somewhat inefficient to collect whole output in a slice
	// and then convert to string, but should be bearable.
	output, err := runSandboxed(git.dir, "git", "log",
		"--pretty=format:%s", "--no-merges", "-n", "200000", baseCommit)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), "\n"), nil
}

func (git *git) ExtractFixTagsFromCommits(baseCommit, email string) ([]FixCommit, error) {
	since := time.Now().Add(-time.Hour * 24 * 365).Format("01-02-2006")
	cmd := exec.Command("git", "log", "--no-merges", "--since", since, baseCommit)
	cmd.Dir = git.dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	return gitExtractFixTags(stdout, email)
}

func gitExtractFixTags(r io.Reader, email string) ([]FixCommit, error) {
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

func (git *git) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	dir := git.dir
	runSandboxed(dir, "git", "bisect", "reset")
	runSandboxed(dir, "git", "reset", "--hard")
	firstBad, err := git.getCommit(bad)
	if err != nil {
		return nil, err
	}
	output, err := runSandboxed(dir, "git", "bisect", "start", bad, good)
	if err != nil {
		return nil, err
	}
	defer runSandboxed(dir, "git", "bisect", "reset")
	fmt.Fprintf(trace, "# git bisect start %v %v\n%s", bad, good, output)
	current, err := git.HeadCommit()
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
		next, err := git.HeadCommit()
		if err != nil {
			return nil, err
		}
		if current.Hash == next.Hash {
			return firstBad, nil
		}
		current = next
	}
}

// Note: linux-specific.
func (git *git) PreviousReleaseTags(commit string) ([]string, error) {
	output, err := runSandboxed(git.dir, "git", "tag", "--no-contains", commit, "--merged", commit, "v*.*")
	if err != nil {
		return nil, err
	}
	return gitParseReleaseTags(output)
}

func gitParseReleaseTags(output []byte) ([]string, error) {
	var tags []string
	for _, tag := range bytes.Split(output, []byte{'\n'}) {
		if releaseTagRe.Match(tag) && gitReleaseTagToInt(string(tag)) != 0 {
			tags = append(tags, string(tag))
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		return gitReleaseTagToInt(tags[i]) > gitReleaseTagToInt(tags[j])
	})
	return tags, nil
}

func gitReleaseTagToInt(tag string) uint64 {
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
