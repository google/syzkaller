// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

type git struct {
	dir      string
	ignoreCC map[string]bool
	precious bool
	sandbox  bool
}

func newGit(dir string, ignoreCC map[string]bool, opts []RepoOpt) *git {
	git := &git{
		dir:      dir,
		ignoreCC: ignoreCC,
		sandbox:  true,
	}
	for _, opt := range opts {
		switch opt {
		case OptPrecious:
			git.precious = true
		case OptDontSandbox:
			git.sandbox = false
		}
	}
	return git
}

func filterEnv() []string {
	// We have to filter various git environment variables - if
	// these variables are set (e.g. if a test is being run as
	// part of a rebase) we're going to be acting on some other
	// repository (e.g the syzkaller tree itself) rather than the
	// intended repo.
	env := os.Environ()
	for i := 0; i < len(env); i++ {
		if strings.HasPrefix(env[i], "GIT_DIR") ||
			strings.HasPrefix(env[i], "GIT_WORK_TREE") ||
			strings.HasPrefix(env[i], "GIT_INDEX_FILE") ||
			strings.HasPrefix(env[i], "GIT_OBJECT_DIRECTORY") {
			env = append(env[:i], env[i+1:]...)
			i--
		}
	}

	return env
}

func (git *git) Poll(repo, branch string) (*Commit, error) {
	git.reset()
	origin, err := git.git("remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(origin)) != repo {
		// The repo is here, but it has wrong origin (e.g. repo in config has changed), re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	// Use origin/branch for the case the branch was force-pushed,
	// in such case branch is not the same is origin/branch and we will
	// stuck with the local version forever (git checkout won't fail).
	if _, err := git.git("checkout", "origin/"+branch); err != nil {
		// No such branch (e.g. branch in config has changed), re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := git.git("fetch", "--force"); err != nil {
		// Something else is wrong, re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := git.git("checkout", "origin/"+branch); err != nil {
		return nil, err
	}
	if _, err := git.git("submodule", "update", "--init"); err != nil {
		return nil, err
	}
	return git.Commit(HEAD)
}

func (git *git) CheckoutBranch(repo, branch string) (*Commit, error) {
	if err := git.repair(); err != nil {
		return nil, err
	}
	repoHash := hash.String([]byte(repo))
	// Because the HEAD is detached, submodules assumes "origin" to be the default
	// remote when initializing.
	// This sets "origin" to be the current remote.
	// Ignore errors as we can double add or remove the same remote and that will fail.
	git.git("remote", "rm", "origin")
	git.git("remote", "add", "origin", repo)
	git.git("remote", "add", repoHash, repo)
	_, err := git.git("fetch", "--force", repoHash, branch)
	if err != nil {
		return nil, err
	}
	if _, err := git.git("checkout", "FETCH_HEAD", "--force"); err != nil {
		return nil, err
	}
	if _, err := git.git("submodule", "update", "--init"); err != nil {
		return nil, err
	}
	// If the branch checkout had to be "forced" the directory may
	// contain remaining untracked files.
	// Clean again to ensure the new branch is in a clean state.
	if err := git.repair(); err != nil {
		return nil, err
	}
	return git.Commit(HEAD)
}

func (git *git) CheckoutCommit(repo, commit string) (*Commit, error) {
	if err := git.repair(); err != nil {
		return nil, err
	}
	if err := git.fetchRemote(repo, commit); err != nil {
		return nil, err
	}
	return git.SwitchCommit(commit)
}

func (git *git) fetchRemote(repo, commit string) error {
	repoHash := hash.String([]byte(repo))
	// Ignore error as we can double add the same remote and that will fail.
	git.git("remote", "add", repoHash, repo)
	fetchArgs := []string{"fetch", "--force", "--tags", repoHash}
	if commit != "" && gitFullHashRe.MatchString(commit) {
		// This trick only works with full commit hashes.
		fetchArgs = append(fetchArgs, commit)
	}
	_, err := git.git(fetchArgs...)
	if err != nil {
		var verbose *osutil.VerboseError
		if errors.As(err, &verbose) &&
			bytes.Contains(verbose.Output, []byte("error: cannot lock ref")) {
			// It can happen that the fetched repo has tags names that conflict
			// with the ones already present in the repository.
			// Try to fetch more, but this time prune tags, it should help.
			// The --prune-tags option will remove all tags that are not present
			// in this remote repo, so don't do it always. Only when necessary.
			_, err = git.git("fetch", "--force", "--tags", "--prune", "--prune-tags", repoHash)
		}
	}
	return err
}

func (git *git) SwitchCommit(commit string) (*Commit, error) {
	if !git.precious {
		git.git("reset", "--hard")
		git.git("clean", "-fdx")
	}
	if _, err := git.git("checkout", commit); err != nil {
		return nil, err
	}
	if _, err := git.git("submodule", "update", "--init"); err != nil {
		return nil, err
	}
	return git.Commit(HEAD)
}

func (git *git) clone(repo, branch string) error {
	if git.precious {
		return fmt.Errorf("won't reinit precious repo")
	}
	if err := git.initRepo(nil); err != nil {
		return err
	}
	if _, err := git.git("remote", "add", "origin", repo); err != nil {
		return err
	}
	if _, err := git.git("fetch", "origin", branch); err != nil {
		return err
	}
	return nil
}

func (git *git) reset() error {
	// This function tries to reset git repo state to a known clean state.
	if git.precious {
		return nil
	}
	git.git("reset", "--hard", "--recurse-submodules")
	git.git("clean", "-xfdf")
	git.git("submodule", "foreach", "--recursive", "git", "clean", "-xfdf")
	git.git("bisect", "reset")
	_, err := git.git("reset", "--hard", "--recurse-submodules")
	return err
}

func (git *git) repair() error {
	if err := git.reset(); err != nil {
		return git.initRepo(err)
	}
	return nil
}

func (git *git) initRepo(reason error) error {
	if reason != nil {
		log.Logf(1, "git: initializing repo at %v: %v", git.dir, reason)
	}
	if err := os.RemoveAll(git.dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %w", err)
	}
	if err := osutil.MkdirAll(git.dir); err != nil {
		return fmt.Errorf("failed to create repo dir: %w", err)
	}
	if git.sandbox {
		if err := osutil.SandboxChown(git.dir); err != nil {
			return err
		}
	}
	if _, err := git.git("init"); err != nil {
		return err
	}
	return nil
}

func (git *git) Contains(commit string) (bool, error) {
	_, err := git.git("merge-base", "--is-ancestor", commit, HEAD)
	return err == nil, nil
}

func (git *git) Commit(com string) (*Commit, error) {
	const patchSeparator = "---===syzkaller-patch-separator===---"
	output, err := git.git("log", "--format=%H%n%s%n%ae%n%an%n%ad%n%P%n%cd%n%b"+patchSeparator,
		"-n", "1", "-p", "-U0", com)
	if err != nil {
		return nil, err
	}
	pos := bytes.Index(output, []byte(patchSeparator))
	if pos == -1 {
		return nil, fmt.Errorf("git log output does not contain patch separator")
	}
	commit, err := gitParseCommit(output[:pos], nil, nil, git.ignoreCC)
	if err != nil {
		return nil, err
	}
	commit.Patch = output[pos+len(patchSeparator):]
	for len(commit.Patch) != 0 && commit.Patch[0] == '\n' {
		commit.Patch = commit.Patch[1:]
	}
	return commit, nil
}

func gitParseCommit(output, user, domain []byte, ignoreCC map[string]bool) (*Commit, error) {
	lines := bytes.Split(output, []byte{'\n'})
	if len(lines) < 8 || len(lines[0]) != 40 {
		return nil, fmt.Errorf("unexpected git log output: %q", output)
	}
	const dateFormat = "Mon Jan 2 15:04:05 2006 -0700"
	date, err := time.Parse(dateFormat, string(lines[4]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse date in git log output: %w\n%q", err, output)
	}
	commitDate, err := time.Parse(dateFormat, string(lines[6]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse date in git log output: %w\n%q", err, output)
	}
	recipients := make(map[string]bool)
	recipients[strings.ToLower(string(lines[2]))] = true
	var tags []string
	// Use summary line + all description lines.
	for _, line := range append([][]byte{lines[1]}, lines[7:]...) {
		if user != nil {
			userPos := bytes.Index(line, user)
			if userPos != -1 {
				domainPos := bytes.Index(line[userPos+len(user)+1:], domain)
				if domainPos != -1 {
					startPos := userPos + len(user)
					endPos := userPos + len(user) + domainPos + 1
					tag := string(line[startPos:endPos])
					present := false
					for _, tag1 := range tags {
						if tag1 == tag {
							present = true
							break
						}
					}
					if !present {
						tags = append(tags, tag)
					}
				}
			}
		}
		for _, re := range ccRes {
			matches := re.FindSubmatchIndex(line)
			if matches == nil {
				continue
			}
			addr, err := mail.ParseAddress(string(line[matches[2]:matches[3]]))
			if err != nil {
				break
			}
			email := strings.ToLower(addr.Address)
			if ignoreCC[email] {
				continue
			}
			recipients[email] = true
			break
		}
	}
	sortedRecipients := make(Recipients, 0, len(recipients))
	for addr := range recipients {
		sortedRecipients = append(sortedRecipients, RecipientInfo{mail.Address{Address: addr}, To})
	}
	sort.Sort(sortedRecipients)
	parents := strings.Split(string(lines[5]), " ")
	com := &Commit{
		Hash:       string(lines[0]),
		Title:      string(lines[1]),
		Author:     string(lines[2]),
		AuthorName: string(lines[3]),
		Parents:    parents,
		Recipients: sortedRecipients,
		Tags:       tags,
		Date:       date,
		CommitDate: commitDate,
	}
	return com, nil
}

func (git *git) GetCommitByTitle(title string) (*Commit, error) {
	commits, _, err := git.GetCommitsByTitles([]string{title})
	if err != nil || len(commits) == 0 {
		return nil, err
	}
	return commits[0], nil
}

const (
	fetchCommitsMaxAgeInYears = 5
)

func (git *git) GetCommitsByTitles(titles []string) ([]*Commit, []string, error) {
	var greps []string
	m := make(map[string]string)
	for _, title := range titles {
		canonical := CanonicalizeCommit(title)
		greps = append(greps, canonical)
		m[canonical] = title
	}
	since := time.Now().Add(-time.Hour * 24 * 365 * fetchCommitsMaxAgeInYears).Format("01-02-2006")
	commits, err := git.fetchCommits(since, HEAD, "", "", greps, true)
	if err != nil {
		return nil, nil, err
	}
	var results []*Commit
	for _, com := range commits {
		canonical := CanonicalizeCommit(com.Title)
		if orig := m[canonical]; orig != "" {
			delete(m, canonical)
			results = append(results, com)
			com.Title = orig
		}
	}
	var missing []string
	for _, orig := range m {
		missing = append(missing, orig)
	}
	return results, missing, nil
}

func (git *git) ListCommitHashes(baseCommit string) ([]string, error) {
	output, err := git.git("log", "--pretty=format:%h", baseCommit)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), "\n"), nil
}

func (git *git) ExtractFixTagsFromCommits(baseCommit, email string) ([]*Commit, error) {
	user, domain, err := splitEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email %q: %w", email, err)
	}
	grep := user + "+.*" + domain
	since := time.Now().Add(-time.Hour * 24 * 365 * fetchCommitsMaxAgeInYears).Format("01-02-2006")
	return git.fetchCommits(since, baseCommit, user, domain, []string{grep}, false)
}

func (git *git) fetchCommits(since, base, user, domain string, greps []string, fixedStrings bool) ([]*Commit, error) {
	const commitSeparator = "---===syzkaller-commit-separator===---"
	args := []string{"log", "--since", since, "--format=%H%n%s%n%ae%n%an%n%ad%n%P%n%cd%n%b%n" + commitSeparator}
	if fixedStrings {
		args = append(args, "--fixed-strings")
	}
	for _, grep := range greps {
		args = append(args, "--grep", grep)
	}
	args = append(args, base)
	cmd := exec.Command("git", args...)
	cmd.Dir = git.dir
	cmd.Env = filterEnv()
	if git.sandbox {
		if err := osutil.Sandbox(cmd, true, false); err != nil {
			return nil, err
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	var (
		s           = bufio.NewScanner(stdout)
		buf         = new(bytes.Buffer)
		separator   = []byte(commitSeparator)
		commits     []*Commit
		userBytes   []byte
		domainBytes []byte
	)
	if user != "" {
		userBytes = []byte(user + "+")
		domainBytes = []byte(domain)
	}
	for s.Scan() {
		ln := s.Bytes()
		if !bytes.Equal(ln, separator) {
			buf.Write(ln)
			buf.WriteByte('\n')
			continue
		}
		com, err := gitParseCommit(buf.Bytes(), userBytes, domainBytes, git.ignoreCC)
		if err != nil {
			return nil, err
		}
		if user == "" || len(com.Tags) != 0 {
			commits = append(commits, com)
		}
		buf.Reset()
	}
	return commits, s.Err()
}

func (git *git) git(args ...string) ([]byte, error) {
	cmd := osutil.Command("git", args...)
	cmd.Dir = git.dir
	cmd.Env = filterEnv()
	if git.sandbox {
		if err := osutil.Sandbox(cmd, true, false); err != nil {
			return nil, err
		}
	}
	return osutil.Run(3*time.Hour, cmd)
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

func (git *git) Bisect(bad, good string, dt debugtracer.DebugTracer, pred func() (BisectResult,
	error)) ([]*Commit, error) {
	git.reset()
	firstBad, err := git.Commit(bad)
	if err != nil {
		return nil, err
	}
	output, err := git.git("bisect", "start", bad, good)
	if err != nil {
		return nil, err
	}
	defer git.reset()
	dt.Log("# git bisect start %v %v\n%s", bad, good, output)
	current, err := git.Commit(HEAD)
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
		// Linux EnvForCommit may cherry-pick some fixes, reset these before the next step.
		git.git("reset", "--hard")
		if err != nil {
			return nil, err
		}
		if res == BisectBad {
			firstBad = current
		}
		output, err = git.git("bisect", bisectTerms[res])
		dt.Log("# git bisect %v %v\n%s", bisectTerms[res], current.Hash, output)
		if err != nil {
			if bytes.Contains(output, []byte("There are only 'skip'ped commits left to test")) {
				return git.bisectInconclusive(output)
			}
			return nil, err
		}
		next, err := git.Commit(HEAD)
		if err != nil {
			return nil, err
		}
		if current.Hash == next.Hash {
			return []*Commit{firstBad}, nil
		}
		current = next
	}
}

var gitFullHashRe = regexp.MustCompile("[a-f0-9]{40}")

func (git *git) bisectInconclusive(output []byte) ([]*Commit, error) {
	// For inconclusive bisection git prints the following message:
	//
	//	There are only 'skip'ped commits left to test.
	//	The first bad commit could be any of:
	//	1f43f400a2cbb02f3d34de8fe30075c070254816
	//	4d96e13ee9cd1f7f801e8c7f4b12f09d1da4a5d8
	//	5cd856a5ef9aa189df757c322be34ad735a5b17f
	//	We cannot bisect more!
	//
	// For conclusive bisection:
	//
	//	7c3850adbcccc2c6c9e7ab23a7dcbc4926ee5b96 is the first bad commit
	var commits []*Commit
	for _, hash := range gitFullHashRe.FindAll(output, -1) {
		com, err := git.Commit(string(hash))
		if err != nil {
			return nil, err
		}
		commits = append(commits, com)
	}
	return commits, nil
}

func (git *git) ReleaseTag(commit string) (string, error) {
	tags, err := git.previousReleaseTags(commit, true, true, true)
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no release tags found for commit %v", commit)
	}
	return tags[0], nil
}

func (git *git) previousReleaseTags(commit string, self, onlyTop, includeRC bool) ([]string, error) {
	var tags []string
	if self {
		output, err := git.git("tag", "--list", "--points-at", commit, "--merged", commit, "v*.*")
		if err != nil {
			return nil, err
		}
		tags = gitParseReleaseTags(output, includeRC)
		if onlyTop && len(tags) != 0 {
			return tags, nil
		}
	}
	output, err := git.git("tag", "--no-contains", commit, "--merged", commit, "v*.*")
	if err != nil {
		return nil, err
	}
	tags1 := gitParseReleaseTags(output, includeRC)
	tags = append(tags, tags1...)
	if len(tags) == 0 {
		return nil, fmt.Errorf("no release tags found for commit %v", commit)
	}
	return tags, nil
}

func (git *git) IsRelease(commit string) (bool, error) {
	tags1, err := git.previousReleaseTags(commit, true, false, false)
	if err != nil {
		return false, err
	}
	tags2, err := git.previousReleaseTags(commit, false, false, false)
	if err != nil {
		return false, err
	}
	return len(tags1) != len(tags2), nil
}

func (git *git) Object(name, commit string) ([]byte, error) {
	return git.git("show", fmt.Sprintf("%s:%s", commit, name))
}

func (git *git) MergeBases(firstCommit, secondCommit string) ([]*Commit, error) {
	output, err := git.git("merge-base", firstCommit, secondCommit)
	if err != nil {
		return nil, err
	}
	ret := []*Commit{}
	for _, hash := range strings.Fields(string(output)) {
		commit, err := git.Commit(hash)
		if err != nil {
			return nil, err
		}
		ret = append(ret, commit)
	}
	return ret, nil
}

// CommitExists relies on 'git cat-file -e'.
// If object exists its exit status is 0.
// If object doesn't exist its exit status is 1 (not documented).
// Otherwise, the exit status is 128 (not documented).
func (git *git) CommitExists(commit string) (bool, error) {
	_, err := git.git("cat-file", "-e", commit)
	var vErr *osutil.VerboseError
	if errors.As(err, &vErr) && vErr.ExitCode == 1 {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (git *git) PushCommit(repo, commit string) error {
	tagName := "tag-" + commit // assign tag to guarantee remote persistence
	git.git("tag", tagName)    // ignore errors on re-tagging
	if _, err := git.git("push", repo, "tag", tagName); err != nil {
		return fmt.Errorf("git push %s tag %s: %w", repo, tagName, err)
	}
	return nil
}

var fileNameRe = regexp.MustCompile(`(?m)^diff.* b\/([^\s]+)`)

// ParseGitDiff extracts the files modified in the git patch.
func ParseGitDiff(patch []byte) []string {
	var files []string
	for _, match := range fileNameRe.FindAllStringSubmatch(string(patch), -1) {
		files = append(files, match[1])
	}
	return files
}
