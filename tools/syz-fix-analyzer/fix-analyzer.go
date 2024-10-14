// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-fix-analyzer analyzes fixed bugs on the dashboard for automatic fixability and prints statistics.
// Fixability implies a known bug type + a simple fix of a particular form.
// For example, for a NULL-deref bug it may be addition of a "if (ptr == NULL) return" check.
package main

import (
	"flag"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/syzkaller/dashboard/api"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/speakeasy-api/git-diff-parser"
)

func main() {
	var (
		flagDashboard = flag.String("dashboard", "https://syzkaller.appspot.com", "dashboard address")
		flagNamespace = flag.String("namespace", "upstream", "target namespace")
		flagToken     = flag.String("token", "", "auth token from 'gcloud auth print-access-token'")
		flagSourceDir = flag.String("sourcedir", "", "fresh linux kernel checkout")
	)
	defer tool.Init()()
	for _, typ := range bugTypes {
		typ.Re = regexp.MustCompile(typ.Pattern)
	}
	cli := api.NewClient(*flagDashboard, *flagToken)
	patches, perType, err := run(cli, *flagNamespace, *flagSourceDir)
	if err != nil {
		tool.Fail(err)
	}
	for _, typ := range bugTypes {
		fmt.Printf("fixable %v:\n", typ.Type)
		for _, bug := range perType[typ.Type].Fixable {
			fmt.Printf("%v\t%v\n", bug.Title, bug.FixCommits[0].Link)
		}
		fmt.Printf("\n")
	}
	total, fixable := 0, 0
	fmt.Printf("%-22v %-8v %v\n", "Type", "Total", "Fixable")
	for _, typ := range bugTypes {
		ti := perType[typ.Type]
		total += ti.Total
		fixable += len(ti.Fixable)
		fmt.Printf("%-22v %-8v %-4v (%.2f%%)\n",
			typ.Type, ti.Total, len(ti.Fixable), percent(len(ti.Fixable), ti.Total))
	}
	fmt.Printf("---\n")
	fmt.Printf("%-22v %-8v %-4v (%.2f%%)\n",
		"classified", total, fixable, percent(fixable, total))
	fmt.Printf("%-22v %-8v %-4v (%.2f%%)\n",
		"total", patches, fixable, percent(fixable, patches))
}

type Job struct {
	bug     api.BugSummary
	repo    vcs.Repo
	typ     BugType
	fixable bool
	err     error
	done    chan struct{}
}

func run(cli *api.Client, ns, sourceDir string) (int, map[BugType]TypeStats, error) {
	repo, err := vcs.NewRepo(targets.Linux, "", sourceDir, vcs.OptPrecious, vcs.OptDontSandbox)
	if err != nil {
		return 0, nil, err
	}
	bugs, err := cli.BugGroups(ns, api.BugGroupFixed)
	if err != nil {
		return 0, nil, err
	}
	jobs := runJobs(bugs, repo)
	patches := make(map[string]bool)
	perType := make(map[BugType]TypeStats)
	for _, job := range jobs {
		<-job.done
		if job.err != nil {
			return 0, nil, job.err
		}
		com := job.bug.FixCommits[0].Hash
		// For now we consider only the first bug for this commit.
		// Potentially we can consider all bugs for this commit,
		// and check if at least one of them is fixable.
		if com == "" || patches[com] {
			continue
		}
		patches[com] = true
		if job.typ == "" {
			continue
		}
		ti := perType[job.typ]
		ti.Total++
		if job.fixable {
			ti.Fixable = append(ti.Fixable, job.bug)
		}
		perType[job.typ] = ti
	}
	return len(patches), perType, nil
}

func runJobs(bugs []api.BugSummary, repo vcs.Repo) []*Job {
	procs := runtime.GOMAXPROCS(0)
	jobC := make(chan *Job, procs)
	for p := 0; p < procs; p++ {
		go func() {
			for job := range jobC {
				typ, fixable, err := isFixable(job.bug, job.repo)
				job.typ, job.fixable, job.err = typ, fixable, err
				close(job.done)
			}
		}()
	}
	var jobs []*Job
	for _, bug := range bugs {
		job := &Job{
			bug:  bug,
			repo: repo,
			done: make(chan struct{}),
		}
		jobC <- job
		jobs = append(jobs, job)
	}
	return jobs
}

func isFixable(bug api.BugSummary, repo vcs.Repo) (BugType, bool, error) {
	// TODO: check that we can infer the file that needs to be fixed
	// (matches the guilty frame in the bug report).

	// TODO: For now we only look at one crash that the dashboard exports.
	// There can be multiple (KASAN+KMSAN+paging fault),
	// we could check if at least one of them is fixable.

	if len(bug.FixCommits) == 0 {
		return "", false, nil
	}
	var typ BugType
	for _, t := range bugTypes {
		if t.Re.MatchString(bug.Title) {
			typ = t.Type
			break
		}
	}
	comHash := bug.FixCommits[0].Hash
	if typ == "" || comHash == "" {
		return "", false, nil
	}
	com, err := repo.Commit(comHash)
	if err != nil {
		return "", false, err
	}
	diff, errs := git_diff_parser.Parse(string(com.Patch))
	if len(errs) != 0 {
		return "", false, fmt.Errorf("parsing patch: %v", errs)
	}
	if len(diff.FileDiff) != 1 {
		return typ, false, nil
	}
	file := diff.FileDiff[0]
	if file.IsBinary || file.FromFile != file.ToFile ||
		!strings.HasSuffix(file.FromFile, ".c") && !strings.HasSuffix(file.FromFile, ".h") {
		return typ, false, nil
	}
	if len(file.Hunks) != 1 {
		return typ, false, nil
	}
	// TODO: check that the patch matches our expected form for this bug type
	// (e.g. adds if+return/continue, etc).
	return typ, true, nil
}

type BugType string

type BugMeta struct {
	Type    BugType
	Pattern string
	Re      *regexp.Regexp
}

type TypeStats struct {
	Total   int
	Fixable []api.BugSummary
}

var bugTypes = []*BugMeta{
	{
		Type: "NULL deref",
		// TODO: check that a GPF is in fact a NULL deref.
		Pattern: `BUG: unable to handle kernel NULL pointer dereference|KASAN: null-ptr-deref|general protection fault`,
	},
	{
		Type: "locking rules",
		Pattern: `BUG: sleeping function called from invalid context|WARNING: suspicious RCU usage|` +
			`suspicious RCU usage at|inconsistent lock state|INFO: trying to register non-static key`,
	},
	{
		Type:    "double-free",
		Pattern: `KASAN: double-free or invalid-free|KASAN: invalid-free`,
	},
	{
		Type:    "out-of-bounds",
		Pattern: `KASAN: .*out-of-bounds|UBSAN: array-index-out-of-bounds`,
	},
	{
		Type:    "use-after-free",
		Pattern: `(KASAN|KMSAN): .*use-after-free`,
	},
	{
		Type:    "data-race",
		Pattern: `KCSAN: data-race`,
	},
	{
		Type:    "shift-out-of-bounds",
		Pattern: `UBSAN: shift-out-of-bounds`,
	},
	{
		Type:    "uninit",
		Pattern: `KMSAN:`,
	},
	{
		Type:    "deadlock",
		Pattern: `deadlock`,
	},
	{
		Type:    "memory leak",
		Pattern: `memory leak in`,
	},
	{
		Type:    "BUG/WARN",
		Pattern: `BUG:|WARNING:`,
	},
}

func percent(a, b int) float64 {
	return float64(a) / float64(b) * 100
}
