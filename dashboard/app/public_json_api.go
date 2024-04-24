// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/syzkaller/pkg/vcs"
)

// publicApiBugDescription is used to serve the /bug HTTP requests
// and provide JSON description of the BUG. Backward compatible.
type publicAPIBugDescription struct {
	Version     int         `json:"version"`
	Title       string      `json:"title,omitempty"`
	ID          string      `json:"id"`
	FixCommits  []vcsCommit `json:"fix-commits,omitempty"`
	CauseCommit *vcsCommit  `json:"cause-commit,omitempty"`
	// links to the discussions
	Discussions []string                    `json:"discussions,omitempty"`
	Crashes     []publicAPICrashDescription `json:"crashes,omitempty"`
}

type vcsCommit struct {
	Title  string `json:"title"`
	Link   string `json:"link,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Branch string `json:"branch,omitempty"`
}

type publicAPICrashDescription struct {
	Title               string `json:"title"`
	SyzReproducer       string `json:"syz-reproducer,omitempty"`
	CReproducer         string `json:"c-reproducer,omitempty"`
	KernelConfig        string `json:"kernel-config,omitempty"`
	KernelSourceGit     string `json:"kernel-source-git,omitempty"`
	KernelSourceCommit  string `json:"kernel-source-commit,omitempty"`
	SyzkallerGit        string `json:"syzkaller-git,omitempty"`
	SyzkallerCommit     string `json:"syzkaller-commit,omitempty"`
	CompilerDescription string `json:"compiler-description,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
	CrashReport         string `json:"crash-report-link,omitempty"`
}

func getExtAPIDescrForBug(c context.Context, bug *uiBug) (*publicAPIBugDescription, error) {
	causeCommit, err := getBugCauseCommit(c, bug.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to getBugCauseCommit(%s): %w", bug.ID, err)
	}
	var crashes []publicAPICrashDescription
	if crashes, err = getBugCrashes(c, bug.ID); err != nil {
		return nil, fmt.Errorf("failed to getBugCrashes(%s): %w", bug.ID, err)
	}
	return &publicAPIBugDescription{
		Version:     1,
		Title:       bug.Title,
		ID:          bug.ID,
		Discussions: getBugDiscussions(bug),
		FixCommits:  getBugFixCommits(bug),
		CauseCommit: causeCommit,
		Crashes:     crashes,
	}, nil
}

func getBugDiscussions(bug *uiBug) []string {
	if bug.ExternalLink == "" {
		return nil
	}
	return []string{bug.ExternalLink}
}

func getBugCrashes(c context.Context, bugID string) ([]publicAPICrashDescription, error) {
	bug, err := findBugByID(c, bugID)
	if err != nil {
		return nil, fmt.Errorf("failed to load bug id(%s)", bugID)
	}
	crashes, _, err := loadCrashesForBug(c, bug)
	if err != nil {
		return nil, fmt.Errorf("failed to loadCrashesForBug(%s)", bugID)
	}
	var res []publicAPICrashDescription
	for _, crash := range crashes {
		res = append(res, publicAPICrashDescription{
			Title:              crash.Title,
			SyzReproducer:      crash.ReproSyzLink,
			CReproducer:        crash.ReproCLink,
			KernelConfig:       crash.KernelConfigLink,
			KernelSourceGit:    crash.KernelCommitLink,
			KernelSourceCommit: crash.KernelCommit,
			SyzkallerGit:       crash.SyzkallerCommitLink,
			SyzkallerCommit:    crash.SyzkallerCommit,
			// TODO: add the CompilerDescription
			// TODO: add the Architecture
			CrashReport: crash.ReportLink,
		})
	}
	return res, nil
}

func getBugCauseCommit(c context.Context, bugID string) (*vcsCommit, error) {
	bug, err := findBugByID(c, bugID)
	if err != nil {
		return nil, fmt.Errorf("failed to load bug id(%s)", bugID)
	}
	var res *vcsCommit
	if bug.BisectCause > BisectPending {
		causeBisections, err := queryBugJobs(c, bug, JobBisectCause)
		if err != nil {
			return nil, fmt.Errorf("failed to load cause bisections: %w", err)
		}
		j := causeBisections.bestBisection()
		if j != nil && len(j.job.Commits) == 1 {
			commit := j.job.Commits[0]
			res = &vcsCommit{
				Title:  commit.Title,
				Link:   vcs.CommitLink(j.job.KernelRepo, commit.Hash),
				Hash:   commit.Hash,
				Repo:   j.job.KernelRepo,
				Branch: j.job.KernelBranch}
		}
	}
	return res, nil
}

func getBugFixCommits(bug *uiBug) []vcsCommit {
	var res []vcsCommit
	for _, commit := range bug.Commits {
		res = append(res, vcsCommit{
			Title:  commit.Title,
			Link:   commit.Link,
			Hash:   commit.Hash,
			Repo:   commit.Repo,
			Branch: commit.Branch,
		})
	}
	return res
}

type publicAPIBugGroup struct {
	Version int `json:"version"`
	Bugs    []publicAPIBug
}

type publicAPIBug struct {
	Title       string      `json:"title,omitempty"`
	Link        string      `json:"link"`
	LastUpdated string      `json:"last-updated,omitempty"`
	FixCommits  []vcsCommit `json:"fix-commits,omitempty"`
	CauseCommit *vcsCommit  `json:"cause-commit,omitempty"`
	// links to the discussions
	Discussions []string                    `json:"discussions,omitempty"`
	Crashes     []publicAPICrashDescription `json:"crashes,omitempty"`
}

func getExtAPIDescrForBugGroups(c context.Context, bugGroups []*uiBugGroup) (*publicAPIBugGroup, error) {
	var res []publicAPIBug
	for _, group := range bugGroups {
		for _, bug := range group.Bugs {
			var err error
			var causeCommit *vcsCommit
			if causeCommit, err = getBugCauseCommit(c, bug.ID); err != nil {
				return nil, fmt.Errorf("failed to getBugCauseCommit(%s): %w", bug.ID, err)
			}
			var crashes []publicAPICrashDescription
			if crashes, err = getBugCrashes(c, bug.ID); err != nil {
				return nil, fmt.Errorf("failed to get bug(%s) crashes: %w", bug.ID, err)
			}
			res = append(res, publicAPIBug{
				Title:       bug.Title,
				Link:        bug.Link,
				FixCommits:  getBugFixCommits(bug),
				CauseCommit: causeCommit,
				Discussions: getBugDiscussions(bug),
				Crashes:     crashes,
			})
		}
	}
	return &publicAPIBugGroup{
		Version: 1,
		Bugs:    res,
	}, nil
}

func GetJSONDescrFor(c context.Context, page interface{}) ([]byte, error) {
	var res interface{}
	var err error
	switch i := page.(type) {
	case *uiBugPage:
		res, err = getExtAPIDescrForBug(c, i.Bug)
	case *uiTerminalPage:
		res, err = getExtAPIDescrForBugGroups(c, []*uiBugGroup{i.Bugs})
	case *uiMainPage:
		res, err = getExtAPIDescrForBugGroups(c, i.Groups)
	default:
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to GetJSONDescrFor(): %w", err)
	}
	return json.MarshalIndent(res, "", "\t")
}
