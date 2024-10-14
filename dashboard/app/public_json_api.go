// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"

	"github.com/google/syzkaller/dashboard/api"
)

func getExtAPIDescrForBugPage(bugPage *uiBugPage) *api.Bug {
	return &api.Bug{
		Version: 1,
		Title:   bugPage.Bug.Title,
		ID:      bugPage.Bug.ID,
		Discussions: func() []string {
			if bugPage.Bug.ExternalLink == "" {
				return nil
			}
			return []string{bugPage.Bug.ExternalLink}
		}(),
		FixCommits: getBugFixCommits(bugPage.Bug),
		CauseCommit: func() *api.Commit {
			if bugPage.BisectCause == nil || bugPage.BisectCause.Commit == nil {
				return nil
			}
			bisectCause := bugPage.BisectCause
			return &api.Commit{
				Title:  bisectCause.Commit.Title,
				Link:   bisectCause.Commit.Link,
				Hash:   bisectCause.Commit.Hash,
				Repo:   bisectCause.KernelRepo,
				Branch: bisectCause.KernelBranch}
		}(),
		Crashes: func() []api.Crash {
			var res []api.Crash
			for _, crash := range bugPage.Crashes.Crashes {
				res = append(res, api.Crash{
					Title:              crash.Title,
					SyzReproducerLink:  crash.ReproSyzLink,
					CReproducerLink:    crash.ReproCLink,
					KernelConfigLink:   crash.KernelConfigLink,
					KernelSourceGit:    crash.KernelCommitLink,
					KernelSourceCommit: crash.KernelCommit,
					SyzkallerGit:       crash.SyzkallerCommitLink,
					SyzkallerCommit:    crash.SyzkallerCommit,
					// TODO: add the CompilerDescription
					// TODO: add the Architecture
					CrashReportLink: crash.ReportLink,
				})
			}
			return res
		}(),
	}
}

func getBugFixCommits(bug *uiBug) []api.Commit {
	var res []api.Commit
	for _, commit := range bug.Commits {
		res = append(res, api.Commit{
			Title:  commit.Title,
			Link:   commit.Link,
			Hash:   commit.Hash,
			Repo:   commit.Repo,
			Branch: commit.Branch,
		})
	}
	return res
}

func getExtAPIDescrForBugGroups(bugGroups []*uiBugGroup) *api.BugGroup {
	var bugs []api.BugSummary
	for _, group := range bugGroups {
		for _, bug := range group.Bugs {
			bugs = append(bugs, api.BugSummary{
				Title:      bug.Title,
				Link:       bug.Link,
				FixCommits: getBugFixCommits(bug),
			})
		}
	}
	return &api.BugGroup{
		Version: 1,
		Bugs:    bugs,
	}
}

type publicKernelTree struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

type publicBackportBug struct {
	Namespace       string `json:"namespace"`
	Title           string `json:"title"`
	ConfigLink      string `json:"config_link"`
	SyzReproLink    string `json:"syz_repro_link"`
	CReproLink      string `json:"c_repro_link"`
	SyzkallerCommit string `json:"syzkaller_commit"`
}

type publicMissingBackport struct {
	From   publicKernelTree    `json:"from"`
	To     publicKernelTree    `json:"to"`
	Commit string              `json:"commit"`
	Title  string              `json:"title"`
	Bugs   []publicBackportBug `json:"bugs"`
}

type publicAPIBackports struct {
	Version int                     `json:"version"`
	List    []publicMissingBackport `json:"list"`
}

func getExtAPIDescrForBackports(groups []*uiBackportGroup) *publicAPIBackports {
	return &publicAPIBackports{
		Version: 1,
		List: func() []publicMissingBackport {
			var res []publicMissingBackport
			for _, group := range groups {
				from := publicKernelTree{
					Repo:   group.From.URL,
					Branch: group.From.Branch,
				}
				to := publicKernelTree{
					Repo:   group.To.URL,
					Branch: group.To.Branch,
				}
				for _, backport := range group.List {
					record := publicMissingBackport{
						From:   from,
						To:     to,
						Commit: backport.Commit.Hash,
						Title:  backport.Commit.Title,
					}
					for ns, bugs := range backport.Bugs {
						for _, info := range bugs {
							record.Bugs = append(record.Bugs, publicBackportBug{
								Namespace:       ns,
								Title:           info.Bug.Title,
								ConfigLink:      info.Crash.KernelConfigLink,
								CReproLink:      info.Crash.ReproCLink,
								SyzReproLink:    info.Crash.ReproSyzLink,
								SyzkallerCommit: info.Crash.SyzkallerCommit,
							})
						}
					}
					res = append(res, record)
				}
			}
			return res
		}(),
	}
}

func GetJSONDescrFor(page interface{}) ([]byte, error) {
	var res interface{}
	switch i := page.(type) {
	case *uiBugPage:
		res = getExtAPIDescrForBugPage(i)
	case *uiTerminalPage:
		res = getExtAPIDescrForBugGroups([]*uiBugGroup{i.Bugs})
	case *uiMainPage:
		res = getExtAPIDescrForBugGroups(i.Groups)
	case *uiBackportsPage:
		res = getExtAPIDescrForBackports(i.Groups)
	default:
		return nil, ErrClientNotFound
	}
	return json.MarshalIndent(res, "", "\t")
}
