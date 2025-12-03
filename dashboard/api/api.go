// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package api provides data structures and helper methods to work with the dashboard JSON API.
// All structures in this package are backwards compatible.
package api

import "time"

const Version = 1

type BugGroup struct {
	Version int `json:"version"`
	Bugs    []BugSummary
}

type BugSummary struct {
	Title       string   `json:"title,omitempty"`
	Link        string   `json:"link"`
	LastUpdated string   `json:"last-updated,omitempty"`
	FixCommits  []Commit `json:"fix-commits,omitempty"`
}

type Bug struct {
	Version     int        `json:"version"`
	Title       string     `json:"title,omitempty"`
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	FirstCrash  time.Time  `json:"first-crash"`
	LastCrash   time.Time  `json:"last-crash"`
	FixTime     *time.Time `json:"fix-time,omitempty"`
	CloseTime   *time.Time `json:"close-time,omitempty"`
	FixCommits  []Commit   `json:"fix-commits,omitempty"`
	CauseCommit *Commit    `json:"cause-commit,omitempty"`
	// Links to the discussions.
	Discussions []string `json:"discussions,omitempty"`
	Crashes     []Crash  `json:"crashes,omitempty"`
}

type Crash struct {
	Title               string `json:"title"`
	SyzReproducerLink   string `json:"syz-reproducer,omitempty"`
	CReproducerLink     string `json:"c-reproducer,omitempty"`
	KernelConfigLink    string `json:"kernel-config,omitempty"`
	KernelSourceGit     string `json:"kernel-source-git,omitempty"`
	KernelSourceCommit  string `json:"kernel-source-commit,omitempty"`
	SyzkallerGit        string `json:"syzkaller-git,omitempty"`
	SyzkallerCommit     string `json:"syzkaller-commit,omitempty"`
	CompilerDescription string `json:"compiler-description,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
	CrashReportLink     string `json:"crash-report-link,omitempty"`
}

type Commit struct {
	Title  string     `json:"title"`
	Link   string     `json:"link,omitempty"`
	Hash   string     `json:"hash,omitempty"`
	Repo   string     `json:"repo,omitempty"`
	Branch string     `json:"branch,omitempty"`
	Date   *time.Time `json:"date,omitempty"`
}
