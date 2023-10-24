// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzbotstats

import "time"

type BugStatSummary struct {
	Title           string
	IDs             []string  // IDs used by syzbot for this bug.
	FirstTime       time.Time // When the bug was first hit.
	ReleasedTime    time.Time // When the bug was published.
	ReproTime       time.Time // When we found the reproducer.
	CauseBisectTime time.Time // When we found cause bisection.
	ResolvedTime    time.Time // When the bug was resolved.
	Status          BugStatus
	Subsystems      []string
	Strace          bool     // Whether we managed to reproduce under strace.
	HitsPerDay      float64  // Average number of bug hits per day.
	FixHashes       []string // Hashes of fix commits.
	HappenedOn      []string // Managers on which the crash happened.
}

type BugStatus string

const (
	BugFixed           BugStatus = "fixed"
	BugInvalidated     BugStatus = "invalidated"
	BugAutoInvalidated BugStatus = "auto-invalidated"
	BugDup             BugStatus = "dup"
	BugPending         BugStatus = "pending"
)
