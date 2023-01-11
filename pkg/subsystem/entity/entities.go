// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package entity

type Subsystem struct {
	Name        string
	PathRules   []PathRule
	Syscalls    []string
	Lists       []string
	Maintainers []string
}

// PathRule describes the part of the directory tree belonging to a single subsystem.
type PathRule struct {
	IncludeRegexp string
	// ExcludeRegexps are tested before IncludeRegexp.
	ExcludeRegexp string
}

func (pr *PathRule) IsEmpty() bool {
	return pr.IncludeRegexp == "" && pr.ExcludeRegexp == ""
}
