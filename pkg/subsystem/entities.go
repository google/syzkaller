// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

type Subsystem struct {
	Name        string
	PathRules   []PathRule
	Syscalls    []string
	Lists       []string
	Maintainers []string
	Parents     []*Subsystem
}

// ReachableParents returns the set of subsystems reachable from the current one.
func (subsystem *Subsystem) ReachableParents() map[*Subsystem]struct{} {
	ret := make(map[*Subsystem]struct{})
	var dfs func(node *Subsystem)
	dfs = func(node *Subsystem) {
		if _, visited := ret[node]; visited {
			return
		}
		for _, p := range node.Parents {
			if p == subsystem {
				panic("loop in the parents relation")
			}
			ret[p] = struct{}{}
			dfs(p)
		}
	}
	dfs(subsystem)
	return ret
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
