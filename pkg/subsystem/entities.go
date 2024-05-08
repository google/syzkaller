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
	// If NoReminders is true, there should be no monthly reports for the subsystem.
	NoReminders bool
	// If NoIndirectCc is true, the subsystem lists are not tagged in sub-subsystem reports.
	NoIndirectCc bool
}

// ReachableParents returns the set of subsystems reachable from the current one.
func (subsystem *Subsystem) ReachableParents() map[*Subsystem]struct{} {
	ret := make(map[*Subsystem]struct{})
	var dfs func(node *Subsystem)
	dfs = func(node *Subsystem) {
		for _, p := range node.Parents {
			if p == subsystem {
				panic("loop in the parents relation")
			}
			if _, visited := ret[p]; !visited {
				ret[p] = struct{}{}
				dfs(p)
			}
		}
	}
	dfs(subsystem)
	return ret
}

// Emails returns the list of emails related to the subsystem.
func (subsystem *Subsystem) Emails() []string {
	ret := []string{}
	// For the subsystem itself, we take both lists and maintainers.
	ret = append(ret, subsystem.Lists...)
	ret = append(ret, subsystem.Maintainers...)
	// For its parent subsystems, we only take lists.
	for parent := range subsystem.ReachableParents() {
		if !parent.NoIndirectCc {
			ret = append(ret, parent.Lists...)
		}
	}
	return ret
}

func FilterList(list []*Subsystem, filter func(*Subsystem) bool) []*Subsystem {
	keep := map[*Subsystem]bool{}
	for _, item := range list {
		keep[item] = filter(item)
	}
	newList := []*Subsystem{}
	for _, item := range list {
		if !keep[item] {
			continue
		}
		newParents := []*Subsystem{}
		for _, p := range item.Parents {
			if keep[p] {
				newParents = append(newParents, p)
			}
		}
		item.Parents = newParents
		newList = append(newList, item)
	}
	return newList
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
