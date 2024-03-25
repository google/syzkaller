// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"

	"github.com/google/syzkaller/pkg/subsystem"
)

func ListFromRepo(repo string) ([]*subsystem.Subsystem, error) {
	return listFromRepoInner(os.DirFS(repo), linuxSubsystemRules)
}

// listFromRepoInner allows for better testing.
func listFromRepoInner(root fs.FS, rules *customRules) ([]*subsystem.Subsystem, error) {
	records, err := getMaintainers(root)
	if err != nil {
		return nil, err
	}
	removeMatchingPatterns(records, dropPatterns)
	ctx := &linuxCtx{
		root:       root,
		rawRecords: records,
		extraRules: rules,
	}
	extraList, err := ctx.groupByRules()
	if err != nil {
		return nil, err
	}
	list := append(ctx.groupByList(), extraList...)
	matrix, err := BuildCoincidenceMatrix(root, list, dropPatterns)
	if err != nil {
		return nil, err
	}
	list, err = parentTransformations(matrix, list)
	if err != nil {
		return nil, err
	}
	if err := setSubsystemNames(list); err != nil {
		return nil, fmt.Errorf("failed to set names: %w", err)
	}
	if err := ctx.applyExtraRules(list); err != nil {
		return nil, fmt.Errorf("failed to apply extra rules: %w", err)
	}

	// Sort subsystems by name to keep output consistent.
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	// Sort path rules to keep output consistent.
	for _, entity := range list {
		sort.Slice(entity.PathRules, func(i, j int) bool {
			a, b := entity.PathRules[i], entity.PathRules[j]
			if a.IncludeRegexp != b.IncludeRegexp {
				return a.IncludeRegexp < b.IncludeRegexp
			}
			return a.ExcludeRegexp < b.ExcludeRegexp
		})
	}
	return list, nil
}

type linuxCtx struct {
	root       fs.FS
	rawRecords []*maintainersRecord
	extraRules *customRules
}

var (
	// Some of the patterns are not really needed for bug subsystem inteference and
	// only complicate the manual review of the rules.
	dropPatterns = regexp.MustCompile(`^(Documentation|scripts|samples|tools)|Makefile`)
)

func (ctx *linuxCtx) groupByList() []*subsystem.Subsystem {
	perList := make(map[string][]*maintainersRecord)
	for _, record := range ctx.rawRecords {
		for _, list := range record.lists {
			perList[list] = append(perList[list], record)
		}
	}
	var exclude map[string]struct{}
	if ctx.extraRules != nil {
		exclude = ctx.extraRules.notSubsystemEmails
	}
	ret := []*subsystem.Subsystem{}
	for email, list := range perList {
		if _, skip := exclude[email]; skip {
			continue
		}
		s := mergeRawRecords(list, email)
		// Skip empty subsystems.
		if len(s.PathRules) > 0 {
			ret = append(ret, s)
		}
	}
	return ret
}

func (ctx *linuxCtx) groupByRules() ([]*subsystem.Subsystem, error) {
	if ctx.extraRules == nil {
		return nil, nil
	}
	perName := map[string]*maintainersRecord{}
	for _, item := range ctx.rawRecords {
		perName[item.name] = item
	}
	var ret []*subsystem.Subsystem
	exclude := map[*maintainersRecord]struct{}{}
	for name, recordNames := range ctx.extraRules.extraSubsystems {
		matching := []*maintainersRecord{}
		for _, recordName := range recordNames {
			record := perName[recordName]
			if record == nil {
				return nil, fmt.Errorf("MAINTAINERS record not found: %#v", recordName)
			}
			exclude[record] = struct{}{}
			matching = append(matching, record)
		}
		s := mergeRawRecords(matching, "")
		s.Name = name
		ret = append(ret, s)
	}
	// Exclude rawRecords from further consideration.
	var newRecords []*maintainersRecord
	for _, record := range ctx.rawRecords {
		if _, ok := exclude[record]; ok {
			continue
		}
		newRecords = append(newRecords, record)
	}
	ctx.rawRecords = newRecords
	return ret, nil
}

func (ctx *linuxCtx) applyExtraRules(list []*subsystem.Subsystem) error {
	if ctx.extraRules == nil {
		return nil
	}
	perName := map[string]*subsystem.Subsystem{}
	for _, entry := range list {
		entry.Syscalls = ctx.extraRules.subsystemCalls[entry.Name]
		_, entry.NoReminders = ctx.extraRules.noReminders[entry.Name]
		perName[entry.Name] = entry
	}
	for from, toNames := range ctx.extraRules.addParents {
		item := perName[from]
		if item == nil {
			return fmt.Errorf("unknown subsystem: %q", from)
		}
		exists := map[string]bool{}
		for _, p := range item.Parents {
			exists[p.Name] = true
		}
		for _, toName := range toNames {
			if exists[toName] {
				continue
			}
			if perName[toName] == nil {
				return fmt.Errorf("unknown parent subsystem: %q", toName)
			}
			item.Parents = append(item.Parents, perName[toName])
		}
	}
	transitiveReduction(list)
	return nil
}

func mergeRawRecords(records []*maintainersRecord, email string) *subsystem.Subsystem {
	var lists []string
	subsystem := &subsystem.Subsystem{}
	for _, record := range records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		lists = append(lists, record.lists...)
	}
	if email != "" {
		subsystem.Lists = []string{email}
	} else if len(lists) > 0 {
		subsystem.Lists = unique(lists)
	}
	subsystem.Maintainers = maintainersFromRecords(records)
	return subsystem
}

func unique(list []string) []string {
	m := make(map[string]struct{})
	for _, s := range list {
		m[s] = struct{}{}
	}
	ret := []string{}
	for s := range m {
		ret = append(ret, s)
	}
	sort.Strings(ret)
	return ret
}

func maintainersFromRecords(records []*maintainersRecord) []string {
	// Generally we avoid merging maintainers from too many MAINTAINERS records,
	// as we may end up pinging too many unrelated people.
	// But in some cases we can still reliably collect the information.
	if len(records) <= 1 {
		// First of all, we're fine if there was just on record.
		return unique(records[0].maintainers)
	}
	// Also let's take a look at the entries that have tree information.
	// They seem to be present only in the most important entries.
	perTrees := map[string][][]string{}
	for _, record := range records {
		if len(record.trees) == 0 {
			continue
		}
		sort.Strings(record.trees)
		key := fmt.Sprintf("%v", record.trees)
		perTrees[key] = append(perTrees[key], record.maintainers)
	}
	if len(perTrees) > 1 {
		// There are several sets of trees, no way to determine the most important.
		return nil
	}
	var maintainerLists [][]string
	for _, value := range perTrees {
		maintainerLists = value
	}
	// Now let's take the intersection of lists.
	counts := map[string]int{}
	var retList []string
	for _, list := range maintainerLists {
		list = unique(list)
		for _, email := range list {
			counts[email]++
			if counts[email] == len(maintainerLists) {
				retList = append(retList, email)
			}
		}
	}
	return retList
}

func getMaintainers(root fs.FS) ([]*maintainersRecord, error) {
	f, err := root.Open("MAINTAINERS")
	if err != nil {
		return nil, fmt.Errorf("failed to open the MAINTAINERS file: %w", err)
	}
	defer f.Close()
	return parseLinuxMaintainers(f)
}
