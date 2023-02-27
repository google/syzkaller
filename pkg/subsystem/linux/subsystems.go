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
	list := ctx.groupByList()
	extraList, err := ctx.groupByRules()
	if err != nil {
		return nil, err
	}
	list = append(list, extraList...)
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
	ctx.applyExtraRules(list)

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
	ret := []*subsystem.Subsystem{}
	for name, recordNames := range ctx.extraRules.extraSubsystems {
		matching := []*maintainersRecord{}
		for _, recordName := range recordNames {
			if perName[recordName] == nil {
				return nil, fmt.Errorf("MAINTAINERS record not found: %#v", recordName)
			}
			matching = append(matching, perName[recordName])
		}
		s := mergeRawRecords(matching, "")
		s.Name = name
		ret = append(ret, s)
	}
	return ret, nil
}

func (ctx *linuxCtx) applyExtraRules(list []*subsystem.Subsystem) {
	if ctx.extraRules == nil {
		return
	}
	for _, entry := range list {
		entry.Syscalls = ctx.extraRules.subsystemCalls[entry.Name]
	}
}

func mergeRawRecords(records []*maintainersRecord, email string) *subsystem.Subsystem {
	unique := func(list []string) []string {
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
	var lists, maintainers []string
	subsystem := &subsystem.Subsystem{}
	for _, record := range records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		lists = append(lists, record.lists...)
		maintainers = append(maintainers, record.maintainers...)
	}
	if email != "" {
		subsystem.Lists = []string{email}
	} else if len(lists) > 0 {
		subsystem.Lists = unique(lists)
	}
	// There's a risk that we collect too many unrelated maintainers, so
	// let's only merge them if there are no lists.
	if len(records) <= 1 {
		subsystem.Maintainers = unique(maintainers)
	}
	return subsystem
}

func getMaintainers(root fs.FS) ([]*maintainersRecord, error) {
	f, err := root.Open("MAINTAINERS")
	if err != nil {
		return nil, fmt.Errorf("failed to open the MAINTAINERS file: %w", err)
	}
	defer f.Close()
	return parseLinuxMaintainers(f)
}
