// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
)

func ListFromRepo(repo string) ([]*entity.Subsystem, error) {
	return listFromRepoInner(os.DirFS(repo), linuxSubsystemRules)
}

// listFromRepoInner allows for better testing.
func listFromRepoInner(root fs.FS, rules *customRules) ([]*entity.Subsystem, error) {
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
	ctx.groupByList()
	list, err := ctx.getSubsystems()
	if err != nil {
		return nil, err
	}
	matrix, err := match.BuildCoincidenceMatrix(root, list, dropPatterns)
	if err != nil {
		return nil, err
	}
	list, err = parentTransformations(matrix, list)
	if err != nil {
		return nil, err
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

type subsystemCandidate struct {
	records     []*maintainersRecord
	commonEmail string
}

var (
	// Some of the patterns are not really needed for bug subsystem inteference and
	// only complicate the manual review of the rules.
	dropPatterns = regexp.MustCompile(`^(Documentation|scripts|samples|tools)|Makefile`)
)

func (ctx *linuxCtx) groupByList() []*subsystemCandidate {
	perList := make(map[string][]*maintainersRecord)
	for _, record := range ctx.rawRecords {
		for _, list := range record.lists {
			perList[list] = append(perList[list], record)
		}
	}
	ret := []*subsystemCandidate{}
	for email, list := range perList {
		ret = append(ret, &subsystemCandidate{
			commonEmail: email,
			records:     list,
		})
	}
	return ret
}

func (ctx *linuxCtx) getSubsystems() ([]*entity.Subsystem, error) {
	ret := []*entity.Subsystem{}
	for _, raw := range ctx.groupByList() {
		s := &entity.Subsystem{}
		raw.mergeRawRecords(s)
		// Skip empty subsystems.
		if len(s.Syscalls)+len(s.PathRules) == 0 {
			continue
		}
		ret = append(ret, s)
	}
	if err := setSubsystemNames(ret); err != nil {
		return nil, fmt.Errorf("failed to set names: %w", err)
	}
	ctx.applyExtraRules(ret)
	return ret, nil
}

func (ctx *linuxCtx) applyExtraRules(list []*entity.Subsystem) {
	if ctx.extraRules == nil {
		return
	}
	for _, entry := range list {
		entry.Syscalls = ctx.extraRules.subsystemCalls[entry.Name]
	}
}

func (candidate *subsystemCandidate) mergeRawRecords(subsystem *entity.Subsystem) {
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
	var maintainers []string
	for _, record := range candidate.records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		maintainers = append(maintainers, record.maintainers...)
	}
	if candidate.commonEmail != "" {
		// For list-grouped subsystems, we risk merging just too many lists.
		// Keep the list short in this case.
		subsystem.Lists = []string{candidate.commonEmail}
	}
	// There's a risk that we collect too many unrelated maintainers, so
	// let's only merge them if there are no lists.
	if len(candidate.records) <= 1 {
		subsystem.Maintainers = unique(maintainers)
	}
}

func getMaintainers(root fs.FS) ([]*maintainersRecord, error) {
	f, err := root.Open("MAINTAINERS")
	if err != nil {
		return nil, fmt.Errorf("failed to open the MAINTAINERS file: %w", err)
	}
	defer f.Close()
	return parseLinuxMaintainers(f)
}
