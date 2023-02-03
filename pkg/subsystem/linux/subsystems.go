// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/google/syzkaller/pkg/subsystem/entity"
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
		mergeRawRecords(s, raw.records)
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

func mergeRawRecords(subsystem *entity.Subsystem, records []*maintainersRecord) {
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
	for _, record := range records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		lists = append(lists, record.lists...)
		maintainers = append(maintainers, record.maintainers...)
	}
	subsystem.Lists = unique(lists)
	// But there's a risk that we collect too many unrelated maintainers, so
	// let's only merge them if there are no lists.
	if len(records) <= 1 {
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
