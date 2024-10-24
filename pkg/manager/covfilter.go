// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

func CoverageFilter(source *ReportGeneratorWrapper, covCfg mgrconfig.CovFilterCfg,
	strict bool) (map[uint64]struct{}, error) {
	if covCfg.Empty() {
		return nil, nil
	}
	rg, err := source.Get()
	if err != nil {
		return nil, err
	}
	pcs := make(map[uint64]struct{})
	foreachSymbol := func(apply func(*backend.ObjectUnit)) {
		for _, sym := range rg.Symbols {
			apply(&sym.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, covCfg.Functions, foreachSymbol, strict); err != nil {
		return nil, err
	}
	foreachUnit := func(apply func(*backend.ObjectUnit)) {
		for _, unit := range rg.Units {
			apply(&unit.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, covCfg.Files, foreachUnit, strict); err != nil {
		return nil, err
	}
	if err := covFilterAddRawPCs(pcs, covCfg.RawPCs); err != nil {
		return nil, err
	}
	// Note that pcs may include both comparison and block/edge coverage callbacks.
	return pcs, nil
}

func covFilterAddFilter(pcs map[uint64]struct{}, filters []string, foreach func(func(*backend.ObjectUnit)),
	strict bool) error {
	res, err := compileRegexps(filters)
	if err != nil {
		return err
	}
	used := make(map[*regexp.Regexp][]string)
	foreach(func(unit *backend.ObjectUnit) {
		for _, re := range res {
			if re.MatchString(unit.Name) {
				// We add both coverage points and comparison interception points
				// because executor filters comparisons as well.
				for _, pc := range unit.PCs {
					pcs[pc] = struct{}{}
				}
				for _, pc := range unit.CMPs {
					pcs[pc] = struct{}{}
				}
				used[re] = append(used[re], unit.Name)
				break
			}
		}
	})
	for _, re := range res {
		sort.Strings(used[re])
		log.Logf(0, "coverage filter: %v: %v", re, used[re])
	}
	if strict && len(res) != len(used) {
		return fmt.Errorf("some filters don't match anything")
	}
	return nil
}

func covFilterAddRawPCs(pcs map[uint64]struct{}, rawPCsFiles []string) error {
	re := regexp.MustCompile(`(0x[0-9a-f]+)(?:: (0x[0-9a-f]+))?`)
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("failed to open raw PCs file: %w", err)
		}
		defer rawFile.Close()
		s := bufio.NewScanner(rawFile)
		for s.Scan() {
			match := re.FindStringSubmatch(s.Text())
			if match == nil {
				return fmt.Errorf("bad line: %q", s.Text())
			}
			pc, err := strconv.ParseUint(match[1], 0, 64)
			if err != nil {
				return err
			}
			weight, err := strconv.ParseUint(match[2], 0, 32)
			if match[2] != "" && err != nil {
				return err
			}
			// If no weight is detected, set the weight to 0x1 by default.
			if match[2] == "" || weight < 1 {
				weight = 1
			}
			_ = weight // currently unused
			pcs[pc] = struct{}{}
		}
		if err := s.Err(); err != nil {
			return err
		}
	}
	return nil
}

func compileRegexps(regexpStrings []string) ([]*regexp.Regexp, error) {
	var regexps []*regexp.Regexp
	for _, rs := range regexpStrings {
		r, err := regexp.Compile(rs)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		regexps = append(regexps, r)
	}
	return regexps, nil
}

type CoverageFilters struct {
	Areas          []corpus.FocusArea
	ExecutorFilter map[uint64]struct{}
}

func PrepareCoverageFilters(source *ReportGeneratorWrapper, cfg *mgrconfig.Config,
	strict bool) (CoverageFilters, error) {
	var ret CoverageFilters
	needExecutorFilter := true
	for _, area := range cfg.Experimental.FocusAreas {
		pcs, err := CoverageFilter(source, area.Filter, strict)
		if err != nil {
			return ret, err
		}
		// KCOV will point to the next instruction, so we need to adjust the map.
		covPCs := make(map[uint64]struct{})
		for pc := range pcs {
			next := backend.NextInstructionPC(cfg.SysTarget, cfg.Type, pc)
			covPCs[next] = struct{}{}
		}
		ret.Areas = append(ret.Areas, corpus.FocusArea{
			Name:     area.Name,
			CoverPCs: covPCs,
			Weight:   area.Weight,
		})
		if area.Filter.Empty() {
			// An empty cover filter indicates that the user is interested in all the coverage.
			needExecutorFilter = false
		}
	}
	if needExecutorFilter {
		ret.ExecutorFilter = map[uint64]struct{}{}
		for _, area := range ret.Areas {
			for pc := range area.CoverPCs {
				ret.ExecutorFilter[pc] = struct{}{}
			}
		}
	}
	return ret, nil
}
