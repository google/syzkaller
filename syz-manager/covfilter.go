// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

func createCoverageFilter(cfg *mgrconfig.Config, modules []cover.KernelModule) ([]uint64, map[uint64]struct{}, error) {
	if !cfg.HasCovFilter() {
		return nil, nil, nil
	}
	// Always initialize ReportGenerator because RPCServer.NewInput will need it to filter coverage.
	rg, err := getReportGenerator(cfg, modules)
	if err != nil {
		return nil, nil, err
	}
	pcs := make(map[uint64]struct{})
	foreachSymbol := func(apply func(*backend.ObjectUnit)) {
		for _, sym := range rg.Symbols {
			apply(&sym.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, cfg.CovFilter.Functions, foreachSymbol); err != nil {
		return nil, nil, err
	}
	foreachUnit := func(apply func(*backend.ObjectUnit)) {
		for _, unit := range rg.Units {
			apply(&unit.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, cfg.CovFilter.Files, foreachUnit); err != nil {
		return nil, nil, err
	}
	if err := covFilterAddRawPCs(pcs, cfg.CovFilter.RawPCs); err != nil {
		return nil, nil, err
	}
	// Copy pcs into execPCs. This is used to filter coverage in the executor.
	execPCs := make([]uint64, 0, len(pcs))
	for pc := range pcs {
		execPCs = append(execPCs, pc)
	}
	// PCs from CMPs are deleted to calculate `filtered coverage` statistics.
	for _, sym := range rg.Symbols {
		for _, pc := range sym.CMPs {
			delete(pcs, pc)
		}
	}
	return execPCs, pcs, nil
}

func covFilterAddFilter(pcs map[uint64]struct{}, filters []string, foreach func(func(*backend.ObjectUnit))) error {
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
	if len(res) != len(used) {
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

func createCoverageBitmap(cfg *mgrconfig.Config, pcs []uint64) []byte {
	// Return nil if filtering is not used.
	if len(pcs) == 0 {
		return nil
	}
	start, size := coverageFilterRegion(pcs)
	log.Logf(2, "coverage filter from 0x%x to 0x%x, size 0x%x, pcs %v", start, start+size, size, len(pcs))
	// The file starts with two uint64: covFilterStart and covFilterSize,
	// and a bitmap with size ((covFilterSize>>4)/8+2 bytes follow them.
	// 8-bit = 1-byte
	data := make([]byte, 16+((size>>4)/8+2))
	order := cfg.SysTarget.HostEndian
	order.PutUint64(data, start)
	order.PutUint64(data[8:], size)

	bitmap := data[16:]
	for _, pc := range pcs {
		// The lowest 4-bit is dropped.
		pc = backend.NextInstructionPC(cfg.SysTarget, cfg.Type, pc)
		pc = (pc - start) >> 4
		bitmap[pc/8] |= (1 << (pc % 8))
	}
	return data
}

func coverageFilterRegion(pcs []uint64) (uint64, uint64) {
	start, end := ^uint64(0), uint64(0)
	for _, pc := range pcs {
		if start > pc {
			start = pc
		}
		if end < pc {
			end = pc
		}
	}
	return start, end - start
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
