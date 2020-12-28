// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func createCoverageFilter(cfg *mgrconfig.Config) (string, map[uint32]uint32, error) {
	if len(cfg.CovFilter.Functions)+len(cfg.CovFilter.Files)+len(cfg.CovFilter.RawPCs) == 0 {
		return "", nil, nil
	}
	// Always initialize ReportGenerator because RPCServer.NewInput will need it to filter coverage.
	rg, err := getReportGenerator(cfg)
	if err != nil {
		return "", nil, err
	}
	pcs := make(map[uint32]uint32)
	foreachSymbol := func(apply func(*backend.ObjectUnit)) {
		for _, sym := range rg.Symbols {
			apply(&sym.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, cfg.CovFilter.Functions, foreachSymbol); err != nil {
		return "", nil, err
	}
	foreachUnit := func(apply func(*backend.ObjectUnit)) {
		for _, unit := range rg.Units {
			apply(&unit.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, cfg.CovFilter.Files, foreachUnit); err != nil {
		return "", nil, err
	}
	if err := covFilterAddRawPCs(pcs, cfg.CovFilter.RawPCs); err != nil {
		return "", nil, err
	}
	if len(pcs) == 0 {
		return "", nil, nil
	}
	if !cfg.SysTarget.ExecutorUsesShmem {
		return "", nil, fmt.Errorf("coverage filter is only supported for targets that use shmem")
	}
	bitmap := createCoverageBitmap(cfg.SysTarget, pcs)
	filename := filepath.Join(cfg.Workdir, "syz-cover-bitmap")
	if err := osutil.WriteFile(filename, bitmap); err != nil {
		return "", nil, err
	}
	// After finish writing down bitmap file, for accurate filtered coverage,
	// pcs from CMPs should be deleted.
	for _, sym := range rg.Symbols {
		for _, pc := range sym.CMPs {
			delete(pcs, uint32(pc))
		}
	}
	return filename, pcs, nil
}

func covFilterAddFilter(pcs map[uint32]uint32, filters []string, foreach func(func(*backend.ObjectUnit))) error {
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
					pcs[uint32(pc)] = 1
				}
				for _, pc := range unit.CMPs {
					pcs[uint32(pc)] = 1
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

func covFilterAddRawPCs(pcs map[uint32]uint32, rawPCsFiles []string) error {
	re := regexp.MustCompile(`(0x[0-9a-f]+)(?:: (0x[0-9a-f]+))?`)
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("failed to open raw PCs file: %v", err)
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
			pcs[uint32(pc)] = uint32(weight)
		}
		if err := s.Err(); err != nil {
			return err
		}
	}
	return nil
}

func createCoverageBitmap(target *targets.Target, pcs map[uint32]uint32) []byte {
	start, size := coverageFilterRegion(pcs)
	log.Logf(0, "coverage filter from 0x%x to 0x%x, size 0x%x, pcs %v", start, start+size, size, len(pcs))
	// The file starts with two uint32: covFilterStart and covFilterSize,
	// and a bitmap with size ((covFilterSize>>4) + 7)/8 bytes follow them.
	// 8-bit = 1-byte, additional 1-byte to prevent overflow
	data := make([]byte, 8+((size>>4)+7)/8)
	order := binary.ByteOrder(binary.BigEndian)
	if target.LittleEndian {
		order = binary.LittleEndian
	}
	order.PutUint32(data, start)
	order.PutUint32(data[4:], size)

	bitmap := data[8:]
	for pc := range pcs {
		// The lowest 4-bit is dropped.
		pc = (pc - start) >> 4
		bitmap[pc/8] |= (1 << (pc % 8))
	}
	return data
}

func coverageFilterRegion(pcs map[uint32]uint32) (uint32, uint32) {
	start, end := ^uint32(0), uint32(0)
	for pc := range pcs {
		if start > pc {
			start = pc
		}
		if end < pc {
			end = pc
		}
	}
	// align
	start &= ^uint32(0xf)
	end = (end + 0xf) &^ uint32(0xf)
	return start, end - start
}

func compileRegexps(regexpStrings []string) ([]*regexp.Regexp, error) {
	var regexps []*regexp.Regexp
	for _, rs := range regexpStrings {
		r, err := regexp.Compile(rs)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		regexps = append(regexps, r)
	}
	return regexps, nil
}
