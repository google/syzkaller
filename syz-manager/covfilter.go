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

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func createCoverageFilter(cfg *mgrconfig.Config) (string, map[uint32]uint32, error) {
	pcs := make(map[uint32]uint32)
	filter := &cfg.CovFilter
	if len(filter.Files) != 0 || len(filter.Functions) != 0 {
		log.Logf(0, "initializing coverage information...")
		if err := initCover(cfg.SysTarget, cfg.KernelObj, cfg.KernelSrc, cfg.KernelBuildSrc); err != nil {
			return "", nil, err
		}
		if err := initFilesFuncs(pcs, filter.Files, filter.Functions); err != nil {
			return "", nil, err
		}
	}
	if err := initWeightedPCs(pcs, filter.RawPCs); err != nil {
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
	return filename, pcs, nil
}

func initFilesFuncs(pcs map[uint32]uint32, files, funcs []string) error {
	funcsRegexp, err := compileRegexps(funcs)
	if err != nil {
		return err
	}
	filesRegexp, err := compileRegexps(files)
	if err != nil {
		return err
	}
	fileDedup := make(map[string]bool)
	used := make(map[*regexp.Regexp][]string)
	for _, sym := range reportGenerator.Symbols {
		matched := false
		for _, re := range funcsRegexp {
			if re.MatchString(sym.Name) {
				matched = true
				used[re] = append(used[re], sym.Name)
				break
			}
		}
		for _, re := range filesRegexp {
			file := sym.Unit.Name
			if re.MatchString(file) {
				matched = true
				if !fileDedup[file] {
					fileDedup[file] = true
					used[re] = append(used[re], file)
				}
				break
			}
		}
		if matched {
			for _, pc := range sym.PCs {
				pcs[uint32(pc)] = 1
			}
		}
	}
	for _, re := range filesRegexp {
		sort.Strings(used[re])
		log.Logf(0, "coverage file filter: %v: %v", re, used[re])
	}
	for _, re := range funcsRegexp {
		sort.Strings(used[re])
		log.Logf(0, "coverage func filter: %v: %v", re, used[re])
	}
	if len(filesRegexp)+len(funcsRegexp) != len(used) {
		return fmt.Errorf("some coverage filters don't match anything")
	}
	return nil
}

func initWeightedPCs(pcs map[uint32]uint32, rawPCsFiles []string) error {
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
