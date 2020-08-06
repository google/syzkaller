// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type CoverFilter struct {
	pcStart     uint32
	pcSize      uint32
	pcEnd       uint32
	weightedPCs map[uint32]uint32

	bitmapFilename string
	target         *targets.Target
}

func createCoverageFilter(cfg *mgrconfig.Config) (covFilterFilename string, err error) {
	files := cfg.CovFilter.Files
	funcs := cfg.CovFilter.Functions
	rawPCs := cfg.CovFilter.RawPCs
	if len(files) == 0 && len(funcs) == 0 && len(rawPCs) == 0 {
		return "", nil
	}
	filesRegexp, err := getRegexps(files)
	if err != nil {
		return "", err
	}
	funcsRegexp, err := getRegexps(funcs)
	if err != nil {
		return "", err
	}

	covFilter := CoverFilter{
		weightedPCs:    make(map[uint32]uint32),
		target:         cfg.SysTarget,
		bitmapFilename: cfg.Workdir + "/" + "syz-cover-bitmap",
	}

	if len(filesRegexp) > 0 || len(funcsRegexp) > 0 {
		log.Logf(0, "initialize coverage information...")
		if err = initCover(cfg.SysTarget, cfg.KernelObj, cfg.KernelSrc, cfg.KernelBuildSrc); err != nil {
			return "", err
		}
		symbols := reportGenerator.GetSymbolsInfo()
		if err = covFilter.initFilesFuncs(filesRegexp, funcsRegexp, symbols); err != nil {
			return "", err
		}
	}

	if err = covFilter.initWeightedPCs(rawPCs); err != nil {
		return "", err
	}

	covFilter.detectRegion()
	if covFilter.pcSize > 0 {
		log.Logf(0, "coverage filter from 0x%x to 0x%x, size 0x%x",
			covFilter.pcStart, covFilter.pcEnd, covFilter.pcSize)
	} else {
		return "", fmt.Errorf("coverage filter is enabled but nothing will be filtered")
	}

	if err = osutil.WriteFile(covFilter.bitmapFilename, covFilter.bitmapBytes()); err != nil {
		return "", err
	}
	return covFilter.bitmapFilename, nil
}

func getRegexps(regexpStrings []string) ([]*regexp.Regexp, error) {
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

func (covFilter *CoverFilter) initFilesFuncs(filesRegexp, funcsRegexp []*regexp.Regexp, symbols []cover.Symbol) error {
	fileDedup := make(map[string]bool)
	used := make(map[*regexp.Regexp][]string)
	for _, sym := range symbols {
		matched := false
		for _, re := range funcsRegexp {
			if re.MatchString(sym.Name) {
				matched = true
				used[re] = append(used[re], sym.Name)
				break
			}
		}
		for _, re := range filesRegexp {
			if re.MatchString(sym.File) {
				matched = true
				if !fileDedup[sym.File] {
					fileDedup[sym.File] = true
					used[re] = append(used[re], sym.File)
				}
				break
			}
		}
		if matched {
			for _, pc := range sym.PCs {
				covFilter.weightedPCs[uint32(pc)] = 1
			}
		}
	}

	for _, re := range filesRegexp {
		if _, ok := used[re]; !ok {
			log.Logf(0, "coverage file filter doesn't match anything: %v", re.String())
		} else {
			log.Logf(1, "coverage file filter: %v: %v", re.String(), used[re])
		}
	}
	for _, re := range funcsRegexp {
		if _, ok := used[re]; !ok {
			log.Logf(0, "coverage func filter doesn't match anything: %v", re.String())
		} else {
			log.Logf(1, "coverage func filter: %v: %v", re.String(), used[re])
		}
	}
	// TODO: do we want to error on this? or logging it enough?
	if len(filesRegexp)+len(funcsRegexp) != len(used) {
		return fmt.Errorf("some coverage filters don't match anything")
	}
	return nil
}

func (covFilter *CoverFilter) initWeightedPCs(rawPCsFiles []string) error {
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("failed to open raw PCs file: %v", err)
		}
		defer rawFile.Close()

		s := bufio.NewScanner(rawFile)
		re := regexp.MustCompile(`(0x[0-9a-f]+)(?:: (0x[0-9a-f]+))?`)
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
			covFilter.weightedPCs[uint32(pc)] = uint32(weight)
		}
	}
	return nil
}

func (covFilter *CoverFilter) detectRegion() {
	covFilter.pcStart = ^uint32(0)
	covFilter.pcEnd = 0x0
	for pc := range covFilter.weightedPCs {
		if pc < covFilter.pcStart {
			covFilter.pcStart = pc
		}
		if pc > covFilter.pcEnd {
			covFilter.pcEnd = pc
		}
	}
	// align
	covFilter.pcStart &= ^uint32(0xf)
	covFilter.pcEnd = (covFilter.pcEnd + 0xf) &^ uint32(0xf)
	covFilter.pcSize = covFilter.pcEnd - covFilter.pcStart
}

func (covFilter *CoverFilter) bitmapBytes() []byte {
	// The file starts with two uint32: covFilterStart and covFilterSize,
	// and a bitmap with size ((covFilterSize>>4) + 7)/8 bytes follow them.
	// 8-bit = 1-byte, additional 1-byte to prevent overflow
	data := make([]byte, 8+((covFilter.pcSize>>4)+7)/8)
	order := binary.ByteOrder(binary.BigEndian)
	if covFilter.target.LittleEndian {
		order = binary.LittleEndian
	}
	order.PutUint32(data, covFilter.pcStart)
	order.PutUint32(data[4:], covFilter.pcSize)

	bitmap := data[8:]
	for pc := range covFilter.weightedPCs {
		// The lowest 4-bit is dropped.
		pc = (pc - covFilter.pcStart) >> 4
		bitmap[pc/8] |= (1 << (pc % 8))
	}
	return data
}
