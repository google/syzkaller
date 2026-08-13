// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

func parseHexPC(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, fmt.Errorf("empty PC address")
	}
	return strconv.ParseUint(s, 16, 64)
}

// CheckPCsInCoverage checks if any of the target PCs were executed during the
// cached run.
func CheckPCsInCoverage(ctx *aflow.Context, executionCachedID string, targetPCs ...uint64) (bool, error) {
	if len(targetPCs) == 0 {
		return false, nil
	}
	coverage, err := LoadCoverage(ctx, executionCachedID)
	if err != nil {
		return false, err
	}

	targetMap := make(map[uint64]bool, len(targetPCs))
	for _, pc := range targetPCs {
		targetMap[pc] = true
	}

	for _, callcov := range coverage {
		for _, frame := range callcov {
			if targetMap[frame.PC] {
				return true, nil
			}
		}
	}

	return false, nil
}

// CheckHexPCsInCoverage parses hex PC strings and returns true if any target PC
// was executed.
func CheckHexPCsInCoverage(ctx *aflow.Context, executionCachedID string, targetPCs ...string) (bool, error) {
	var parsedPCs []uint64
	for _, pcStr := range targetPCs {
		pc, err := parseHexPC(pcStr)
		if err != nil {
			return false, fmt.Errorf("invalid PC %q: %w", pcStr, err)
		}
		parsedPCs = append(parsedPCs, pc)
	}
	if len(parsedPCs) == 0 {
		return false, nil
	}
	return CheckPCsInCoverage(ctx, executionCachedID, parsedPCs...)
}
