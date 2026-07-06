// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"github.com/google/syzkaller/pkg/aflow"
)

func CheckPCInCoverage(ctx *aflow.Context, executionCachedID string, targetPC uint64) (bool, error) {
	coverage, err := LoadCoverage(ctx, executionCachedID)
	if err != nil {
		return false, err
	}

	for _, callcov := range coverage {
		for _, frame := range callcov {
			if frame.PC == targetPC {
				return true, nil
			}
		}
	}

	return false, nil
}
