// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"errors"
	"fmt"
)

// AggregateTestResults selects the most relevant result from a set of test runs.
// It prioritizes crashes, then successes (to ignore transient errors), then errors.
func AggregateTestResults(results []EnvTestResult) (*EnvTestResult, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no env test runs")
	}

	var best *EnvTestResult
	var bestRank int
	for i := range results {
		res := &results[i]
		rank, preferLast := resultRank(res)
		if best == nil {
			best = res
			bestRank = rank
			continue
		}
		if rank > bestRank {
			best = res
			bestRank = rank
		} else if rank == bestRank && preferLast {
			best = res
		}
	}
	return best, nil
}

const (
	rankError       = 1
	rankSuccess     = 2
	rankCrash       = 3 // Crash without report.
	rankCrashReport = 4 // Crash with report.
)

// resultRank returns the rank of the result and whether we should prefer
// the last result (true) or first (false).
func resultRank(res *EnvTestResult) (int, bool) {
	if res.Error == nil {
		return rankSuccess, true
	}
	var crash *CrashError
	if errors.As(res.Error, &crash) {
		if crash.Report != nil && len(crash.Report.Report) > 0 {
			return rankCrashReport, false
		}
		return rankCrash, false
	}
	return rankError, true
}
