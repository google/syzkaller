// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"errors"
	"fmt"
)

// RunAttempt represents a single execution batch, returning results for numVMs.
type RunAttempt func(numVMs int) ([]EnvTestResult, error)

// CollectRunsOpts configures the execution of CollectRuns.
type CollectRunsOpts struct {
	WantValid int // Target number of valid runs to collect.
	MaxTotal  int // Maximum total number of runs (including failed infra runs).
	MaxVMs    int // Maximum number of VMs to run concurrently in a single batch.
}

// CollectRuns runs attempts to collect the requested number of valid test results.
// It automatically retries on infrastructure errors.
func CollectRuns(attempt RunAttempt, opts CollectRunsOpts) ([]EnvTestResult, error) {
	if opts.MaxTotal < opts.WantValid {
		return nil, fmt.Errorf("collectRuns: MaxTotal (%d) cannot be less than WantValid (%d)", opts.MaxTotal, opts.WantValid)
	}
	opts.MaxVMs = max(opts.MaxVMs, 1)

	var validResults []EnvTestResult
	var lastInfraErr error

	totalAttempts := 0

	for totalAttempts < opts.MaxTotal && len(validResults) < opts.WantValid {
		// Run as many as we need, up to MaxVMs.
		need := opts.WantValid - len(validResults)
		batchSize := min(need, opts.MaxVMs)
		// We still need to respect MaxTotal.
		batchSize = min(batchSize, opts.MaxTotal-totalAttempts)

		results, err := attempt(batchSize)
		totalAttempts += batchSize

		if err != nil {
			return nil, err
		}

		for _, res := range results {
			if res.Error == nil {
				validResults = append(validResults, res)
				continue
			}

			var crashErr *CrashError
			var testErr *TestError
			if errors.As(res.Error, &crashErr) || (errors.As(res.Error, &testErr) && !testErr.Infra) {
				validResults = append(validResults, res)
			} else {
				lastInfraErr = res.Error
			}
		}
	}

	if len(validResults) < opts.WantValid {
		return validResults, fmt.Errorf("failed to collect %d valid runs within %d total attempts. Last infra error: %w",
			opts.WantValid, opts.MaxTotal, lastInfraErr)
	}
	return validResults[:opts.WantValid], nil // Trim just in case an attempt returned more than requested.
}
