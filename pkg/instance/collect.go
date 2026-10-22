// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RunAttempt represents a single execution batch, returning results for numVMs.
type RunAttempt func(numVMs int) ([]EnvTestResult, error)

// CollectRunsOpts configures the execution of CollectRuns.
type CollectRunsOpts struct {
	WantValid int // Target number of valid runs to collect.
	MaxTotal  int // Maximum total number of runs (including failed infra runs).
	MaxVMs    int // Maximum number of VMs to run concurrently in a single batch.
	// Maximum number of batches to run after the batches that had infra errors.
	// Each such retry is preceded by infraErrorBackoff.
	MaxRetries int
}

// ErrTooManyInfraErrors is returned by CollectRuns if it could not collect enough valid runs
// because of infrastructure errors.
var ErrTooManyInfraErrors = errors.New("too many infra errors")

// infraErrorBackoff is the delay before the next batch if the previous one had infra errors.
// Such errors are usually caused by a temporary lack of cloud capacity, which takes time to recover.
const infraErrorBackoff = time.Minute

// CollectRuns runs attempts to collect the requested number of valid test results.
// It automatically retries on infrastructure errors.
func CollectRuns(ctx context.Context, attempt RunAttempt, opts CollectRunsOpts) ([]EnvTestResult, error) {
	if opts.MaxTotal < opts.WantValid {
		return nil, fmt.Errorf("collectRuns: MaxTotal (%d) cannot be less than WantValid (%d)", opts.MaxTotal, opts.WantValid)
	}
	opts.MaxVMs = max(opts.MaxVMs, 1)

	var validResults []EnvTestResult
	var lastInfraErr error

	totalAttempts := 0
	retries := 0
	backoff := false

	for totalAttempts < opts.MaxTotal && len(validResults) < opts.WantValid {
		if backoff {
			if retries >= opts.MaxRetries {
				break
			}
			retries++
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(infraErrorBackoff):
			}
			backoff = false
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Run as many as we need, up to MaxVMs.
		need := opts.WantValid - len(validResults)
		batchSize := min(need, opts.MaxVMs)
		// We still need to respect MaxTotal.
		batchSize = min(batchSize, opts.MaxTotal-totalAttempts)

		results, err := attempt(batchSize)
		if err != nil {
			return nil, err
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("collectRuns: attempt returned no results")
		}
		// The attempt may run fewer VMs than requested (e.g. if the VM pool is smaller).
		totalAttempts += len(results)

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
				backoff = true
			}
		}
	}

	if len(validResults) < opts.WantValid {
		return validResults, fmt.Errorf("%w: failed to collect %d valid runs within %d total attempts "+
			"and %d retries. Last infra error: %w", ErrTooManyInfraErrors, opts.WantValid, totalAttempts,
			retries, lastInfraErr)
	}
	return validResults[:opts.WantValid], nil // Trim just in case an attempt returned more than requested.
}
