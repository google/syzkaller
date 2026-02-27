// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package retest

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

type Runner struct {
	Client    *api.Client
	Base      instance.Env
	Patched   instance.Env
	SessionID string
	TestName  string
}

func (r *Runner) Run(ctx context.Context, task *api.RetestTask) error {
	for _, findingID := range task.Findings {
		log.Logf(0, "retesting finding %s", findingID)
		if err := r.retestFinding(ctx, findingID); err != nil {
			log.Logf(0, "failed to retest finding %s: %v", findingID, err)
		}
	}
	return nil
}

func (r *Runner) retestFinding(ctx context.Context, findingID string) error {
	finding, err := r.Client.GetFinding(ctx, findingID)
	if err != nil {
		return fmt.Errorf("failed to get finding: %w", err)
	}

	baseRes := testOnEnv(r.Base, finding)
	if err := r.uploadStep(ctx, finding, findingID, api.StepTargetBase, baseRes); err != nil {
		return fmt.Errorf("failed to upload base step: %w", err)
	}

	patchedRes := testOnEnv(r.Patched, finding)
	if err := r.uploadStep(ctx, finding, findingID, api.StepTargetPatched, patchedRes); err != nil {
		return fmt.Errorf("failed to upload patched step: %w", err)
	}

	// If the base did not crash and patched crashed, a finding should be reported.
	if baseRes.Status == api.StepResultPassed && patchedRes.Status == api.StepResultFailed {
		title := patchedRes.Title
		if title == "" {
			title = finding.Title
		}
		log.Logf(0, "found regression: %s", title)
		newFinding := &api.RawFinding{
			SessionID:    r.SessionID,
			TestName:     r.TestName,
			Title:        title,
			Log:          patchedRes.Log,
			Report:       patchedRes.Report,
			SyzRepro:     finding.SyzRepro,
			SyzReproOpts: finding.SyzReproOpts,
			CRepro:       finding.CRepro,
		}
		if err := r.Client.UploadFinding(ctx, newFinding); err != nil {
			return fmt.Errorf("failed to upload finding: %w", err)
		}
	}
	return nil
}

type testResult struct {
	Status string
	Log    []byte
	Report []byte
	Title  string
	Error  string
}

func testOnEnv(env instance.Env, finding *api.RawFinding) *testResult {
	const runAttempts = 3
	results, err := env.Test(runAttempts, finding.SyzRepro, finding.SyzReproOpts, finding.CRepro)

	ret := &testResult{
		Status: api.StepResultPassed,
	}

	// TODO: we also want to ensure that we actually got 3 results, and not
	// e.g. 2 infrastructure failures and 1 actual run.
	var res *instance.EnvTestResult
	if err == nil {
		res, err = instance.AggregateTestResults(results)
	}

	if err != nil {
		ret.Status = api.StepResultError
		ret.Error = err.Error()
		return ret
	}

	ret.Log = res.RawOutput
	if res.Error == nil {
		return ret
	}

	var testErr *instance.TestError
	var crashErr *instance.CrashError
	if errors.As(res.Error, &testErr) {
		ret.Status = api.StepResultError
		ret.Error = testErr.Title
		ret.Title = testErr.Title
		if testErr.Report != nil {
			ret.Report = testErr.Report.Report
			ret.Title = testErr.Report.Title
		}
	} else if errors.As(res.Error, &crashErr) {
		ret.Status = api.StepResultFailed
		if crashErr.Report != nil {
			ret.Report = crashErr.Report.Report
			ret.Title = crashErr.Report.Title
		}
	} else {
		ret.Status = api.StepResultError
		ret.Error = res.Error.Error()
	}
	return ret
}

func (r *Runner) uploadStep(ctx context.Context, finding *api.RawFinding,
	findingID, target string, res *testResult) error {
	log := res.Log
	if res.Error != "" {
		log = append(log, []byte("\nError: "+res.Error)...)
	}
	step := &api.SessionTestStep{
		TestName:  r.TestName,
		Title:     finding.Title,
		Log:       log,
		FindingID: findingID,
		Target:    target,
		Result:    res.Status,
	}
	return r.Client.UploadTestStep(ctx, r.SessionID, step)
}
