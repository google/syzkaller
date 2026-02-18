// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package retest

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEnv struct {
	results []instance.EnvTestResult
	err     error
}

func (m *mockEnv) BuildSyzkaller(repo, commit string) (string, error) { return "", nil }
func (m *mockEnv) BuildKernel(cfg *instance.BuildKernelConfig) (string, build.ImageDetails, error) {
	return "", build.ImageDetails{}, nil
}
func (m *mockEnv) CleanKernel(cfg *instance.BuildKernelConfig) error { return nil }
func (m *mockEnv) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]instance.EnvTestResult, error) {
	return m.results, m.err
}

func runTest(t *testing.T, params TestParams) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)

	// 1. Create Series and initial Session (Discovery).
	ids := controller.UploadTestSeries(t, ctx, client, controller.DummySeries())
	baseBuild := controller.UploadTestBuild(t, ctx, client, controller.DummyBuild())
	patchedBuild := controller.UploadTestBuild(t, ctx, client, controller.DummyBuild())

	err := client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      ids.SessionID,
		BaseBuildID:    baseBuild.ID,
		PatchedBuildID: patchedBuild.ID,
		TestName:       "test",
		Result:         api.TestFailed,
	})
	require.NoError(t, err)

	finding := &api.RawFinding{
		SessionID: ids.SessionID,
		TestName:  "test",
		Title:     "crash title",
		SyzRepro:  []byte("repro"),
	}
	err = client.UploadFinding(ctx, finding)
	require.NoError(t, err)

	repo := db.NewFindingRepository(env.Spanner)
	findings, err := repo.ListForSession(ctx, ids.SessionID, 1)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	findingID := findings[0].ID

	// 2. Create second Session (Retest).
	retestSession, err := client.UploadSession(ctx, &api.NewSession{
		ExtID: "ext-id",
	})
	require.NoError(t, err)
	retestSessionID := retestSession.ID

	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      retestSessionID,
		BaseBuildID:    baseBuild.ID,
		PatchedBuildID: patchedBuild.ID,
		TestName:       "retest",
		Result:         api.TestRunning,
	})
	require.NoError(t, err)

	base := &mockEnv{results: params.BaseResults, err: params.BaseError}
	patched := &mockEnv{results: params.PatchedResults, err: params.PatchedError}

	runner := &Runner{
		Client:    client,
		Base:      base,
		Patched:   patched,
		SessionID: retestSessionID,
		TestName:  "retest",
	}

	task := &api.RetestTask{Findings: []string{findingID}}
	err = runner.Run(ctx, task)
	assert.NoError(t, err)

	findings, err = repo.ListForSession(ctx, retestSessionID, 10)
	assert.NoError(t, err)

	var titles []string
	for _, f := range findings {
		titles = append(titles, f.Title)
	}
	assert.Equal(t, params.ExpectedTitles, titles)

	stepRepo := db.NewSessionTestStepRepository(env.Spanner)
	steps, err := stepRepo.ListForSession(ctx, retestSessionID, "retest")
	assert.NoError(t, err)

	var baseStatus, patchedStatus string
	for _, step := range steps {
		switch step.Target {
		case api.StepTargetBase:
			baseStatus = step.Result
		case api.StepTargetPatched:
			patchedStatus = step.Result
		}
	}
	assert.Equal(t, params.ExpectedBaseStatus, baseStatus, "base status mismatch")
	assert.Equal(t, params.ExpectedPatchedStatus, patchedStatus, "patched status mismatch")
}

type TestParams struct {
	BaseResults           []instance.EnvTestResult
	BaseError             error
	PatchedResults        []instance.EnvTestResult
	PatchedError          error
	ExpectedTitles        []string
	ExpectedBaseStatus    string
	ExpectedPatchedStatus string
}

func TestRetestScenarios(t *testing.T) {
	t.Run("both crash", func(t *testing.T) {
		crash := instance.EnvTestResult{
			Error: &instance.CrashError{
				Report: &report.Report{Title: "crash title"},
			},
		}
		runTest(t, TestParams{
			BaseResults:           []instance.EnvTestResult{crash},
			PatchedResults:        []instance.EnvTestResult{crash},
			ExpectedTitles:        nil,
			ExpectedBaseStatus:    api.StepResultFailed,
			ExpectedPatchedStatus: api.StepResultFailed,
		})
	})

	t.Run("patched affected", func(t *testing.T) {
		pass := instance.EnvTestResult{RawOutput: []byte("log")}
		crash := instance.EnvTestResult{
			RawOutput: []byte("log"),
			Error: &instance.CrashError{
				Report: &report.Report{Title: "new crash"},
			},
		}
		runTest(t, TestParams{
			BaseResults:           []instance.EnvTestResult{pass},
			PatchedResults:        []instance.EnvTestResult{crash},
			ExpectedTitles:        []string{"new crash"},
			ExpectedBaseStatus:    api.StepResultPassed,
			ExpectedPatchedStatus: api.StepResultFailed,
		})
	})

	t.Run("both pass", func(t *testing.T) {
		pass := instance.EnvTestResult{RawOutput: []byte("log")}
		runTest(t, TestParams{
			BaseResults:           []instance.EnvTestResult{pass},
			PatchedResults:        []instance.EnvTestResult{pass},
			ExpectedTitles:        nil,
			ExpectedBaseStatus:    api.StepResultPassed,
			ExpectedPatchedStatus: api.StepResultPassed,
		})
	})

	t.Run("patched mixed", func(t *testing.T) {
		pass := instance.EnvTestResult{RawOutput: []byte("log")}
		crash := instance.EnvTestResult{
			RawOutput: []byte("log"),
			Error: &instance.CrashError{
				Report: &report.Report{Title: "mixed crash"},
			},
		}
		runTest(t, TestParams{
			BaseResults:           []instance.EnvTestResult{pass},
			PatchedResults:        []instance.EnvTestResult{pass, crash},
			ExpectedTitles:        []string{"mixed crash"},
			ExpectedBaseStatus:    api.StepResultPassed,
			ExpectedPatchedStatus: api.StepResultFailed,
		})
	})

	t.Run("test failure", func(t *testing.T) {
		runTest(t, TestParams{
			BaseError:             fmt.Errorf("test failure"),
			PatchedResults:        []instance.EnvTestResult{{RawOutput: []byte("log")}},
			ExpectedTitles:        nil,
			ExpectedBaseStatus:    api.StepResultError,
			ExpectedPatchedStatus: api.StepResultPassed,
		})
	})
}
