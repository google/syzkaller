// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/triage"
)

var (
	flagSession = flag.String("session", "", "session ID")
	flagRepo    = flag.String("repository", "", "path to a kernel checkout")
	flagVerdict = flag.String("verdict", "", "where to save the verdict")
)

func main() {
	flag.Parse()
	if *flagSession == "" || *flagRepo == "" {
		// TODO: abort the whole workflow, no sense to retry. Alert the error.
		app.Fatalf("--session and --repo must be set")
	}
	client := app.DefaultClient()
	repo, err := triage.NewGitTreeOps(*flagRepo, true)
	if err != nil {
		app.Fatalf("failed to initialize the repository: %v", err)
	}
	ctx := context.Background()
	output := new(bytes.Buffer)
	tracer := &debugtracer.GenericTracer{WithTime: true, TraceWriter: output}

	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to load app config: %v", err)
	}

	triager := &seriesTriager{
		DebugTracer: tracer,
		client:      client,
		ops:         repo,
		config:      cfg,
	}
	verdict, err := triager.GetVerdict(ctx, *flagSession)
	if err != nil {
		app.Fatalf("failed to get the verdict: %v", err)
	}
	err = client.UploadTriageResult(ctx, *flagSession, &api.UploadTriageResultReq{
		SkipReason: verdict.SkipReason,
		Log:        output.Bytes(),
		Trajectory: verdict.Trajectory,
	})
	if err != nil {
		app.Fatalf("failed to upload triage results: %v", err)
	}
	if *flagVerdict != "" {
		osutil.WriteJSON(*flagVerdict, verdict)
	}

	// TODO:
	// 1. It might be that the kernel builds/boots for one arch and does not build for another.
	// 2. What if controller does not reply? Let Argo just restart the step.
}

type seriesTriager struct {
	debugtracer.DebugTracer
	client    *api.Client
	ops       *triage.GitTreeOps
	config    *app.AppConfig
	aiVerdict *triage.AITriageResult
}

func (triager *seriesTriager) GetVerdict(ctx context.Context, sessionID string) (*api.TriageResult, error) {
	sessionInfo, err := triager.client.GetSessionInfo(ctx, sessionID)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query series: %w", err)
	}
	series := sessionInfo.Series
	treesResp, err := triager.client.GetTrees(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query trees: %w", err)
	}
	if sessionInfo.Job != nil {
		return triager.prepareJobTask(series, sessionInfo.Job, treesResp.Trees)
	}
	fuzzConfigs := triage.MergeKernelFuzzConfigs(triage.SelectFuzzConfigs(series, treesResp.FuzzTargets))
	if len(fuzzConfigs) == 0 {
		return &api.TriageResult{
			SkipReason: "no suitable fuzz configs found",
		}, nil
	}
	ret := &api.TriageResult{}
	for _, campaign := range fuzzConfigs {
		fuzzTask, err := triager.prepareFuzzingTask(ctx, series, sessionInfo.Direct, treesResp.Trees, campaign)
		if skipErr, ok := errors.AsType[*SkipTriageError](err); ok {
			ret.SkipReason = skipErr.Reason.Error()
			continue
		} else if err != nil {
			return nil, err
		}
		ret.Targets = append(ret.Targets, fuzzTask)
	}
	if len(ret.Targets) > 0 {
		// If we have prepared at least one fuzzing task, the series was not skipped.
		ret.SkipReason = ""
	}
	if triager.aiVerdict != nil {
		ret.Trajectory = triager.aiVerdict.Trajectory
	}
	return ret, nil
}

func (triager *seriesTriager) prepareFuzzingTask(ctx context.Context, series *api.Series, forceTriage bool,
	trees []*api.Tree, target *triage.MergedFuzzConfig) (*api.TestTarget, error) {
	var err error
	if target.FuzzConfig, err = prepareFuzzConfig(target.FuzzConfig); err != nil {
		return nil, err
	}

	result, err := triager.selectBaseCommit(ctx, series, trees, target)
	if err != nil {
		return nil, err
	}
	triager.Logf("continuing with %v in %v", result.Commit, result.Tree.Name)

	if err := triager.ops.ApplySeries(result.Commit, series.PatchBodies()); err != nil {
		return nil, fmt.Errorf("failed to apply series to base commit: %w", err)
	}

	if err := triager.evaluateAI(ctx, series, forceTriage); err != nil {
		return nil, err
	}
	base := api.BuildRequest{
		TreeName:      result.Tree.Name,
		TreeURL:       result.Tree.URL,
		ConfigName:    target.KernelConfig,
		CommitHash:    result.Commit,
		Arch:          target.FuzzConfig.Arch,
		EnableConfigs: triager.aiVerdict.EnableConfigs,
		VMType:        target.FuzzConfig.VMType,
	}
	fuzzCfg := new(api.FuzzConfig)
	*fuzzCfg = *target.FuzzConfig
	fuzzCfg.FocusSymbols = triager.aiVerdict.FocusSymbols
	testTarget := &api.TestTarget{
		Base:    base,
		Patched: base,
		Track:   target.Track,
		Fuzz:    fuzzCfg,
	}
	testTarget.Patched.SeriesID = series.ID
	retestFindings, err := triager.client.ListPreviousFindings(ctx, &api.ListPreviousFindingsReq{
		SeriesID: series.ID,
		Arch:     target.FuzzConfig.Arch,
		Config:   target.KernelConfig,
	})
	if err != nil {
		// This is sad, but not critical.
		app.Errorf("failed to query previous findings: %v", err)
	} else if len(retestFindings) > 0 {
		triager.Logf("scheduling retest for %d findings", len(retestFindings))
		testTarget.Retest = &api.RetestTask{
			Findings: retestFindings,
		}
	}
	return testTarget, nil
}

func prepareFuzzConfig(cfg *api.FuzzConfig) (*api.FuzzConfig, error) {
	if cfg == nil {
		cfg = &api.FuzzConfig{}
	}
	if cfg.Arch == "" {
		cfg.Arch = "amd64"
	}
	if cfg.VMType == "" {
		cfg.VMType = "qemu"
	}
	if cfg.VMType != "gce" && cfg.VMType != "qemu" {
		return nil, SkipError(fmt.Sprintf("only gce and qemu vms are supported now. %s is not supported", cfg.VMType))
	}
	return cfg, nil
}

func (triager *seriesTriager) selectBaseCommit(
	ctx context.Context, series *api.Series, trees []*api.Tree, target *triage.MergedFuzzConfig,
) (*SelectResult, error) {
	if result, err := triager.selectFromBaseCommitHint(series.BaseCommitHint, trees); err != nil {
		return nil, fmt.Errorf("selection by base-commit failed: %w", err)
	} else if result != nil {
		return result, nil
	}

	if result, err := triager.selectFromBlobs(series, trees); err != nil {
		return nil, fmt.Errorf("selection by blob failed: %w", err)
	} else if result != nil {
		return result, nil
	}

	if result, err := triager.selectFromList(ctx, series, trees, target); err != nil {
		return nil, fmt.Errorf("selection from the list failed: %w", err)
	} else if result != nil {
		return result, nil
	}

	return nil, SkipError("no base commit found")
}

func (triager *seriesTriager) evaluateAI(ctx context.Context, series *api.Series, forceTriage bool) error {
	if triager.aiVerdict == nil {
		triager.aiVerdict = &triage.AITriageResult{WorthFuzzing: true}
		if !triager.config.AI.Empty() {
			if err := triage.CommitPatchForAflow(triager.ops); err != nil {
				return fmt.Errorf("failed to commit patch for aflow: %w", err)
			}
			aiResult, err := triage.EvaluatePatch(ctx, triager.config, series, triager.DebugTracer, "/workdir")
			if err != nil {
				triager.Logf("AI evaluation failed: %v", err)
			} else if aiResult != nil {
				triager.aiVerdict = aiResult
			}
		}
	}

	if forceTriage && !triager.aiVerdict.WorthFuzzing {
		triager.Logf("AI determined the patch has no functional impact, but fuzzing is forced")
		triager.aiVerdict.WorthFuzzing = true
	}

	if !triager.aiVerdict.WorthFuzzing {
		return SkipError("AI determined the patch has no functional impact")
	}
	return nil
}

func (triager *seriesTriager) prepareJobTask(
	series *api.Series, job *api.Job, trees []*api.Tree,
) (*api.TriageResult, error) {
	var targets []*api.TestTarget
	for i, task := range job.FindingGroups {
		foundTree := triage.FindTreeByName(trees, task.Build.TreeName)
		if foundTree == nil {
			return &api.TriageResult{
				SkipReason: fmt.Sprintf("tree %q is no longer known", task.Build.TreeName),
			}, nil
		}
		triager.Logf("continuing with job's original tree %q", task.Build.TreeName)
		testTarget := &api.TestTarget{
			Track: fmt.Sprintf("build %d", i),
		}
		testTarget.Patched = api.BuildRequest{
			TreeName:   task.Build.TreeName,
			TreeURL:    task.Build.TreeURL,
			ConfigName: task.Build.ConfigName,
			CommitHash: task.Build.CommitHash,
			Arch:       task.Build.Arch,
			SeriesID:   series.ID,
			JobID:      job.ID,
			VMType:     task.Build.VMType,
		}
		if len(task.FindingIDs) > 0 {
			testTarget.Retest = &api.RetestTask{
				Findings: task.FindingIDs,
			}
		}
		targets = append(targets, testTarget)
	}
	if len(targets) == 0 {
		return &api.TriageResult{
			SkipReason: "job has no testing tasks available",
		}, nil
	}
	return &api.TriageResult{
		Targets: targets,
	}, nil
}

type SelectResult struct {
	Tree   *api.Tree
	Commit string
}

func (triager *seriesTriager) selectFromBlobs(series *api.Series, trees []*api.Tree) (*SelectResult, error) {
	triager.Logf("attempting to guess the base commit by blob hashes")
	var diff []byte
	for _, patch := range series.Patches {
		diff = append(diff, patch.Body...)
		diff = append(diff, '\n')
	}
	baseList, err := triager.ops.BaseForDiff(diff, triager.DebugTracer)
	if err != nil {
		return nil, err
	}
	tree, commit := triage.FromBaseCommits(series, baseList, trees)
	if tree == nil {
		triager.Logf("no candidate base commit is found")
		return nil, nil
	}
	return &SelectResult{
		Tree:   tree,
		Commit: commit,
	}, nil
}

func (triager *seriesTriager) selectFromBaseCommitHint(commit string, trees []*api.Tree) (*SelectResult, error) {
	if commit == "" {
		return nil, nil
	}
	triager.Logf("attempting to use the base commit %s provided by author", commit)
	commitExists, _ := triager.ops.Git.CommitExists(commit)
	if !commitExists {
		triager.Logf("commit doesn't exist")
		return nil, nil
	}
	const cutOffDays = 60
	branchList, err := triager.ops.BranchesThatContain(commit, time.Now().Add(-time.Hour*24*cutOffDays))
	if err != nil {
		return nil, fmt.Errorf("failed to query branches: %w", err)
	}
	for _, branch := range branchList {
		treeIndex, _ := triage.FindTree(trees, branch.Branch)
		if treeIndex != -1 {
			return &SelectResult{
				Tree:   trees[treeIndex],
				Commit: commit,
			}, nil
		}
	}
	return nil, nil
}

func (triager *seriesTriager) selectFromList(ctx context.Context, series *api.Series, trees []*api.Tree,
	target *triage.MergedFuzzConfig) (*SelectResult, error) {
	selectedTrees := triage.SelectTrees(series, trees)
	if len(selectedTrees) == 0 {
		return nil, SkipError("no suitable base kernel trees found")
	}
	var skipErr error
	for _, tree := range selectedTrees {
		triager.Logf("considering tree %q", tree.Name)
		lastBuild, err := triager.client.LastBuild(ctx, &api.LastBuildReq{
			Arch:       target.FuzzConfig.Arch,
			ConfigName: target.KernelConfig,
			TreeName:   tree.Name,
			Status:     api.BuildSuccess,
		})
		if err != nil {
			// TODO: the workflow step must be retried.
			return nil, fmt.Errorf("failed to query the last build for %q: %w", tree.Name, err)
		}
		triager.Logf("%q's last build: %q", tree.Name, lastBuild)
		selector := triage.NewCommitSelector(triager.ops, triager.DebugTracer)
		result, err := selector.Select(series, tree, lastBuild)
		if err != nil {
			// TODO: the workflow step must be retried.
			return nil, fmt.Errorf("failed to run the commit selector for %q: %w", tree.Name, err)
		} else if result.Commit == "" {
			// If we fail to find a suitable commit for all the trees, return an error just about the first one.
			if skipErr == nil {
				skipErr = SkipError("failed to find a base commit: " + result.Reason)
			}
			triager.Logf("failed to find a base commit for %q", tree.Name)
			continue
		}
		triager.Logf("result: %s", result.Commit)
		return &SelectResult{
			Tree:   tree,
			Commit: result.Commit,
		}, nil
	}
	return nil, skipErr
}

type SkipTriageError struct {
	Reason error
}

func SkipError(reason string) *SkipTriageError {
	return &SkipTriageError{Reason: errors.New(reason)}
}

func (e *SkipTriageError) Error() string {
	return fmt.Sprintf("series must be skipped: %s", e.Reason)
}

func (e *SkipTriageError) Unwrap() error {
	return e.Reason
}
