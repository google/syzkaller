// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"

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

	triager := &seriesTriager{
		DebugTracer: tracer,
		client:      client,
		ops:         repo,
	}
	verdict, err := triager.GetVerdict(ctx, *flagSession)
	if err != nil {
		app.Fatalf("failed to get the verdict: %v", err)
	}
	err = client.UploadTriageResult(ctx, *flagSession, &api.UploadTriageResultReq{
		SkipReason: verdict.SkipReason,
		Log:        output.Bytes(),
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
	client *api.Client
	ops    triage.TreeOps
}

func (triager *seriesTriager) GetVerdict(ctx context.Context, sessionID string) (*api.TriageResult, error) {
	series, err := triager.client.GetSessionSeries(ctx, sessionID)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query series: %w", err)
	}
	treesResp, err := triager.client.GetTrees(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query trees: %w", err)
	}
	selectedTrees := triage.SelectTrees(series, treesResp.Trees)
	if len(selectedTrees) == 0 {
		return &api.TriageResult{
			SkipReason: "no suitable base kernel trees found",
		}, nil
	}
	fuzzConfigs := triage.MergeKernelFuzzConfigs(triage.SelectFuzzConfigs(series, treesResp.FuzzTargets))
	if len(fuzzConfigs) == 0 {
		return &api.TriageResult{
			SkipReason: "no suitable fuzz configs found",
		}, nil
	}
	ret := &api.TriageResult{}
	for _, campaign := range fuzzConfigs {
		fuzzTask, err := triager.prepareFuzzingTask(ctx, series, selectedTrees, campaign)
		var skipErr *SkipTriageError
		if errors.As(err, &skipErr) {
			ret.SkipReason = skipErr.Reason.Error()
			continue
		} else if err != nil {
			return nil, err
		}
		ret.Fuzz = append(ret.Fuzz, fuzzTask)
	}
	if len(ret.Fuzz) > 0 {
		// If we have prepared at least one fuzzing task, the series was not skipped.
		ret.SkipReason = ""
	}
	return ret, nil
}

func (triager *seriesTriager) prepareFuzzingTask(ctx context.Context, series *api.Series, trees []*api.Tree,
	target *triage.MergedFuzzConfig) (*api.FuzzTask, error) {
	var skipErr error
	for _, tree := range trees {
		triager.Log("considering tree %q", tree.Name)
		arch := "amd64"
		lastBuild, err := triager.client.LastBuild(ctx, &api.LastBuildReq{
			Arch:       arch,
			ConfigName: target.KernelConfig,
			TreeName:   tree.Name,
			Status:     api.BuildSuccess,
		})
		if err != nil {
			// TODO: the workflow step must be retried.
			return nil, fmt.Errorf("failed to query the last build for %q: %w", tree.Name, err)
		}
		triager.Log("%q's last build: %q", tree.Name, lastBuild)
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
			triager.Log("failed to find a base commit for %q", tree.Name)
			continue
		}
		triager.Log("selected base commit: %s", result.Commit)
		base := api.BuildRequest{
			TreeName:   tree.Name,
			TreeURL:    tree.URL,
			ConfigName: target.KernelConfig,
			CommitHash: result.Commit,
			Arch:       arch,
		}
		fuzz := &api.FuzzTask{
			Base:       base,
			Patched:    base,
			FuzzConfig: *target.FuzzConfig,
		}
		fuzz.Patched.SeriesID = series.ID
		return fuzz, nil
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
