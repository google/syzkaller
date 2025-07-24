// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
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
	verdict, err := getVerdict(ctx, tracer, client, repo)
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

func getVerdict(ctx context.Context, tracer debugtracer.DebugTracer, client *api.Client,
	ops triage.TreeOps) (*api.TriageResult, error) {
	series, err := client.GetSessionSeries(ctx, *flagSession)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query series: %w", err)
	}
	trees, err := client.GetTrees(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query trees: %w", err)
	}
	tree := triage.SelectTree(series, trees.Trees)
	if tree == nil {
		return &api.TriageResult{
			SkipReason: "no suitable base kernel tree found",
		}, nil
	}
	tracer.Log("selected tree %q", tree.Name)
	arch := "amd64"
	lastBuild, err := client.LastBuild(ctx, &api.LastBuildReq{
		Arch:       arch,
		ConfigName: tree.KernelConfig,
		TreeName:   tree.Name,
		Status:     api.BuildSuccess,
	})
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query the last build: %w", err)
	}
	tracer.Log("last build: %q", lastBuild)
	selector := triage.NewCommitSelector(ops, tracer)
	result, err := selector.Select(series, tree, lastBuild)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to run the commit selector: %w", err)
	} else if result.Commit == "" {
		return &api.TriageResult{
			SkipReason: "failed to find the base commit: " + result.Reason,
		}, nil
	}
	tracer.Log("selected base commit: %s", result.Commit)
	base := api.BuildRequest{
		TreeName:   tree.Name,
		TreeURL:    tree.URL,
		ConfigName: tree.KernelConfig,
		CommitHash: result.Commit,
		Arch:       arch,
	}
	ret := &api.TriageResult{
		Fuzz: &api.FuzzConfig{
			Base:      base,
			Patched:   base,
			Config:    tree.FuzzConfig,
			CorpusURL: tree.CorpusURL(),
		},
	}
	ret.Fuzz.Patched.SeriesID = series.ID
	return ret, nil
}
