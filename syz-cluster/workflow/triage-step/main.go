// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"

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
	verdict, err := getVerdict(ctx, client, repo)
	if err != nil {
		app.Fatalf("failed to get the verdict: %v", err)
	}
	if verdict.Skip != nil {
		err := client.SkipSession(context.Background(), *flagSession, verdict.Skip)
		if err != nil {
			app.Fatalf("failed to upload the skip reason: %v", err)
		}
	}
	if *flagVerdict != "" {
		osutil.WriteJSON(*flagVerdict, verdict)
	}

	// TODO:
	// 1. It might be that the kernel builds/boots for one arch and does not build for another.
	// 2. What if controller does not reply? Let Argo just restart the step.
}

func getVerdict(ctx context.Context, client *api.Client, ops triage.TreeOps) (*api.TriageResult, error) {
	series, err := client.GetSessionSeries(ctx, *flagSession)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query series: %w", err)
	}
	tree := triage.SelectTree(series, client.GetTrees())
	if tree == nil {
		return &api.TriageResult{
			Skip: &api.SkipRequest{
				Reason: "no suitable kernel tree found",
			},
		}, nil
	}
	arch := "amd64"
	lastBuild, err := client.LastSuccessfulBuild(ctx, &api.LastBuildReq{
		Arch:       arch,
		ConfigName: tree.ConfigName,
		TreeName:   tree.Name,
	})
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query the last build: %w", err)
	}
	selector := triage.NewCommitSelector(ops)
	commits, err := selector.Select(series, tree, lastBuild)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to run the commit selector: %w", err)
	}
	if len(commits) == 0 {
		return &api.TriageResult{
			Skip: &api.SkipRequest{
				Reason: "no suitable commits found",
			},
		}, nil
	}
	ret := &api.TriageResult{}
	for _, commit := range commits {
		base := api.BuildRequest{
			TreeName:   tree.Name,
			ConfigName: tree.ConfigName,
			CommitHash: commit,
			Arch:       arch,
		}
		patched := base
		patched.SeriesID = series.ID
		ret.Fuzz = append(ret.Fuzz, &api.FuzzConfig{
			Base:    base,
			Patched: patched,
			Config:  "all",
		})
	}
	return ret, nil
}
