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
	flagSeries  = flag.String("series", "", "series ID")
	flagRepo    = flag.String("repository", "", "path to a kernel checkout")
	flagVerdict = flag.String("verdict", "", "where to save the verdict")
)

func main() {
	flag.Parse()
	if *flagSeries == "" || *flagRepo == "" {
		// TODO: abort the whole workflow, no sense to retry. Alert the error.
		app.Fatalf("--series and --repo must be set")
	}
	client := app.DefaultClient()
	repo, err := triage.NewGitTreeOps(*flagRepo, true)
	if err != nil {
		app.Fatalf("failed to initialize the repository: %v", err)
	}
	verdict, err := getVerdict(*flagSeries, client, repo)
	if err != nil {
		app.Fatalf("failed to get the verdict: %v", err)
	}
	if *flagVerdict != "" {
		osutil.WriteJSON(*flagVerdict, verdict)
	}

	// TODO:
	// 1. It might be that the kernel builds/boots for one arch and does not build for another.
	// 2. What if controller does not reply? Let Argo just restart the step.
}

func getVerdict(seriesID string, client *api.Client, ops triage.TreeOps) (*api.TriageResult, error) {
	ctx := context.Background()
	series, err := client.GetSeries(ctx, *flagSeries)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query series: %v", err)
	}
	tree := triage.SelectTree(series, client.GetTrees())
	if tree == nil {
		return &api.TriageResult{
			Skip: true,
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
		return nil, fmt.Errorf("failed to query the last build: %v", err)
	}
	selector := triage.NewCommitSelector(ops)
	commits, err := selector.Select(series, tree, lastBuild)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to run the commit selector: %v", err)
	}
	if len(commits) == 0 {
		return &api.TriageResult{
			Skip: true,
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
		patched.SeriesID = seriesID
		ret.Fuzz = append(ret.Fuzz, &api.FuzzConfig{
			Base:    base,
			Patched: patched,
		})
	}
	return ret, nil
}
