// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzzconfig"
	"github.com/google/syzkaller/syz-cluster/pkg/retest"
)

var (
	flagRetestTask   = flag.String("retest_task", "", "retest task JSON file")
	flagBaseBuild    = flag.String("base_build", "", "base build ID")
	flagPatchedBuild = flag.String("patched_build", "", "patched build ID")
	flagSession      = flag.String("session", "", "session ID")
	flagWorkdir      = flag.String("workdir", "", "workdir")
	flagTestName     = flag.String("test_name", "", "test name")
)

const (
	// 50KB should be enough for the log.
	maxLogSize  = 50 << 10
	maxLogLines = 1000
)

func main() {
	flag.Parse()
	if *flagRetestTask == "" || *flagSession == "" || *flagWorkdir == "" || *flagTestName == "" {
		app.Fatalf("retest_task, session, test_name and workdir flags are required")
	}
	log.EnableLogCaching(maxLogLines, maxLogSize)
	ctx := context.Background()
	client := app.DefaultClient()

	reportStatus(ctx, client, api.TestRunning, nil)

	err := run(ctx, client)
	finalStatus := api.TestPassed
	if err != nil {
		finalStatus = api.TestError
		log.Logf(0, "retest failed: %v", err)
	}

	reportStatus(ctx, client, finalStatus, []byte(log.CachedLogOutput()))
}

func run(ctx context.Context, client *api.Client) error {
	retestTaskData, err := os.ReadFile(*flagRetestTask)
	if err != nil {
		return fmt.Errorf("failed to read retest task: %w", err)
	}

	var retestTask api.RetestTask
	if err := json.Unmarshal(retestTaskData, &retestTask); err != nil {
		return fmt.Errorf("failed to parse retest task: %w", err)
	}

	baseCfg, err := fuzzconfig.GenerateBase(&api.FuzzConfig{})
	if err != nil {
		return fmt.Errorf("failed to generate base config: %w", err)
	}
	patchedCfg, err := fuzzconfig.GeneratePatched(&api.FuzzConfig{})
	if err != nil {
		return fmt.Errorf("failed to generate patched config: %w", err)
	}

	if *flagWorkdir != "" {
		baseCfg.Workdir = *flagWorkdir + "/base"
		patchedCfg.Workdir = *flagWorkdir + "/patched"
	}

	if err := mgrconfig.Complete(baseCfg); err != nil {
		return fmt.Errorf("failed to complete base config: %w", err)
	}
	if err := mgrconfig.Complete(patchedCfg); err != nil {
		return fmt.Errorf("failed to complete patched config: %w", err)
	}

	// Retest runs sequentially, so we don't need semaphores for concurrent builds within this process.
	baseEnv, err := instance.NewEnv(baseCfg, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create base env: %w", err)
	}
	patchedEnv, err := instance.NewEnv(patchedCfg, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create patched env: %w", err)
	}

	runner := &retest.Runner{
		Client:    client,
		Base:      baseEnv,
		Patched:   patchedEnv,
		SessionID: *flagSession,
		TestName:  *flagTestName,
	}

	return runner.Run(ctx, &retestTask)
}

func reportStatus(ctx context.Context, client *api.Client, status string, logs []byte) {
	err := client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:      *flagSession,
		TestName:       *flagTestName,
		BaseBuildID:    *flagBaseBuild,
		PatchedBuildID: *flagPatchedBuild,
		Result:         status,
		Log:            logs,
	})
	if err != nil {
		app.Fatalf("failed to report status: %v", err)
	}
}
