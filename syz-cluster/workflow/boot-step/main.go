// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzzconfig"
)

var (
	flagConfig       = flag.String("config", "", "syzkaller config")
	flagSession      = flag.String("session", "", "session ID")
	flagTestName     = flag.String("test_name", "", "test name")
	flagBaseBuild    = flag.String("base_build", "", "base build ID")
	flagPatchedBuild = flag.String("patched_build", "", "patched build ID")
	flagOutput       = flag.String("output", "", "where to store the result")
	flagFindings     = flag.Bool("findings", false, "report failur as findings")
)

func main() {
	flag.Parse()
	if *flagConfig == "" || *flagSession == "" || *flagTestName == "" {
		app.Fatalf("--config, --session and --test_name must be set")
	}

	ctx := context.Background()
	client := app.DefaultClient()

	testResult := &api.TestResult{
		SessionID:      *flagSession,
		TestName:       *flagTestName,
		BaseBuildID:    *flagBaseBuild,
		PatchedBuildID: *flagPatchedBuild,
		Result:         api.TestRunning,
	}
	// Report that we've begun the test -- it will let us report the findings.
	err := client.UploadTestResult(ctx, testResult)
	if err != nil {
		app.Fatalf("failed to upload test result: %v", err)
	}

	bootedFine, err := runTest(ctx, client)
	if err != nil {
		app.Fatalf("failed to run the boot test: %v", err)
	}
	if bootedFine {
		testResult.Result = api.TestPassed
	} else {
		testResult.Result = api.TestFailed
	}

	// Report the test results.
	err = client.UploadTestResult(ctx, testResult)
	if err != nil {
		app.Fatalf("failed to upload test result: %v", err)
	}
	if *flagOutput != "" {
		osutil.WriteJSON(*flagOutput, &api.BootResult{
			Success: bootedFine,
		})
	}
}

// To prevent false positive results, demand that in order to be marked as FAILED,
// the test must fail 3 times in a row.
const retryCount = 3

// The base config may have more VMs, but we don't need that many.
const vmCount = 3

func runTest(ctx context.Context, client *api.Client) (bool, error) {
	cfg, err := fuzzconfig.GenerateBase(&api.FuzzConfig{})
	if err != nil {
		return false, err
	}
	if err := instance.OverrideVMCount(cfg, vmCount); err != nil {
		return false, err
	}
	cfg.Workdir = "/tmp/test-workdir"
	if err := mgrconfig.Complete(cfg); err != nil {
		return false, fmt.Errorf("failed to complete the config: %w", err)
	}

	var rep *report.Report
	for i := 0; i < retryCount; i++ {
		log.Printf("starting attempt #%d", i)
		var err error
		rep, err = instance.RunSmokeTest(cfg)
		if err != nil {
			return false, err
		} else if rep == nil {
			return true, nil
		}
		log.Printf("attempt failed: %q", rep.Title)
	}
	if *flagFindings {
		log.Printf("reporting the finding")
		findingErr := client.UploadFinding(ctx, &api.NewFinding{
			SessionID: *flagSession,
			TestName:  *flagTestName,
			Title:     rep.Title,
			Report:    rep.Report,
			Log:       rep.Output,
		})
		if findingErr != nil {
			return false, fmt.Errorf("failed to report the finding: %w", findingErr)
		}
	} else {
		log.Printf("report:\n%s", rep.Report)
		log.Printf("output:\n%s", rep.Output)
	}
	return false, nil
}
