// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
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

func runTest(ctx context.Context, client *api.Client) (bool, error) {
	cfg, err := mgrconfig.LoadFile(filepath.Join("/configs", *flagConfig, "base.cfg"))
	if err != nil {
		return false, err
	}
	cfg.Workdir = "/tmp/test-workdir"
	rep, err := instance.RunSmokeTest(cfg)
	if err != nil {
		return false, err
	} else if rep == nil {
		return true, nil
	}

	log.Printf("found: %q", rep.Title)
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
	}
	return false, nil
}
