// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"log"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

var (
	flagSession      = flag.String("session", "", "session ID")
	flagTest         = flag.String("test", "", "test name")
	flagBaseBuild    = flag.String("base-build", "", "base build ID")
	flagPatchedBuild = flag.String("patched-build", "", "patched build ID")
	flagResult       = flag.String("result", "", "passed/failed/error")
)

func main() {
	flag.Parse()
	client := app.DefaultClient()
	result := &api.TestResult{
		SessionID:      *flagSession,
		BaseBuildID:    *flagBaseBuild,
		PatchedBuildID: *flagPatchedBuild,
		TestName:       *flagTest,
		Result:         *flagResult,
	}
	log.Printf("submitting %q", result)
	err := client.UploadTestResult(context.Background(), result)
	if err != nil {
		app.Fatalf("request failed: %v", err)
	}
}
