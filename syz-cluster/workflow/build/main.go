// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/build"
	"github.com/google/syzkaller/syz-cluster/pkg/workspace"
)

var (
	flagRequest    = flag.String("request", "", "path to a build request description")
	flagRepository = flag.String("repository", "", "path to a kernel checkout")
	flagOutput     = flag.String("output", "", "path to save kernel build artifacts")
	flagTestName   = flag.String("test_name", "", "test name")
	flagSession    = flag.String("session", "", "session ID")
	flagFindings   = flag.Bool("findings", false, "report build failures as findings")
)

func main() {
	flag.Parse()
	ensureFlags(
		*flagRequest, "--request",
		*flagRepository, "--repository",
		*flagOutput, "--output",
		*flagTestName, "--test_name",
		*flagSession, "--session",
	)

	req := readRequest()
	ctx := context.Background()
	client := app.DefaultClient()
	// TODO: (optimization) query whether the same BuildRequest has already been completed.
	var patches [][]byte
	if req.SeriesID != "" {
		series, err := client.GetSeries(ctx, req.SeriesID)
		if err != nil {
			app.Fatalf("failed to query the series info: %v", err)
		}
		patches = append(patches, series.PatchBodies()...)
	}
	if req.JobID != "" {
		job, err := client.GetJob(ctx, req.JobID)
		if err != nil {
			app.Fatalf("failed to query the job info: %v", err)
		}
		if len(job.Patch) > 0 {
			patches = append(patches, job.Patch)
		}
	}
	uploadReq := &api.UploadBuildReq{
		Build: api.Build{
			Arch:       req.Arch,
			ConfigName: req.ConfigName,
			TreeName:   req.TreeName,
			TreeURL:    req.TreeURL,
			SeriesID:   req.SeriesID,
			JobID:      req.JobID,
		},
	}
	output := new(bytes.Buffer)
	tracer := &debugtracer.GenericTracer{
		WithTime:    false,
		TraceWriter: output,
		OutDir:      "",
	}
	ws, err := workspace.New(*flagRepository, tracer)
	if err != nil {
		log.Printf("failed to initialize workspace: %v", err)
		reportResults(ctx, client, nil, nil, []byte(err.Error()))
		return
	}
	commit, err := ws.Checkout(req.TreeName, req.CommitHash, patches)
	if commit != nil {
		uploadReq.CommitHash = commit.Hash
		uploadReq.CommitDate = commit.CommitDate
	}
	if err != nil {
		log.Printf("failed to checkout: %v", err)
		reportResults(ctx, client, nil, nil, []byte(err.Error()))
		return
	}
	ret, err := build.Run(&build.Params{
		Req:       req,
		KernelDir: *flagRepository,
		OutputDir: *flagOutput,
		Tracer:    tracer,
	})
	if err != nil {
		log.Printf("build process failed: %v", err)
		reportResults(ctx, client, nil, nil, []byte(err.Error()))
		return
	}
	uploadReq.Compiler = ret.Compiler
	uploadReq.Config = ret.Config
	var finding *api.RawFinding
	if ret.Success {
		uploadReq.BuildSuccess = true
	} else {
		finding = &api.RawFinding{
			SessionID: *flagSession,
			TestName:  *flagTestName,
			Title:     "kernel build error",
			Report:    ret.Report,
			Log:       ret.Log,
		}
		log.Printf("%s", output.Bytes())
		log.Printf("failed: %s\n%s", finding.Title, finding.Report)
		uploadReq.Log = ret.Log
	}
	reportResults(ctx, client, uploadReq, finding, output.Bytes())
}

func reportResults(ctx context.Context, client *api.Client,
	uploadReq *api.UploadBuildReq, finding *api.RawFinding, output []byte) {
	var buildID string
	status := api.TestPassed
	if uploadReq != nil {
		if !uploadReq.BuildSuccess {
			status = api.TestFailed
		}
		buildInfo, err := client.UploadBuild(ctx, uploadReq)
		if err != nil {
			app.Fatalf("failed to upload build: %v", err)
		}
		log.Printf("uploaded build, reply: %q", buildInfo)
		buildID = buildInfo.ID
	} else {
		status = api.TestError
	}
	osutil.WriteJSON(filepath.Join(*flagOutput, "result.json"), &api.BuildResult{
		BuildID: buildID,
		Success: status == api.TestPassed,
	})
	testResult := &api.SessionTest{
		SessionID: *flagSession,
		TestName:  *flagTestName,
		Result:    status,
		Log:       output,
	}
	if uploadReq != nil {
		if uploadReq.SeriesID != "" {
			testResult.PatchedBuildID = buildID
		} else {
			testResult.BaseBuildID = buildID
		}
	}
	err := client.UploadSessionTest(ctx, testResult)
	if err != nil {
		app.Fatalf("failed to report the test result: %v", err)
	}
	if *flagFindings && finding != nil {
		err = client.UploadFinding(ctx, finding)
		if err != nil {
			app.Fatalf("failed to report the finding: %v", err)
		}
	}
}

func readRequest() *api.BuildRequest {
	raw, err := os.ReadFile(*flagRequest)
	if err != nil {
		app.Fatalf("failed to read request: %v", err)
		return nil
	}
	var req api.BuildRequest
	err = json.Unmarshal(raw, &req)
	if err != nil {
		app.Fatalf("failed to unmarshal request: %v, %s", err, raw)
		return nil
	}
	return &req
}

func ensureFlags(args ...string) {
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] == "" {
			app.Fatalf("%s must be set", args[i+1])
		}
	}
}
