// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/triage"
)

var (
	flagRequest    = flag.String("request", "", "path to a build request description")
	flagRepository = flag.String("repository", "", "path to a kernel checkout")
	flagOutput     = flag.String("output", "", "path to save kernel build artifacts")
	flagTestName   = flag.String("test_name", "", "test name")
	flagSession    = flag.String("session", "", "session ID")
	flagFindings   = flag.Bool("findings", false, "report build failures as findings")
	flagSmokeBuild = flag.Bool("smoke_build", false, "build only if new, don't report findings")
)

func main() {
	flag.Parse()
	ensureFlags(*flagRequest, "--request",
		*flagRepository, "--repository",
		*flagOutput, "--output")
	if !*flagSmokeBuild {
		ensureFlags(
			*flagTestName, "--test_name",
			*flagSession, "--session",
		)
	}

	req := readRequest()
	ctx := context.Background()
	client := app.DefaultClient()
	// TODO: (optimization) query whether the same BuildRequest has already been completed.
	var series *api.Series
	if req.SeriesID != "" {
		var err error
		series, err = client.GetSeries(ctx, req.SeriesID)
		if err != nil {
			app.Fatalf("failed to query the series info: %v", err)
		}
	}
	uploadReq := &api.UploadBuildReq{
		Build: api.Build{
			Arch:       req.Arch,
			ConfigName: req.ConfigName,
			TreeName:   req.TreeName,
			SeriesID:   req.SeriesID,
		},
	}
	output := new(bytes.Buffer)
	tracer := &debugtracer.GenericTracer{
		WithTime:    false,
		TraceWriter: output,
		OutDir:      "",
	}
	commit, err := checkoutKernel(tracer, req, series)
	if commit != nil {
		uploadReq.CommitHash = commit.Hash
		uploadReq.CommitDate = commit.CommitDate
	}
	if *flagSmokeBuild {
		skip, err := alreadyBuilt(ctx, client, uploadReq)
		if err != nil {
			app.Fatalf("failed to query known builds: %v", err)
		} else if skip {
			log.Printf("%s already built, skipping", uploadReq.CommitHash)
			return
		}
	}
	var finding *api.NewFinding
	if err != nil {
		log.Printf("failed to checkout: %v", err)
		uploadReq.Log = []byte(err.Error())
	} else {
		err := buildKernel(tracer, req)
		if err == nil {
			uploadReq.BuildSuccess = true
		} else {
			log.Printf("%s", output.Bytes())
			log.Printf("failed to build: %v", err)
			uploadReq.Log = []byte(err.Error())
			finding = &api.NewFinding{
				SessionID: *flagSession,
				TestName:  *flagTestName,
				Title:     "failed to build the kernel",
				Log:       uploadReq.Log,
			}
		}
	}
	reportResults(ctx, client, req.SeriesID != "",
		uploadReq, finding, output.Bytes())
}

func reportResults(ctx context.Context, client *api.Client, patched bool,
	uploadReq *api.UploadBuildReq, finding *api.NewFinding, output []byte) {
	buildInfo, err := client.UploadBuild(ctx, uploadReq)
	if err != nil {
		app.Fatalf("failed to upload build: %v", err)
	}
	log.Printf("uploaded build, reply: %q", buildInfo)
	osutil.WriteJSON(filepath.Join(*flagOutput, "result.json"), &api.BuildResult{
		BuildID: buildInfo.ID,
		Success: uploadReq.BuildSuccess,
	})
	if *flagSmokeBuild {
		return
	}
	testResult := &api.TestResult{
		SessionID: *flagSession,
		TestName:  *flagTestName,
		Result:    api.TestFailed,
		Log:       output,
	}
	if uploadReq.BuildSuccess {
		testResult.Result = api.TestPassed
	}
	if patched {
		testResult.PatchedBuildID = buildInfo.ID
	} else {
		testResult.BaseBuildID = buildInfo.ID
	}
	err = client.UploadTestResult(ctx, testResult)
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

func alreadyBuilt(ctx context.Context, client *api.Client,
	req *api.UploadBuildReq) (bool, error) {
	build, err := client.LastBuild(ctx, &api.LastBuildReq{
		Arch:       req.Build.Arch,
		ConfigName: req.Build.ConfigName,
		TreeName:   req.Build.TreeName,
		Commit:     req.CommitHash,
	})
	if err != nil {
		return false, err
	}
	return build != nil, nil
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

func checkoutKernel(tracer debugtracer.DebugTracer, req *api.BuildRequest, series *api.Series) (*vcs.Commit, error) {
	tracer.Log("checking out %q", req.CommitHash)
	ops, err := triage.NewGitTreeOps(*flagRepository, true)
	if err != nil {
		return nil, err
	}
	commit, err := ops.Commit(req.CommitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit info: %w", err)
	}
	var patches [][]byte
	if series != nil {
		patches = series.PatchBodies()
	}
	if len(patches) > 0 {
		tracer.Log("applying %d patches", len(patches))
	}
	err = ops.ApplySeries(req.CommitHash, patches)
	return commit, err
}

func buildKernel(tracer debugtracer.DebugTracer, req *api.BuildRequest) error {
	kernelConfig, err := os.ReadFile(filepath.Join("/kernel-configs", req.ConfigName))
	if err != nil {
		return fmt.Errorf("failed to read the kernel config: %w", err)
	}
	if req.Arch != "amd64" {
		// TODO: lift this restriction.
		return fmt.Errorf("only amd64 builds are supported now")
	}
	params := build.Params{
		TargetOS:     targets.Linux,
		TargetArch:   req.Arch,
		VMType:       "qemu", // TODO: support others.
		KernelDir:    *flagRepository,
		OutputDir:    *flagOutput,
		Compiler:     "clang",
		Linker:       "ld.lld",
		UserspaceDir: "/disk-images/buildroot_amd64_2024.09", // See the Dockerfile.
		Config:       kernelConfig,
		Tracer:       tracer,
	}
	tracer.Log("started build: %q", req)
	info, err := build.Image(params)
	tracer.Log("compiler: %q", info.CompilerID)
	if err != nil {
		var kernelError *build.KernelError
		var verboseError *osutil.VerboseError
		switch {
		case errors.As(err, &kernelError):
			tracer.Log("kernel error: %q / %s", kernelError.Report, kernelError.Output)
		case errors.As(err, &verboseError):
			tracer.Log("verbose error: %q / %s", verboseError.Title, verboseError.Output)
		default:
			tracer.Log("other error: %v", err)
		}
		return err
	}
	tracer.Log("build finished successfully")
	// TODO: capture build logs and the compiler identity.
	// Note: Output directory has the following structure:
	//   |-- image
	//   |-- kernel
	//   |-- kernel.config
	//   `-- obj
	//      `-- vmlinux
	return nil
}

func ensureFlags(args ...string) {
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] == "" {
			app.Fatalf("%s must be set", args[i+1])
		}
	}
}
