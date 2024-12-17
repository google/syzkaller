// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
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
)

func main() {
	flag.Parse()
	if *flagRequest == "" || *flagRepository == "" || *flagOutput == "" {
		// TODO: abort the whole workflow, no sense to retry. Alert the error.
		app.Fatalf("--series, --repository and --output must be set")
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
			TreeName:   req.TreeName,
			CommitHash: req.CommitHash,
			SeriesID:   req.SeriesID,
		},
	}
	commit, err := checkoutKernel(req, series)
	if commit != nil {
		uploadReq.CommitDate = commit.CommitDate
	}
	if err != nil {
		log.Printf("failed to checkout: %v", err)
		uploadReq.Log = []byte(err.Error())
	} else {
		err := buildKernel(req)
		if err == nil {
			uploadReq.BuildSuccess = true
		} else {
			log.Printf("failed to build: %v", err)
			uploadReq.Log = []byte(err.Error())
		}
	}
	buildInfo, err := client.UploadBuild(ctx, uploadReq)
	if err != nil {
		app.Fatalf("failed to upload build: %v", err)
	}
	log.Printf("uploaded build, reply: %q", buildInfo)
	osutil.WriteJSON(filepath.Join(*flagOutput, "result.json"), &api.BuildResult{
		BuildID: buildInfo.ID,
		Success: uploadReq.BuildSuccess,
	})
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

func checkoutKernel(req *api.BuildRequest, series *api.Series) (*vcs.Commit, error) {
	log.Printf("checking out %q", req.CommitHash)
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
		patches = series.Patches
	}
	if len(patches) > 0 {
		log.Printf("applying %d patches", len(patches))
	}
	err = ops.ApplySeries(req.CommitHash, patches)
	return commit, err
}

func buildKernel(req *api.BuildRequest) error {
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
		Tracer: &debugtracer.GenericTracer{
			TraceWriter: os.Stdout,
			OutDir:      "",
		},
	}
	log.Printf("started build: %q", req)
	info, err := build.Image(params)
	log.Printf("compiler: %q", info.CompilerID)
	if err != nil {
		var kernelError *build.KernelError
		var verboseError *osutil.VerboseError
		switch {
		case errors.As(err, &kernelError):
			log.Printf("kernel error: %q / %s", kernelError.Report, kernelError.Output)
		case errors.As(err, &verboseError):
			log.Printf("verbose error: %q / %s", verboseError.Title, verboseError.Output)
		default:
			log.Printf("other error: %v", err)
		}
		return err
	}
	log.Printf("build finished successfully")
	// TODO: capture build logs and the compiler identity.
	/*
	   Output directory has the form:
	   |-- image
	   |-- kernel
	   |-- kernel.config
	   `-- obj
	      `-- vmlinux
	*/
	return nil
}
