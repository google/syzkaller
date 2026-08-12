// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/prog"
	"google.golang.org/api/option"
)

const (
	compilerClang = "clang"
)

var (
	flagRepo        = flag.String("repo", "", "kernel git repository URL")
	flagBranch      = flag.String("branch", "", "branch to checkout")
	flagCommit      = flag.String("commit", "", "commit hash to checkout")
	flagConfig      = flag.String("config", "", "path to kernel config file")
	flagCompiler    = flag.String("compiler", compilerClang, "compiler to build kernel with (clang or gcc)")
	flagBucket      = flag.String("gcs-bucket", "syzkaller-builds", "GCS bucket name")
	flagGcsEndpoint = flag.String("gcs-endpoint", "", "GCS endpoint (for emulator)")
	flagDashAddr    = flag.String("dashboard-addr", "", "dashboard address")
	flagDashClient  = flag.String("dashboard-client", "local_ui_client", "dashboard client name")
	flagDashKey     = flag.String("dashboard-key", "localuipasswordlocaluipasswordlocaluipassword", "dashboard client key")
	flagManagerName = flag.String("manager-name", "syz-k8s-manager", "manager name to register build for")
	flagTag         = flag.String("tag", "", "custom build ID tag (defaults to commit hash)")
)

func main() {
	flag.Parse()

	if *flagRepo == "" {
		log.Fatal("-repo is required")
	}
	if *flagConfig == "" {
		log.Fatal("-config is required")
	}

	ctx := context.Background()
	gcsClient, err := createGCSClient(ctx, *flagGcsEndpoint)
	if err != nil {
		log.Fatalf("failed to create GCS client: %v", err)
	}
	defer gcsClient.Close()

	tmpDir := "/tmp/kernel-build"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kernelDir := filepath.Join(tmpDir, "kernel")
	cloneAndCheckoutKernel(kernelDir)
	applyKernelConfig(kernelDir)
	buildKernel(kernelDir)
	copyArtifactsToLocalAssets(kernelDir)
	uploadArtifactsToGCS(ctx, gcsClient, kernelDir)
	uploadBuildToDashboard(kernelDir)

	log.Println("build and upload complete!")
}

func copyArtifactsToLocalAssets(kernelDir string) {
	assetsDir := "/syzkaller/assets"
	if _, err := os.Stat(assetsDir); os.IsNotExist(err) {
		assetsDir = "assets"
	}
	_ = os.MkdirAll(assetsDir, 0755)

	bzImageSrc := filepath.Join(kernelDir, "arch/x86/boot/bzImage")
	vmlinuxSrc := filepath.Join(kernelDir, "vmlinux")
	configSrc := filepath.Join(kernelDir, ".config")

	if *flagTag != "" {
		tagDir := filepath.Join(assetsDir, *flagTag)
		_ = os.MkdirAll(tagDir, 0755)
		_ = copyLocalFile(bzImageSrc, filepath.Join(tagDir, "bzImage"))
		_ = copyLocalFile(vmlinuxSrc, filepath.Join(tagDir, "vmlinux"))
		_ = copyLocalFile(configSrc, filepath.Join(tagDir, ".config"))
	}
	_ = copyLocalFile(bzImageSrc, filepath.Join(assetsDir, "bzImage"))
	_ = copyLocalFile(vmlinuxSrc, filepath.Join(assetsDir, "vmlinux"))
}

func copyLocalFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func createGCSClient(ctx context.Context, endpoint string) (*storage.Client, error) {
	var clientOpts []option.ClientOption
	if endpoint != "" {
		clientOpts = append(clientOpts, option.WithEndpoint(endpoint), option.WithoutAuthentication())
		os.Setenv("STORAGE_EMULATOR_HOST", endpoint)
	}
	return storage.NewClient(ctx, clientOpts...)
}

func cloneAndCheckoutKernel(kernelDir string) {
	log.Printf("cloning %s into %s...", *flagRepo, kernelDir)
	var cloneArgs []string
	if *flagCommit == "" && *flagBranch != "" {
		cloneArgs = []string{"clone", "--depth", "1", "-b", *flagBranch, *flagRepo, kernelDir}
	} else if *flagCommit == "" {
		cloneArgs = []string{"clone", "--depth", "1", *flagRepo, kernelDir}
	} else {
		cloneArgs = []string{"clone", *flagRepo, kernelDir}
	}
	if err := runCmd("git", cloneArgs...); err != nil {
		log.Fatalf("git clone failed: %v", err)
	}

	if *flagCommit != "" {
		log.Printf("checking out commit %s...", *flagCommit)
		if err := runCmdInDir(kernelDir, "git", "checkout", *flagCommit); err != nil {
			log.Fatalf("git checkout commit failed: %v", err)
		}
	} else if *flagBranch != "" {
		log.Printf("checking out branch %s...", *flagBranch)
		if err := runCmdInDir(kernelDir, "git", "checkout", *flagBranch); err != nil {
			log.Fatalf("git checkout branch failed: %v", err)
		}
	}
}

func applyKernelConfig(kernelDir string) {
	makeArgs := []string{"olddefconfig"}
	if *flagCompiler == compilerClang {
		makeArgs = []string{"CC=clang", "olddefconfig"}
	}

	if *flagConfig == "tinyconfig" || *flagConfig == "defconfig" {
		log.Printf("running make %s...", *flagConfig)
		args := []string{*flagConfig}
		if *flagCompiler == compilerClang {
			args = []string{"CC=clang", *flagConfig}
		}
		if err := runCmdInDir(kernelDir, "make", args...); err != nil {
			log.Fatalf("make %s failed: %v", *flagConfig, err)
		}
		return
	}

	log.Printf("applying config from %s...", *flagConfig)
	configContent, err := os.ReadFile(*flagConfig)
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kernelDir, ".config"), configContent, 0644); err != nil {
		log.Fatalf("failed to write .config: %v", err)
	}

	log.Printf("running make %s...", strings.Join(makeArgs, " "))
	if err := runCmdInDir(kernelDir, "make", makeArgs...); err != nil {
		log.Fatalf("make olddefconfig failed: %v", err)
	}
}

func buildKernel(kernelDir string) {
	log.Printf("building kernel (bzImage) with %s...", *flagCompiler)
	makeArgs := []string{"-j", "8", "bzImage"}
	if *flagCompiler == compilerClang {
		makeArgs = []string{"CC=clang", "-j", "8", "bzImage"}
	}
	if err := runCmdInDir(kernelDir, "make", makeArgs...); err != nil {
		log.Fatalf("make bzImage failed: %v", err)
	}
}

func uploadArtifactsToGCS(ctx context.Context, client *storage.Client, kernelDir string) {
	artifacts := []string{
		"vmlinux",
		"arch/x86/boot/bzImage",
	}

	for _, art := range artifacts {
		localPath := filepath.Join(kernelDir, art)
		objectName := filepath.Base(art)
		if *flagCommit != "" {
			objectName = fmt.Sprintf("builds/%s/%s", *flagCommit, objectName)
		} else {
			objectName = fmt.Sprintf("builds/latest/%s", objectName)
		}

		log.Printf("uploading %s to gs://%s/%s...", localPath, *flagBucket, objectName)
		if err := uploadFile(ctx, client, *flagBucket, objectName, localPath); err != nil {
			log.Fatalf("failed to upload %s: %v", art, err)
		}
	}
}

func uploadBuildToDashboard(kernelDir string) {
	if *flagDashAddr == "" {
		return
	}

	log.Printf("uploading build metadata to dashboard at %s...", *flagDashAddr)
	dash, err := dashapi.New(*flagDashClient, *flagDashAddr, *flagDashKey)
	if err != nil {
		log.Fatalf("failed to connect to dashapi: %v", err)
	}

	commitHash, err := runCmdOutInDir(kernelDir, "git", "rev-parse", "HEAD")
	if err != nil {
		log.Fatalf("failed to get commit hash: %v", err)
	}
	commitTitle, err := runCmdOutInDir(kernelDir, "git", "log", "-1", "--format=%s")
	if err != nil {
		log.Fatalf("failed to get commit title: %v", err)
	}
	commitDateStr, err := runCmdOutInDir(kernelDir, "git", "log", "-1", "--format=%cI")
	if err != nil {
		log.Fatalf("failed to get commit date: %v", err)
	}
	commitDate, err := time.Parse(time.RFC3339, strings.TrimSpace(commitDateStr))
	if err != nil {
		commitDate = time.Now()
	}

	var compilerOut []byte
	if *flagCompiler == compilerClang {
		compilerOut, _ = exec.Command("clang", "--version").Output()
	} else {
		compilerOut, _ = exec.Command("gcc", "--version").Output()
	}
	compilerID, _, _ := strings.Cut(string(compilerOut), "\n")
	if compilerID == "" {
		compilerID = *flagCompiler
	}

	kernelConfig, err := os.ReadFile(filepath.Join(kernelDir, ".config"))
	if err != nil {
		log.Fatalf("failed to read generated .config: %v", err)
	}

	buildID := *flagTag
	if buildID == "" {
		buildID = strings.TrimSpace(commitHash)
	}

	build := &dashapi.Build{
		Manager:             *flagManagerName,
		ID:                  buildID,
		OS:                  "linux",
		Arch:                "amd64",
		VMArch:              "amd64",
		SyzkallerCommit:     prog.GitRevision,
		SyzkallerCommitDate: time.Now(),
		CompilerID:          compilerID,
		KernelRepo:          *flagRepo,
		KernelBranch:        *flagBranch,
		KernelCommit:        strings.TrimSpace(commitHash),
		KernelCommitTitle:   strings.TrimSpace(commitTitle),
		KernelCommitDate:    commitDate,
		KernelConfig:        kernelConfig,
	}

	if err := dash.UploadBuild(build); err != nil {
		log.Fatalf("failed to upload build to dashboard: %v", err)
	}
	log.Printf("build %s registered with dashboard successfully!", buildID)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCmdInDir(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCmdOutInDir(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

func uploadFile(ctx context.Context, client *storage.Client, bucket, object, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	wc := client.Bucket(bucket).Object(object).NewWriter(ctx)
	if _, err = io.Copy(wc, f); err != nil {
		return err
	}
	return wc.Close()
}
