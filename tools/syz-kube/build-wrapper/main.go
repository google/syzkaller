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

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

var (
	flagRepo        = flag.String("repo", "", "kernel git repository URL")
	flagBranch      = flag.String("branch", "", "branch to checkout")
	flagCommit      = flag.String("commit", "", "commit hash to checkout")
	flagConfig      = flag.String("config", "", "path to kernel config file")
	flagBucket      = flag.String("gcs-bucket", "syzkaller-builds", "GCS bucket name")
	flagGcsEndpoint = flag.String("gcs-endpoint", "", "GCS endpoint (for emulator)")
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

	// 1. Setup GCS client
	var clientOpts []option.ClientOption
	if *flagGcsEndpoint != "" {
		clientOpts = append(clientOpts, option.WithEndpoint(*flagGcsEndpoint), option.WithoutAuthentication())
		// For fake-gcs-server we might need this env var as well if using default client.
		os.Setenv("STORAGE_EMULATOR_HOST", *flagGcsEndpoint)
	}
	gcsClient, err := storage.NewClient(ctx, clientOpts...)
	if err != nil {
		log.Fatalf("failed to create GCS client: %v", err)
	}
	defer gcsClient.Close()

	// 2. Clone repo
	tmpDir := "/tmp/kernel-build"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kernelDir := filepath.Join(tmpDir, "kernel")
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

	// 3. Checkout commit/branch
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

	// 4. Apply config
	if *flagConfig == "tinyconfig" || *flagConfig == "defconfig" {
		log.Printf("running make %s...", *flagConfig)
		if err := runCmdInDir(kernelDir, "make", *flagConfig); err != nil {
			log.Fatalf("make %s failed: %v", *flagConfig, err)
		}
	} else {
		log.Printf("applying config from %s...", *flagConfig)
		configContent, err := os.ReadFile(*flagConfig)
		if err != nil {
			log.Fatalf("failed to read config file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(kernelDir, ".config"), configContent, 0644); err != nil {
			log.Fatalf("failed to write .config: %v", err)
		}

		log.Printf("running make olddefconfig...")
		if err := runCmdInDir(kernelDir, "make", "olddefconfig"); err != nil {
			log.Fatalf("make olddefconfig failed: %v", err)
		}
	}

	// 5. Build kernel
	// For now assume x86_64 and build bzImage + vmlinux
	log.Printf("building kernel (bzImage)...")
	if err := runCmdInDir(kernelDir, "make", "-j", "8", "bzImage"); err != nil {
		log.Fatalf("make bzImage failed: %v", err)
	}

	// 6. Upload artifacts
	artifacts := []string{
		"vmlinux",
		"arch/x86/boot/bzImage",
	}

	for _, art := range artifacts {
		localPath := filepath.Join(kernelDir, art)
		objectName := filepath.Base(art) // e.g. "vmlinux" or "bzImage"
		if *flagCommit != "" {
			objectName = fmt.Sprintf("builds/%s/%s", *flagCommit, objectName)
		} else {
			objectName = fmt.Sprintf("builds/latest/%s", objectName)
		}

		log.Printf("uploading %s to gs://%s/%s...", localPath, *flagBucket, objectName)
		if err := uploadFile(ctx, gcsClient, *flagBucket, objectName, localPath); err != nil {
			log.Fatalf("failed to upload %s: %v", art, err)
		}
	}

	log.Println("Build and upload complete!")
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
