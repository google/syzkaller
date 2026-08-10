// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

const (
	defaultConfigPath   = "/syzkaller/dashboard/config/linux/upstream-apparmor-kasan.config"
	defaultGCSEndpoint  = "http://fake-gcs-server.syzkube.svc.cluster.local:4443"
	defaultBisectConfig = "/config/tools/syz-kube/bisect_config.json"
)

func main() {
	var (
		flagKubeconfig = flag.String("kubeconfig", "", "path to kubeconfig file (optional)")
		flagNamespace  = flag.String("namespace", "syzkube", "target kubernetes namespace")
		flagAction     = flag.String("action", "list", "action to perform: build, bisect, list, delete")

		// Build flags.
		flagRepo        = flag.String("repo", "https://github.com/torvalds/linux.git", "kernel repository URL")
		flagBranch      = flag.String("branch", "master", "kernel branch")
		flagCommit      = flag.String("commit", "", "kernel commit hash")
		flagConfig      = flag.String("config", defaultConfigPath, "kernel config path")
		flagGCSBucket   = flag.String("gcs-bucket", "syzkaller-builds", "GCS bucket for build artifacts")
		flagGCSEndpoint = flag.String("gcs-endpoint", defaultGCSEndpoint, "GCS API endpoint")

		// Bisect flags.
		flagBisectConfig = flag.String("bisect-config", defaultBisectConfig, "path to bisection config JSON")
		flagCrashPath    = flag.String("crash", "/config/tools/syz-kube/test-crash", "path to crash directory")

		// Delete flags.
		flagJobName = flag.String("job", "", "name of the job to delete")
	)
	flag.Parse()

	ctx := context.Background()
	orch, err := NewOrchestrator(*flagKubeconfig, *flagNamespace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize orchestrator: %v\n", err)
		os.Exit(1)
	}

	switch *flagAction {
	case "build":
		job, err := orch.ScheduleBuildJob(ctx, BuildConfig{
			Repo:        *flagRepo,
			Branch:      *flagBranch,
			Commit:      *flagCommit,
			ConfigPath:  *flagConfig,
			GCSBucket:   *flagGCSBucket,
			GCSEndpoint: *flagGCSEndpoint,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to schedule build job: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("scheduled build job: %s\n", job.Name)

	case "bisect":
		job, err := orch.ScheduleBisectionJob(ctx, BisectConfig{
			ConfigPath: *flagBisectConfig,
			CrashPath:  *flagCrashPath,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to schedule bisection job: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("scheduled bisection job: %s\n", job.Name)

	case "list":
		jobs, err := orch.ListJobs(ctx, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to list jobs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("active / completed jobs in namespace %q (%d total):\n", *flagNamespace, len(jobs.Items))
		for _, j := range jobs.Items {
			status := "Running"
			if j.Status.Succeeded > 0 {
				status = "Succeeded"
			} else if j.Status.Failed > 0 {
				status = "Failed"
			}
			fmt.Printf("- %s (status: %s)\n", j.Name, status)
		}

	case "delete":
		if *flagJobName == "" {
			fmt.Fprintf(os.Stderr, "flag -job is required for delete action\n")
			os.Exit(1)
		}
		if err := orch.DeleteJob(ctx, *flagJobName); err != nil {
			fmt.Fprintf(os.Stderr, "failed to delete job %s: %v\n", *flagJobName, err)
			os.Exit(1)
		}
		fmt.Printf("deleted job: %s\n", *flagJobName)

	default:
		fmt.Fprintf(os.Stderr, "unknown action %q (supported: build, bisect, list, delete)\n", *flagAction)
		os.Exit(1)
	}
}
