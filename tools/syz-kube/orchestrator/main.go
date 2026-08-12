// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	defaultConfigPath   = "/syzkaller/dashboard/config/linux/upstream-apparmor-kasan.config"
	defaultGCSEndpoint  = "http://fake-gcs-server.syzkube.svc.cluster.local:4443"
	defaultBisectConfig = "/config/tools/syz-kube/bisect_config.json"
	defaultDashboard    = "http://syz-dashboard.syzkube.svc.cluster.local:8080"
	defaultClient       = "local_ui_client"
	defaultKey          = "localuipasswordlocaluipasswordlocaluipassword"
	defaultManagerName  = "syz-k8s-manager"
)

func main() {
	var (
		flagKubeconfig = flag.String("kubeconfig", "", "path to kubeconfig file (optional)")
		flagNamespace  = flag.String("namespace", "syzkube", "target kubernetes namespace")
		flagAction     = flag.String("action", "list", "action: build, bisect, fuzz-loop, list, delete")

		// Fuzz loop flags.
		flagMatrix       = flag.String("matrix", "/syzkaller/tools/syz-matrix/matrix.yaml", "path to matrix.yaml")
		flagPlatform     = flag.String("platform", "qemu_x86_64", "platform filter prefix (e.g. qemu_x86_64, gce)")
		flagCompiler     = flag.String("compiler", "clang", "compiler filter (e.g. clang, gcc)")
		flagFuzzDuration = flag.Duration("fuzz-duration", 1*time.Hour, "fuzzing duration per config")

		// Build flags.
		flagRepo            = flag.String("repo", "https://github.com/torvalds/linux.git", "kernel repository URL")
		flagBranch          = flag.String("branch", "master", "kernel branch")
		flagCommit          = flag.String("commit", "", "kernel commit hash")
		flagConfig          = flag.String("config", defaultConfigPath, "kernel config path")
		flagGCSBucket       = flag.String("gcs-bucket", "syzkaller-builds", "GCS bucket for build artifacts")
		flagGCSEndpoint     = flag.String("gcs-endpoint", defaultGCSEndpoint, "GCS API endpoint")
		flagDashboardAddr   = flag.String("dashboard-addr", defaultDashboard, "dashboard HTTP address")
		flagDashboardClient = flag.String("dashboard-client", defaultClient, "dashboard client name")
		flagDashboardKey    = flag.String("dashboard-key", defaultKey, "dashboard client key")
		flagManagerName     = flag.String("manager-name", defaultManagerName, "syz-manager name")
		flagTag             = flag.String("tag", "", "kernel build tag")

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
	case "fuzz-loop":
		err := orch.RunFuzzLoop(ctx, LoopConfig{
			MatrixPath:      *flagMatrix,
			PlatformPrefix:  *flagPlatform,
			Compiler:        *flagCompiler,
			FuzzDuration:    *flagFuzzDuration,
			Repo:            *flagRepo,
			Branch:          *flagBranch,
			Commit:          *flagCommit,
			GCSBucket:       *flagGCSBucket,
			GCSEndpoint:     *flagGCSEndpoint,
			DashboardAddr:   *flagDashboardAddr,
			DashboardClient: *flagDashboardClient,
			DashboardKey:    *flagDashboardKey,
			ManagerName:     *flagManagerName,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "fuzz loop failed: %v\n", err)
			os.Exit(1)
		}

	case "build":
		job, err := orch.ScheduleBuildJob(ctx, BuildConfig{
			Repo:            *flagRepo,
			Branch:          *flagBranch,
			Commit:          *flagCommit,
			ConfigPath:      *flagConfig,
			GCSBucket:       *flagGCSBucket,
			GCSEndpoint:     *flagGCSEndpoint,
			DashboardAddr:   *flagDashboardAddr,
			DashboardClient: *flagDashboardClient,
			DashboardKey:    *flagDashboardKey,
			ManagerName:     *flagManagerName,
			Tag:             *flagTag,
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
		fmt.Fprintf(os.Stderr, "unknown action: %s\n", *flagAction)
		os.Exit(1)
	}
}
