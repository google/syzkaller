// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	batch "cloud.google.com/go/batch/apiv1"
	"cloud.google.com/go/batch/apiv1/batchpb"
	_ "cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/protobuf/types/known/durationpb"
)

func initCoverageBatches() {
	http.HandleFunc("/cron/batch_coverage", handleBatchCoverage)
	// TODO: delme
	http.HandleFunc("/test_batch_coverage", handleBatchCoverage)
}

const (
	daysPerBatch        = 5
	daysToMerge         = 7
	batchTimeoutSeconds = 60*60*6 - 5 // 6 hours minus 5 minutes to not enter hour 7
)

func handleBatchCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	beforeYesterday := civil.DateOf(time.Now().Add(-1 * 48 * time.Hour))
	for ns, nsConfig := range getConfig(ctx).Namespaces {
		if nsConfig.Coverage == nil {
			continue
		}
		repo, branch := nsConfig.mainRepoBranch()
		if repo == "" || branch == "" {
			log.Errorf(ctx, "can't find default repo or branch for ns %s", ns)
		} else {
			if err := createScriptJob(
				ctx,
				nsConfig.Coverage.BatchProject,
				nsConfig.Coverage.BatchServiceAccount,
				mergerScript(ns, repo, branch, 7, beforeYesterday)); err != nil {
				log.Errorf(ctx, "failed to batchScript(): %s", err.Error())
			}
		}
	}
}

func mergerScript(ns, repo, branch string, days int, dateFor civil.Date) string {
	return "git clone https://github.com/google/syzkaller\n" +
		"cd syzkaller\n" +
		"export CI=1\n" +
		"./tools/syz-env ./tools/syz-bq.sh -w ../workdir-cover-aggregation/" +
		" -n " + ns +
		" -r " + repo +
		" -b " + branch +
		" -d " + strconv.Itoa(days) +
		" -t " + dateFor.String() +
		" 2>&1" // we don't want stderr output to be logged as errors
}

// from https://cloud.google.com/batch/docs/samples/batch-create-script-job
func createScriptJob(ctx context.Context, projectID, serviceAccount, script string) error {
	region := "us-central1"
	jobName := fmt.Sprintf("coverage-merge-%s", uuid.New().String())

	batchClient, err := batch.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed NewClient: %w", err)
	}
	defer batchClient.Close()

	taskGroups := []*batchpb.TaskGroup{
		{
			TaskSpec: &batchpb.TaskSpec{
				Runnables: []*batchpb.Runnable{{
					Executable: &batchpb.Runnable_Script_{
						Script: &batchpb.Runnable_Script{Command: &batchpb.Runnable_Script_Text{
							Text: script,
						}},
					},
				}},
				ComputeResource: &batchpb.ComputeResource{
					// CpuMilli is milliseconds per cpu-second. This means the task requires 2 whole CPUs.
					CpuMilli:  4000,
					MemoryMib: 12 * 1024,
				},
				MaxRunDuration: &durationpb.Duration{
					Seconds: 60*60*6 - 5, // 6 hours minus 5 minutes to not enter hour 7
				},
			},
		},
	}

	// Policies are used to define on what kind of virtual machines the tasks will run on.
	// In this case, we tell the system to use "e2-standard-4" machine type.
	// Read more about machine types here: https://cloud.google.com/compute/docs/machine-types
	allocationPolicy := &batchpb.AllocationPolicy{
		Instances: []*batchpb.AllocationPolicy_InstancePolicyOrTemplate{{
			PolicyTemplate: &batchpb.AllocationPolicy_InstancePolicyOrTemplate_Policy{
				Policy: &batchpb.AllocationPolicy_InstancePolicy{
					MachineType: "c3-standard-4",
				},
			},
		}},
		ServiceAccount: &batchpb.ServiceAccount{
			Email: serviceAccount,
		},
	}

	logsPolicy := &batchpb.LogsPolicy{
		Destination: batchpb.LogsPolicy_CLOUD_LOGGING,
	}

	// The job's parent is the region in which the job will run.
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)

	job := batchpb.Job{
		TaskGroups:       taskGroups,
		AllocationPolicy: allocationPolicy,
		LogsPolicy:       logsPolicy,
	}

	req := &batchpb.CreateJobRequest{
		Parent: parent,
		JobId:  jobName,
		Job:    &job,
	}

	createdJob, err := batchClient.CreateJob(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to create job: %w", err)
	}

	log.Infof(ctx, "job created: %v\n", createdJob)

	return nil
}
