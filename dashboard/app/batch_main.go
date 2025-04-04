// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"

	"cloud.google.com/go/batch/apiv1"
	"cloud.google.com/go/batch/apiv1/batchpb"
	"github.com/google/uuid"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/protobuf/types/known/durationpb"
)

func initBatchProcessors() {
	http.HandleFunc("/cron/batch_coverage", handleBatchCoverage)
	http.HandleFunc("/cron/batch_db_export", handleBatchDBExport)
	http.HandleFunc("/cron/batch_coverage_clean", handleBatchCoverageClean)
}

// from https://cloud.google.com/batch/docs/samples/batch-create-script-job
func createScriptJob(ctx context.Context, projectID, jobNamePrefix, script string,
	timeout int64, sa *batchpb.ServiceAccount) error {
	region := "us-central1"
	jobName := fmt.Sprintf("%s-%s", jobNamePrefix, uuid.New().String())

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
					// CpuMilli is milliseconds per cpu-second. This means the task requires 8 whole CPUs.
					CpuMilli:  8000,
					MemoryMib: 30 * 1024,
				},
				MaxRunDuration: &durationpb.Duration{
					Seconds: timeout,
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
					// Spot machines may also be used here.
					// The problem with spot machines is the high probability of preemption on long runs.
					// Quarter long coverage merge costs 4 hours on 8 cores and we trigger it only once/week.
					// TODO(tarasmadan): switch back to the spot machines in combination with higher retry count
					ProvisioningModel: batchpb.AllocationPolicy_STANDARD,
					// Quarter long aggregation OOMs on machine with 16 gigs and 8 cores.
					// It is important to use machine with min 32 gigs for 8 cores.
					MachineType: "e2-standard-8",
				},
			},
			InstallOpsAgent: true,
		}},
		ServiceAccount: sa,
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
