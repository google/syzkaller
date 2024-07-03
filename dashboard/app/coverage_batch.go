// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"cloud.google.com/go/batch/apiv1"
	"cloud.google.com/go/batch/apiv1/batchpb"
	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/protobuf/types/known/durationpb"
)

func initCoverageBatches() {
	http.HandleFunc("/cron/batch_coverage", handleBatchCoverage)
}

const (
	daysPerBatch        = 5
	daysToMerge         = 7
	batchTimeoutSeconds = 60 * 60 * 6
)

func handleBatchCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	for ns, nsConfig := range getConfig(ctx).Namespaces {
		if nsConfig.Coverage == nil {
			continue
		}
		repo, branch := nsConfig.mainRepoBranch()
		if repo == "" || branch == "" {
			log.Errorf(ctx, "can't find default repo or branch for ns %s", ns)
			continue
		}
		dates, err := nsDatesToMerge(ctx, ns, daysToMerge, daysPerBatch)
		if err != nil {
			log.Errorf(ctx, "failed nsDatesToMerge(): %s", err)
			continue
		}
		if len(dates) == 0 {
			log.Infof(ctx, "there is no new coverage for merging available in %s", ns)
			continue
		}
		if err := createScriptJob(
			ctx,
			nsConfig.Coverage.BatchProject,
			nsConfig.Coverage.BatchServiceAccount,
			batchScript(ns, repo, branch, 7, dates)); err != nil {
			log.Errorf(ctx, "failed to batchScript(): %s", err.Error())
		}
	}
}

func batchScript(ns, repo, branch string, days int, datesTo []civil.Date) string {
	script := "git clone --depth 1 --branch master --single-branch https://github.com/google/syzkaller\n" +
		"cd syzkaller\n" +
		"export CI=1\n" +
		"./tools/syz-env \""
	for _, dateTo := range datesTo {
		script += "./tools/syz-bq.sh" +
			" -w ../workdir-cover-aggregation/" +
			" -n " + ns +
			" -r " + repo +
			" -b " + branch +
			" -d " + strconv.Itoa(days) +
			" -t " + dateTo.String() +
			" 2>&1; " // we don't want stderr output to be logged as errors
	}
	script += "\""
	return script
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
					Seconds: batchTimeoutSeconds,
				},
				MaxRetryCount: 2,
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
					ProvisioningModel: batchpb.AllocationPolicy_SPOT,
					MachineType:       "c3-standard-4",
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

func nsDatesToMerge(ctx context.Context, ns string, days, maxRecords int64) ([]civil.Date, error) {
	client, err := bigquery.NewClient(ctx, "syzkaller")
	client.EnableStorageReadClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bigquery client: %w", err)
	}
	q := client.Query(fmt.Sprintf(`
		WITH data AS (
		  SELECT
		    table_name as namespace,
		    PARSE_DATE('%%Y%%m%%d', partition_id) as partition_date,
		    total_rows
		  FROM
		    syzkaller.syzbot_coverage.INFORMATION_SCHEMA.PARTITIONS
			WHERE table_name LIKE '%s'
		)

		SELECT * from (
		  SELECT
		    mainquery.namespace as namespace,
		    partition_date as dateto,
		    sp.total_rows_dest,
		    (
		      select
		        sum(total_rows)
		      FROM
		        data as subquery
		      WHERE
		        subquery.partition_date
		          BETWEEN
		          DATE_SUB(mainquery.partition_date, INTERVAL %d DAY) AND
		          mainquery.partition_date AND
		        subquery.namespace = mainquery.namespace
		      ) as total_rows_src
		  FROM data as mainquery
			LEFT JOIN
				EXTERNAL_QUERY("syzkaller.us-central1.spanner-coverage", '''
					SELECT
						distinct namespace, duration, dateto, totalrows as total_rows_dest
					FROM
						merge_history
					WHERE
						duration = %d;''') AS sp
			ON
				mainquery.partition_date = sp.dateto AND
				mainquery.namespace = sp.namespace
			ORDER BY dateto DESC
		)
		WHERE
		  total_rows_dest IS NULL OR total_rows_dest != total_rows_src
		LIMIT %d
	`, ns, days, days, maxRecords))
	it, err := q.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to Read() from bigquery: %w", err)
	}

	var dates []civil.Date
	for {
		var values struct {
			Dateto civil.Date
		}
		err = it.Next(&values)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to it.Next() bigquery records: %w", err)
		}
		dates = append(dates, values.Dateto)
	}

	return dates, nil
}
