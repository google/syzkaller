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
	"github.com/google/syzkaller/pkg/coveragedb"
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
	daysToMerge         = 7
	batchTimeoutSeconds = 60 * 60 * 6
)

func handleBatchCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	doQuarters := r.FormValue("quarters") == "true"
	doMonths := r.FormValue("months") == "true"
	doDays := r.FormValue("days") == "true"
	maxSteps, err := strconv.Atoi(r.FormValue("steps"))
	if err != nil {
		log.Errorf(ctx, "failed to convert &steps= into maxSteps: %s", err.Error())
		return
	}
	for ns, nsConfig := range getConfig(ctx).Namespaces {
		if nsConfig.Coverage == nil {
			continue
		}
		repo, branch := nsConfig.mainRepoBranch()
		if repo == "" || branch == "" {
			log.Errorf(ctx, "can't find default repo or branch for ns %s", ns)
			continue
		}
		daysAvailable, rowsAvailable, err := nsDataAvailable(ctx, ns)
		if err != nil {
			log.Errorf(ctx, "failed nsDataAvailable(%s): %s", ns, err)
		}
		periodsMerged, rowsMerged, err := coveragedb.NsDataMerged(ctx, "syzkaller", ns)
		if err != nil {
			log.Errorf(ctx, "failed coveragedb.NsDataMerged(%s): %s", ns, err)
		}
		var periods []coveragedb.TimePeriod
		if doDays {
			periods = append(periods, coveragedb.PeriodsToMerge(daysAvailable, periodsMerged, rowsAvailable, rowsMerged,
				&coveragedb.DayPeriodOps{})...)
		}
		if doMonths {
			periods = append(periods, coveragedb.PeriodsToMerge(daysAvailable, periodsMerged, rowsAvailable, rowsMerged,
				&coveragedb.MonthPeriodOps{})...)
		}
		if doQuarters {
			periods = append(periods, coveragedb.PeriodsToMerge(daysAvailable, periodsMerged, rowsAvailable, rowsMerged,
				&coveragedb.QuarterPeriodOps{})...)
		}
		if len(periods) == 0 {
			log.Infof(ctx, "there is no new coverage for merging available in %s", ns)
			continue
		}
		periods = coveragedb.AtMostNLatestPeriods(periods, maxSteps)
		nsCovConfig := nsConfig.Coverage
		if err := createScriptJob(
			ctx,
			nsCovConfig.BatchProject,
			nsCovConfig.BatchServiceAccount,
			batchScript(ns, repo, branch, periods,
				nsCovConfig.JobInitScript,
				nsCovConfig.SyzEnvInitScript,
				nsCovConfig.DashboardClientName),
			nsCovConfig.BatchScopes); err != nil {
			log.Errorf(ctx, "failed to batchScript: %s", err.Error())
		}
	}
}

func batchScript(ns, repo, branch string, periods []coveragedb.TimePeriod,
	jobInitScript, syzEnvInitScript, clientName string) string {
	if clientName == "" {
		clientName = defaultDashboardClientName
	}
	script := jobInitScript + "\n"
	script += "git clone --depth 1 --branch master --single-branch https://github.com/google/syzkaller\n" +
		"cd syzkaller\n" +
		"export CI=1\n" +
		"./tools/syz-env \""
	if syzEnvInitScript != "" {
		script += syzEnvInitScript + "; "
	}
	for _, period := range periods {
		script += "./tools/syz-bq.sh" +
			" -w ../workdir-cover-aggregation/" +
			" -n " + ns +
			" -r " + repo +
			" -b " + branch +
			" -d " + strconv.Itoa(period.Days) +
			" -t " + period.DateTo.String() +
			" -c " + clientName +
			" 2>&1; " // we don't want stderr output to be logged as errors
	}
	script += "\""
	return script
}

// from https://cloud.google.com/batch/docs/samples/batch-create-script-job
func createScriptJob(ctx context.Context, projectID, serviceAccount, script string, scopes []string) error {
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
			Email:  serviceAccount,
			Scopes: scopes,
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

func nsDataAvailable(ctx context.Context, ns string) ([]coveragedb.TimePeriod, []int64, error) {
	client, err := bigquery.NewClient(ctx, "syzkaller")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize bigquery client: %w", err)
	}
	if err := client.EnableStorageReadClient(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to client.EnableStorageReadClient: %w", err)
	}
	q := client.Query(fmt.Sprintf(`
	SELECT
		PARSE_DATE('%%Y%%m%%d', partition_id) as partitiondate,
		total_rows as records
	FROM
		syzkaller.syzbot_coverage.INFORMATION_SCHEMA.PARTITIONS
	WHERE table_name LIKE '%s'
	`, ns))
	it, err := q.Read(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Read() from bigquery: %w", err)
	}

	var periods []coveragedb.TimePeriod
	var recordsCount []int64
	for {
		var values struct {
			PartitionDate civil.Date
			Records       int64
		}
		err = it.Next(&values)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to it.Next() bigquery records: %w", err)
		}
		periods = append(periods, coveragedb.TimePeriod{DateTo: values.PartitionDate, Days: 1})
		recordsCount = append(recordsCount, values.Records)
	}
	return periods, recordsCount, nil
}
