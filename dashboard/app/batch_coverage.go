// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"cloud.google.com/go/batch/apiv1/batchpb"
	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/coveragedb"
	"google.golang.org/api/iterator"
	"google.golang.org/appengine/v2/log"
)

const batchCoverageTimeoutSeconds = 60 * 60 * 12

func handleBatchCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
		periodsMerged, rowsMerged, err := coveragedb.NsDataMerged(ctx, coverageDBClient, ns)
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
		serviceAccount := &batchpb.ServiceAccount{
			Email:  nsCovConfig.BatchServiceAccount,
			Scopes: nsCovConfig.BatchScopes,
		}
		if err := createScriptJob(ctx, nsCovConfig.BatchProject, "coverage-merge",
			batchCoverageScript(ns, repo, branch, periods,
				nsCovConfig.JobInitScript,
				nsCovConfig.SyzEnvInitScript,
				nsCovConfig.DashboardClientName),
			batchCoverageTimeoutSeconds,
			serviceAccount,
		); err != nil {
			log.Errorf(ctx, "failed to batchCoverageScript: %s", err.Error())
		}
	}
}

func batchCoverageScript(ns, repo, branch string, periods []coveragedb.TimePeriod,
	jobInitScript, syzEnvInitScript, clientName string) string {
	if clientName == "" {
		clientName = defaultDashboardClientName
	}
	script := jobInitScript + "\n"
	script += "git clone -q --depth 1 --branch master --single-branch https://github.com/google/syzkaller\n" +
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

func handleBatchCoverageClean(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	totalDeleted, err := coveragedb.DeleteGarbage(ctx, coverageDBClient)
	if err != nil {
		errMsg := fmt.Sprintf("failed to coveragedb.DeleteGarbage: %s", err.Error())
		log.Errorf(ctx, "%s", errMsg)
		w.Write([]byte(errMsg))
		return
	}
	logMsg := fmt.Sprintf("successfully deleted %d rows\n", totalDeleted)
	log.Infof(ctx, "%s", logMsg)
	w.Write([]byte(logMsg))
}
