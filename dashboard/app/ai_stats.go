// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"golang.org/x/sync/errgroup"
)

type uiAIGraphsPage struct {
	Header            *uiHeader
	TokenGraph        *uiGraph
	JobTypeTokenGraph *uiGraph
	FinishedJobsGraph *uiGraph
	JobTypesGraph     *uiGraph
}

func handleAIGraphs(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	if !hdr.Admin {
		return ErrAccess
	}

	var modelTokens []*aidb.MonthlyModelTokenStat
	var jobTypeTokens []*aidb.MonthlyJobTypeTokenStat
	var finishedJobs []*aidb.MonthlyFinishedJobsStat
	var jobTypes []*aidb.MonthlyJobTypeStat

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		modelTokens, err = aidb.LoadMonthlyModelTokenStats(egCtx, hdr.Namespace)
		return err
	})
	eg.Go(func() error {
		var err error
		jobTypeTokens, err = aidb.LoadMonthlyJobTypeTokenStats(egCtx, hdr.Namespace)
		return err
	})
	eg.Go(func() error {
		var err error
		finishedJobs, err = aidb.LoadMonthlyFinishedJobsStats(egCtx, hdr.Namespace)
		return err
	})
	eg.Go(func() error {
		var err error
		jobTypes, err = aidb.LoadMonthlyJobTypeStats(egCtx, hdr.Namespace)
		return err
	})
	if err := eg.Wait(); err != nil {
		return err
	}

	tokenGraph := createAITokenGraph(modelTokens)
	jobTypeTokenGraph := createAIJobTypeTokenGraph(jobTypeTokens)
	finishedGraph := createAIFinishedJobsGraph(finishedJobs)
	jobTypesGraph := createAIJobTypesGraph(jobTypes)

	page := &uiAIGraphsPage{
		Header:            hdr,
		TokenGraph:        tokenGraph,
		JobTypeTokenGraph: jobTypeTokenGraph,
		FinishedJobsGraph: finishedGraph,
		JobTypesGraph:     jobTypesGraph,
	}

	return serveTemplate(w, "graph_ai.html", page)
}

type aiMonthlySeriesData struct {
	month  time.Time
	series string
	val    int64
}

func createAIMonthlyMultiSeriesGraph(items []aiMonthlySeriesData, hintFormatter func(string, int64) string) *uiGraph {
	monthMap := make(map[time.Time]map[string]int64)
	var months []time.Time
	var seriesList []string
	seriesSeen := make(map[string]bool)

	for _, item := range items {
		m := time.Date(item.month.Year(), item.month.Month(), 1, 0, 0, 0, 0, time.UTC)
		if monthMap[m] == nil {
			monthMap[m] = make(map[string]int64)
			months = append(months, m)
		}
		s := item.series
		if s == "" {
			s = "unknown"
		}
		if !seriesSeen[s] {
			seriesSeen[s] = true
			seriesList = append(seriesList, s)
		}
		monthMap[m][s] += item.val
	}
	slices.SortFunc(months, func(a, b time.Time) int {
		return a.Compare(b)
	})
	slices.Sort(seriesList)

	var headers []uiGraphHeader
	for _, s := range seriesList {
		headers = append(headers, uiGraphHeader{Name: s})
	}

	var columns []uiGraphColumn
	for _, m := range months {
		col := uiGraphColumn{Hint: m.Format("Jan-06")}
		for _, s := range seriesList {
			val := monthMap[m][s]
			hint := fmt.Sprintf("%s: %d", s, val)
			if hintFormatter != nil {
				hint = hintFormatter(s, val)
			}
			col.Vals = append(col.Vals, uiGraphValue{
				Val:  float32(val),
				Hint: hint,
			})
			col.Annotation += float32(val)
		}
		columns = append(columns, col)
	}
	return &uiGraph{
		Headers: headers,
		Columns: columns,
	}
}

func tokensToMonthlySeries[T any](stats []T, get func(T) (time.Time, string, int64)) *uiGraph {
	var items []aiMonthlySeriesData
	for _, s := range stats {
		month, series, val := get(s)
		items = append(items, aiMonthlySeriesData{
			month:  month,
			series: series,
			val:    val,
		})
	}
	return createAIMonthlyMultiSeriesGraph(items, func(series string, val int64) string {
		return fmt.Sprintf("%s: %d tokens", series, val)
	})
}

func createAITokenGraph(stats []*aidb.MonthlyModelTokenStat) *uiGraph {
	return tokensToMonthlySeries(stats, func(s *aidb.MonthlyModelTokenStat) (time.Time, string, int64) {
		return s.Month, s.Model, s.TotalTokens
	})
}

func createAIJobTypeTokenGraph(stats []*aidb.MonthlyJobTypeTokenStat) *uiGraph {
	return tokensToMonthlySeries(stats, func(s *aidb.MonthlyJobTypeTokenStat) (time.Time, string, int64) {
		return s.Month, s.Type, s.TotalTokens
	})
}

func createAIFinishedJobsGraph(stats []*aidb.MonthlyFinishedJobsStat) *uiGraph {
	monthMap := make(map[time.Time]int64)
	var months []time.Time
	for _, s := range stats {
		m := time.Date(s.Month.Year(), s.Month.Month(), 1, 0, 0, 0, 0, time.UTC)
		if _, ok := monthMap[m]; !ok {
			months = append(months, m)
		}
		monthMap[m] += s.FinishedCount
	}
	slices.SortFunc(months, func(a, b time.Time) int {
		return a.Compare(b)
	})
	headers := []uiGraphHeader{{Name: "Finished Jobs", Color: "#4285F4"}}
	var columns []uiGraphColumn
	for _, m := range months {
		count := monthMap[m]
		col := uiGraphColumn{
			Hint:       m.Format("Jan-06"),
			Annotation: float32(count),
			Vals: []uiGraphValue{{
				Val:  float32(count),
				Hint: fmt.Sprintf("%d jobs", count),
			}},
		}
		columns = append(columns, col)
	}
	return &uiGraph{
		Headers: headers,
		Columns: columns,
	}
}

func createAIJobTypesGraph(stats []*aidb.MonthlyJobTypeStat) *uiGraph {
	var items []aiMonthlySeriesData
	for _, s := range stats {
		items = append(items, aiMonthlySeriesData{
			month:  s.Month,
			series: s.Type,
			val:    s.Count,
		})
	}
	return createAIMonthlyMultiSeriesGraph(items, nil)
}
