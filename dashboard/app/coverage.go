// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strconv"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/google/syzkaller/pkg/covermerger"
	"github.com/google/syzkaller/pkg/validator"
)

type funcStyleBodyJS func(
	ctx context.Context, client spannerclient.SpannerClient,
	scope *cover.SelectScope, onlyUnique bool, sss, managers []string,
) (template.CSS, template.HTML, template.HTML, error)

func handleCoverageHeatmap(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleHeatmap(c, w, r, cover.DoHeatMapStyleBodyJS)
}

func handleSubsystemsCoverageHeatmap(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleHeatmap(c, w, r, cover.DoSubsystemsHeatMapStyleBodyJS)
}

func handleHeatmap(c context.Context, w http.ResponseWriter, r *http.Request, f funcStyleBodyJS) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	ss := r.FormValue("subsystem")
	manager := r.FormValue("manager")

	periodType := r.FormValue("period")
	if periodType == "" {
		periodType = coveragedb.DayPeriod
	}
	if periodType != coveragedb.DayPeriod && periodType != coveragedb.MonthPeriod {
		return fmt.Errorf("only day and month are allowed, but received %s instead, %w",
			periodType, ErrClientBadRequest)
	}

	periodCount := r.FormValue("period_count")
	if periodCount == "" {
		periodCount = "4"
	}
	nPeriods, err := strconv.Atoi(periodCount)
	if err != nil || nPeriods > 12 || nPeriods < 1 {
		return fmt.Errorf("periods_count is wrong, expected [1, 12]: %w", err)
	}

	periods, err := coveragedb.GenNPeriodsTill(nPeriods, civil.DateOf(timeNow(c)), periodType)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrClientBadRequest)
	}
	managers, err := CachedManagerList(c, hdr.Namespace)
	if err != nil {
		return err
	}
	ssService := getNsConfig(c, hdr.Namespace).Subsystems.Service
	var subsystems []string
	for _, ss := range ssService.List() {
		subsystems = append(subsystems, ss.Name)
	}
	slices.Sort(managers)
	slices.Sort(subsystems)

	onlyUnique := r.FormValue("unique-only") == "1"

	spannerClient, err := spannerclient.NewClient(c, "syzkaller")
	if err != nil {
		return fmt.Errorf("spanner.NewClient: %s", err.Error())
	}
	defer spannerClient.Close()

	var style template.CSS
	var body, js template.HTML
	if style, body, js, err = f(c, spannerClient,
		&cover.SelectScope{
			Ns:        hdr.Namespace,
			Subsystem: ss,
			Manager:   manager,
			Periods:   periods,
		},
		onlyUnique, subsystems, managers); err != nil {
		return fmt.Errorf("failed to generate heatmap: %w", err)
	}
	return serveTemplate(w, "custom_content.html", struct {
		Header *uiHeader
		*cover.StyleBodyJS
	}{
		Header: hdr,
		StyleBodyJS: &cover.StyleBodyJS{
			Style: style,
			Body:  body,
			JS:    js,
		},
	})
}

func makeProxyURIProvider(url string) covermerger.FuncProxyURI {
	return func(filePath, commit string) string {
		return fmt.Sprintf("%s/%s/%s", url, commit, filePath)
	}
}

func handleFileCoverage(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	nsConfig := getNsConfig(c, hdr.Namespace)
	if nsConfig.Coverage == nil || nsConfig.Coverage.WebGitURI == "" {
		return ErrClientNotFound
	}
	dateToStr := r.FormValue("dateto")
	periodType := r.FormValue("period")
	targetCommit := r.FormValue("commit")
	kernelFilePath := r.FormValue("filepath")
	manager := r.FormValue("manager")
	if err := validator.AnyError("input validation failed",
		validator.TimePeriodType(periodType, "period"),
		validator.CommitHash(targetCommit, "commit"),
		validator.KernelFilePath(kernelFilePath, "filepath"),
		validator.AnyOk(
			validator.Allowlisted(manager, []string{"", "*"}, "manager"),
			validator.ManagerName(manager, "manager")),
	); err != nil {
		return fmt.Errorf("%w: %w", err, ErrClientBadRequest)
	}
	targetDate, err := civil.ParseDate(dateToStr)
	if err != nil {
		return fmt.Errorf("civil.ParseDate(%s): %w", dateToStr, err)
	}
	tp, err := coveragedb.MakeTimePeriod(targetDate, periodType)
	if err != nil {
		return fmt.Errorf("coveragedb.MakeTimePeriod: %w", err)
	}
	onlyUnique := r.FormValue("unique-only") == "1"
	mainNsRepo, _ := nsConfig.mainRepoBranch()
	hitLines, hitCounts, err := coveragedb.ReadLinesHitCount(c, hdr.Namespace, targetCommit, manager, kernelFilePath, tp)
	covMap := cover.MakeCovMap(hitLines, hitCounts)
	if err != nil {
		return fmt.Errorf("coveragedb.ReadLinesHitCount(%s): %w", manager, err)
	}
	if onlyUnique {
		allHitLines, allHitCounts, err := coveragedb.ReadLinesHitCount(c, hdr.Namespace, targetCommit, manager, kernelFilePath, tp)
		if err != nil {
			return fmt.Errorf("coveragedb.ReadLinesHitCount(*): %w", err)
		}
		covMap = cover.UniqCoverage(cover.MakeCovMap(allHitLines, allHitCounts), covMap)
	}

	content, err := cover.RendFileCoverage(
		mainNsRepo,
		targetCommit,
		kernelFilePath,
		makeProxyURIProvider(nsConfig.Coverage.WebGitURI),
		&covermerger.MergeResult{HitCounts: covMap},
		cover.DefaultHTMLRenderConfig())
	if err != nil {
		return fmt.Errorf("cover.RendFileCoverage: %w", err)
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(content))
	return nil
}

func handleCoverageGraph(c context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	periodType := r.FormValue("period")
	if periodType == "" {
		periodType = coveragedb.QuarterPeriod
	}
	if periodType != coveragedb.QuarterPeriod && periodType != coveragedb.MonthPeriod {
		return fmt.Errorf("only quarter and month are allowed, but received %s instead", periodType)
	}
	hist, err := MergedCoverage(c, hdr.Namespace, periodType)
	if err != nil {
		return err
	}
	periodEndDates, err := coveragedb.GenNPeriodsTill(12, civil.DateOf(timeNow(c)), periodType)
	if err != nil {
		return err
	}
	cols := []uiGraphColumn{}
	for _, periodEndDate := range periodEndDates {
		date := periodEndDate.DateTo.String()
		if _, ok := hist.covered[date]; !ok || hist.instrumented[date] == 0 {
			cols = append(cols, uiGraphColumn{Hint: date, Vals: []uiGraphValue{{IsNull: true}}})
		} else {
			val := float32(hist.covered[date]) / float32(hist.instrumented[date])
			cols = append(cols, uiGraphColumn{
				Hint:       date,
				Annotation: val,
				Vals:       []uiGraphValue{{Val: val}},
			})
		}
	}
	data := &uiHistogramPage{
		Title:  hdr.Namespace + " coverage",
		Header: hdr,
		Graph: &uiGraph{
			Headers: []uiGraphHeader{
				{Name: "Total", Color: "Red"},
			},
			Columns: cols,
		},
	}
	return serveTemplate(w, "graph_histogram.html", data)
}
