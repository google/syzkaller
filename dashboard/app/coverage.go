// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/google/syzkaller/pkg/covermerger"
	"github.com/google/syzkaller/pkg/html/urlutil"
	"github.com/google/syzkaller/pkg/validator"
	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
)

var coverageDBClient spannerclient.SpannerClient

func initCoverageDB() {
	if !appengine.IsAppEngine() {
		// It is a test environment.
		// Use setCoverageDBClient to specify the coveragedb mock or emulator in every test.
		return
	}
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	var err error
	coverageDBClient, err = spannerclient.NewClient(context.Background(), projectID)
	if err != nil {
		panic("spanner.NewClient: " + err.Error())
	}
}

var keyCoverageDBClient = "coveragedb client key"

func getCoverageDBClient(ctx context.Context) spannerclient.SpannerClient {
	ctxClient, _ := ctx.Value(&keyCoverageDBClient).(spannerclient.SpannerClient)
	if ctxClient == nil && coverageDBClient == nil {
		panic("attempt to get coverage db client before it was set in tests")
	}
	if ctxClient != nil {
		return ctxClient
	}
	return coverageDBClient
}

type funcStyleBodyJS func(
	ctx context.Context, client spannerclient.SpannerClient,
	scope *coveragedb.SelectScope, onlyUnique bool, sss, managers []string, dataFilters cover.Format,
) (template.CSS, template.HTML, template.HTML, error)

type coverageHeatmapParams struct {
	manager    string
	subsystem  string
	onlyUnique bool
	periodType string
	nPeriods   int
	dateTo     civil.Date
	cover.Format
}

const minPeriodsOnThePage = 1
const maxPeriodsOnThePage = 12

func makeHeatmapParams(ctx context.Context, r *http.Request) (*coverageHeatmapParams, error) {
	onlyUnique := getParam[bool](r, UniqueOnly.ParamName(), false)
	periodType := getParam[string](r, PeriodType.ParamName())
	if !slices.Contains(coveragedb.AllPeriods, periodType) {
		return nil, fmt.Errorf("only {%s} are allowed, but received %s instead, %w",
			strings.Join(coveragedb.AllPeriods, ", "), periodType, ErrClientBadRequest)
	}
	nPeriods := getParam[int](r, PeriodCount.ParamName(), 4)
	if nPeriods > maxPeriodsOnThePage || nPeriods < minPeriodsOnThePage {
		return nil, fmt.Errorf("periods_count is wrong, expected [%d, %d]",
			minPeriodsOnThePage, maxPeriodsOnThePage)
	}

	return &coverageHeatmapParams{
		manager:    getParam[string](r, ManagerName.ParamName()),
		subsystem:  getParam[string](r, SubsystemName.ParamName()),
		onlyUnique: onlyUnique,
		periodType: periodType,
		nPeriods:   nPeriods,
		dateTo:     getParam[civil.Date](r, DateTo.ParamName(), civil.DateOf(timeNow(ctx))),
		Format: cover.Format{
			DropCoveredLines0:         onlyUnique,
			OrderByCoveredLinesDrop:   getParam[bool](r, OrderByCoverDrop.ParamName()),
			FilterMinCoveredLinesDrop: getParam[int](r, MinCoverLinesDrop.ParamName()),
		},
	}, nil
}

func getParam[T int | string | bool | civil.Date](r *http.Request, name string, orDefault ...T) T {
	var def T
	if len(orDefault) > 0 {
		def = orDefault[0]
	}
	if r.FormValue(name) == "" {
		return def
	}
	var t T
	return extractVal(t, r.FormValue(name)).(T)
}

func extractVal(t any, val string) any {
	switch t.(type) {
	case int:
		res, _ := strconv.Atoi(val)
		return res
	case string:
		return val
	case bool:
		res, _ := strconv.ParseBool(val)
		return res
	case civil.Date:
		res, _ := civil.ParseDate(val)
		return res
	}
	panic("unsupported type")
}

func handleCoverageHeatmap(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	params, err := makeHeatmapParams(ctx, r)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrClientBadRequest)
	}
	if getParam[bool](r, "jsonl") {
		ns := hdr.Namespace
		repo, _ := getNsConfig(ctx, ns).mainRepoBranch()
		w.Header().Set("Content-Type", "application/json")
		return writeExtAPICoverageFor(ctx, w, ns, repo, params)
	}
	return handleHeatmap(ctx, w, hdr, params, cover.DoHeatMapStyleBodyJS)
}

func handleSubsystemsCoverageHeatmap(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	params, err := makeHeatmapParams(ctx, r)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrClientBadRequest)
	}
	return handleHeatmap(ctx, w, hdr, params, cover.DoSubsystemsHeatMapStyleBodyJS)
}

type covPageParam string

func (p covPageParam) ParamName() string {
	return string(p)
}

const (
	// keep-sorted start
	CommitHash        = covPageParam("commit")
	DateTo            = covPageParam("dateto")
	FilePath          = covPageParam("filepath")
	ManagerName       = covPageParam("manager")
	MinCoverLinesDrop = covPageParam("min-cover-lines-drop")
	OrderByCoverDrop  = covPageParam("order-by-cover-lines-drop")
	PeriodCount       = covPageParam("period_count")
	PeriodType        = covPageParam("period")
	SubsystemName     = covPageParam("subsystem")
	UniqueOnly        = covPageParam("unique-only")
	// keep-sorted end
)

func coveragePageLink(ns, periodType, dateTo string, minDrop, periodCount int, orderByCoverDrop bool) string {
	if periodType == "" {
		periodType = coveragedb.MonthPeriod
	}
	url := "/" + ns + "/coverage"
	url = urlutil.SetParam(url, PeriodType.ParamName(), periodType)
	if periodCount != 0 {
		url = urlutil.SetParam(url, PeriodCount.ParamName(), strconv.Itoa(periodCount))
	}
	if dateTo != "" {
		url = urlutil.SetParam(url, DateTo.ParamName(), dateTo)
	}
	if minDrop > 0 {
		url = urlutil.SetParam(url, MinCoverLinesDrop.ParamName(), strconv.Itoa(minDrop))
	}
	if orderByCoverDrop {
		url = urlutil.SetParam(url, OrderByCoverDrop.ParamName(), "1")
	}
	return url
}

func handleHeatmap(ctx context.Context, w http.ResponseWriter, hdr *uiHeader, p *coverageHeatmapParams,
	f funcStyleBodyJS) error {
	nsConfig := getNsConfig(ctx, hdr.Namespace)
	if nsConfig.Coverage == nil {
		return ErrClientNotFound
	}

	periods, err := coveragedb.GenNPeriodsTill(p.nPeriods, p.dateTo, p.periodType)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrClientBadRequest)
	}
	managers, err := CachedManagerList(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	var subsystems []string
	if ssService := getNsConfig(ctx, hdr.Namespace).Subsystems.Service; ssService != nil {
		for _, s := range ssService.List() {
			subsystems = append(subsystems, s.Name)
		}
	}
	slices.Sort(managers)
	slices.Sort(subsystems)

	var style template.CSS
	var body, js template.HTML
	if style, body, js, err = f(ctx, getCoverageDBClient(ctx),
		&coveragedb.SelectScope{
			Ns:        hdr.Namespace,
			Subsystem: p.subsystem,
			Manager:   p.manager,
			Periods:   periods,
		},
		p.onlyUnique, subsystems, managers, p.Format,
	); err != nil {
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
		// Parameter format=TEXT is ignored by git servers but is processed by gerrit servers.
		// Gerrit returns base64 encoded data.
		// Git return the plain text data.
		return fmt.Sprintf("%s/%s/%s?format=TEXT", url, commit, filePath)
	}
}

func handleFileCoverage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	nsConfig := getNsConfig(ctx, hdr.Namespace)
	if nsConfig.Coverage == nil || nsConfig.Coverage.WebGitURI == "" {
		return ErrClientNotFound
	}
	dateToStr := r.FormValue(DateTo.ParamName())
	periodType := r.FormValue(PeriodType.ParamName())
	targetCommit := r.FormValue(CommitHash.ParamName())
	kernelFilePath := r.FormValue(FilePath.ParamName())
	manager := r.FormValue(ManagerName.ParamName())
	if err := validator.AnyError("input validation failed",
		validator.TimePeriodType(periodType, PeriodType.ParamName()),
		validator.CommitHash(targetCommit, CommitHash.ParamName()),
		validator.KernelFilePath(kernelFilePath, FilePath.ParamName()),
		validator.AnyOk(
			validator.Allowlisted(manager, []string{"", "*"}, ManagerName.ParamName()),
			validator.ManagerName(manager, ManagerName.ParamName())),
	); err != nil {
		return fmt.Errorf("%w: %w", err, ErrClientBadRequest)
	}
	targetDate, err := civil.ParseDate(dateToStr)
	if err != nil {
		return fmt.Errorf("%w: civil.ParseDate(%s): %w", ErrClientBadRequest, dateToStr, err)
	}
	tp, err := coveragedb.MakeTimePeriod(targetDate, periodType)
	if err != nil {
		return fmt.Errorf("coveragedb.MakeTimePeriod: %w", err)
	}
	mainNsRepo, _ := nsConfig.mainRepoBranch()
	client := getCoverageDBClient(ctx)
	if client == nil {
		return fmt.Errorf("spannerdb client is nil")
	}
	hitLines, hitCounts, err := coveragedb.ReadLinesHitCount(
		ctx, client, hdr.Namespace, targetCommit, kernelFilePath, manager, tp)
	covMap := coveragedb.MakeCovMap(hitLines, hitCounts)
	if err != nil {
		return fmt.Errorf("coveragedb.ReadLinesHitCount(%s): %w", manager, err)
	}
	if getParam[bool](r, UniqueOnly.ParamName()) {
		// This request is expected to be made second by tests.
		// Moving it to goroutine don't forget to change multiManagerCovDBFixture.
		allHitLines, allHitCounts, err := coveragedb.ReadLinesHitCount(
			ctx, client, hdr.Namespace, targetCommit, kernelFilePath, "*", tp)
		if err != nil {
			return fmt.Errorf("coveragedb.ReadLinesHitCount(*): %w", err)
		}
		covMap = coveragedb.UniqCoverage(coveragedb.MakeCovMap(allHitLines, allHitCounts), covMap)
	}

	webGit := getWebGit(ctx) // Get mock if available.
	if webGit == nil {
		webGit = covermerger.MakeWebGit(makeProxyURIProvider(nsConfig.Coverage.WebGitURI))
	}

	content, err := cover.RendFileCoverage(
		mainNsRepo,
		targetCommit,
		kernelFilePath,
		webGit,
		&covermerger.MergeResult{HitCounts: covMap},
		cover.DefaultHTMLRenderConfig())
	if err != nil {
		return fmt.Errorf("cover.RendFileCoverage: %w", err)
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(content))
	return nil
}

var keyWebGit = "file content provider"

func setWebGit(ctx context.Context, provider covermerger.FileVersProvider) context.Context {
	return context.WithValue(ctx, &keyWebGit, provider)
}

func getWebGit(ctx context.Context) covermerger.FileVersProvider {
	res, _ := ctx.Value(&keyWebGit).(covermerger.FileVersProvider)
	return res
}

func handleCoverageGraph(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	nsConfig := getNsConfig(ctx, hdr.Namespace)
	if nsConfig.Coverage == nil {
		return ErrClientNotFound
	}
	periodType := r.FormValue(PeriodType.ParamName())
	if periodType == "" {
		periodType = coveragedb.QuarterPeriod
	}
	if periodType != coveragedb.QuarterPeriod && periodType != coveragedb.MonthPeriod {
		return fmt.Errorf("only quarter and month are allowed, but received %s instead", periodType)
	}
	hist, err := MergedCoverage(ctx, getCoverageDBClient(ctx), hdr.Namespace, periodType)
	if err != nil {
		return err
	}
	periodEndDates, err := coveragedb.GenNPeriodsTill(12, civil.DateOf(timeNow(ctx)), periodType)
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

func handleUpdateCoverDBSubsystems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	for ns, nsConfig := range getConfig(ctx).Namespaces {
		service := nsConfig.Subsystems.Service
		if service == nil {
			continue
		}
		sss := service.List()
		updatedRecords, err := coveragedb.RegenerateSubsystems(ctx, ns, sss, coverageDBClient)
		if err != nil {
			httpErr := fmt.Errorf("ns %s: %w", ns, err)
			log.Errorf(ctx, "%s", httpErr.Error())
			http.Error(w, httpErr.Error(), http.StatusInternalServerError)
			return
		}
		log.Infof(ctx, "%s: %v records updated\n", ns, updatedRecords)
		fmt.Fprintf(w, "%s: %v records updated\n", ns, updatedRecords)
	}
}
