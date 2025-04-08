// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"slices"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"golang.org/x/exp/maps"
)

type templateHeatmapRow struct {
	Items            []*templateHeatmapRow
	Name             string
	Coverage         []int64 // in percent
	Covered          []int64 // in lines count
	IsDir            bool
	Depth            int
	Summary          int64 // right column, may be negative to show drops
	Tooltips         []string
	FileCoverageLink []string

	builder      map[string]*templateHeatmapRow
	instrumented map[coveragedb.TimePeriod]int64
	covered      map[coveragedb.TimePeriod]int64
	filePath     string
}

type templateHeatmap struct {
	Root       *templateHeatmapRow
	Periods    []string
	Subsystems []string
	Managers   []string
}

func (th *templateHeatmap) Filter(pred func(*templateHeatmapRow) bool) {
	th.Root.filter(pred)
}

func (th *templateHeatmap) Transform(f func(*templateHeatmapRow)) {
	th.Root.transform(f)
}

func (th *templateHeatmap) Sort(pred func(*templateHeatmapRow, *templateHeatmapRow) int) {
	th.Root.sort(pred)
}

func (thm *templateHeatmapRow) transform(f func(*templateHeatmapRow)) {
	for _, item := range thm.Items {
		item.transform(f)
	}
	f(thm)
}

func (thm *templateHeatmapRow) filter(pred func(*templateHeatmapRow) bool) {
	var filteredItems []*templateHeatmapRow
	for _, item := range thm.Items {
		item.filter(pred)
		if pred(item) {
			filteredItems = append(filteredItems, item)
		}
	}
	thm.Items = filteredItems
}

func (thm *templateHeatmapRow) sort(pred func(*templateHeatmapRow, *templateHeatmapRow) int) {
	for _, item := range thm.Items {
		item.sort(pred)
	}
	slices.SortFunc(thm.Items, pred)
}

func (thm *templateHeatmapRow) addParts(depth int, pathLeft []string, filePath string, instrumented, covered int64,
	timePeriod coveragedb.TimePeriod) {
	thm.instrumented[timePeriod] += instrumented
	thm.covered[timePeriod] += covered
	if len(pathLeft) == 0 {
		return
	}
	nextElement := pathLeft[0]
	isDir := len(pathLeft) > 1
	fp := ""
	if !isDir {
		fp = filePath
	}
	if _, ok := thm.builder[nextElement]; !ok {
		thm.builder[nextElement] = &templateHeatmapRow{
			Name:         nextElement,
			Depth:        depth,
			IsDir:        isDir,
			filePath:     fp,
			builder:      make(map[string]*templateHeatmapRow),
			instrumented: make(map[coveragedb.TimePeriod]int64),
			covered:      make(map[coveragedb.TimePeriod]int64),
		}
	}
	thm.builder[nextElement].addParts(depth+1, pathLeft[1:], filePath, instrumented, covered, timePeriod)
}

func (thm *templateHeatmapRow) prepareDataFor(pageColumns []pageColumnTarget) {
	for _, item := range thm.builder {
		thm.Items = append(thm.Items, item)
	}
	sort.Slice(thm.Items, func(i, j int) bool {
		if thm.Items[i].IsDir != thm.Items[j].IsDir {
			return thm.Items[i].IsDir
		}
		return thm.Items[i].Name < thm.Items[j].Name
	})
	for _, pageColumn := range pageColumns {
		var dateCoverage int64
		tp := pageColumn.TimePeriod
		if thm.instrumented[tp] != 0 {
			dateCoverage = Percent(thm.covered[tp], thm.instrumented[tp])
		}
		thm.Coverage = append(thm.Coverage, dateCoverage)
		thm.Covered = append(thm.Covered, thm.covered[tp])
		thm.Tooltips = append(thm.Tooltips, fmt.Sprintf("Instrumented:\t%d blocks\nCovered:\t%d blocks",
			thm.instrumented[tp], thm.covered[tp]))
		if !thm.IsDir {
			thm.FileCoverageLink = append(thm.FileCoverageLink,
				fmt.Sprintf("/coverage/file?dateto=%s&period=%s&commit=%s&filepath=%s",
					tp.DateTo.String(),
					tp.Type,
					pageColumn.Commit,
					thm.filePath))
		}
	}
	if len(pageColumns) > 0 {
		lastDate := pageColumns[len(pageColumns)-1].TimePeriod
		thm.Summary = thm.instrumented[lastDate]
	}
	for _, item := range thm.builder {
		item.prepareDataFor(pageColumns)
	}
}

type pageColumnTarget struct {
	TimePeriod coveragedb.TimePeriod
	Commit     string
}

func filesCoverageToTemplateData(fCov []*coveragedb.FileCoverageWithDetails) *templateHeatmap {
	res := templateHeatmap{
		Root: &templateHeatmapRow{
			IsDir:        true,
			builder:      map[string]*templateHeatmapRow{},
			instrumented: map[coveragedb.TimePeriod]int64{},
			covered:      map[coveragedb.TimePeriod]int64{},
		},
	}
	columns := map[pageColumnTarget]struct{}{}
	for _, fc := range fCov {
		var pathLeft []string
		if fc.Subsystem != "" {
			pathLeft = append(pathLeft, fc.Subsystem)
		}
		res.Root.addParts(
			0,
			append(pathLeft, strings.Split(fc.Filepath, "/")...),
			fc.Filepath,
			fc.Instrumented,
			fc.Covered,
			fc.TimePeriod)
		columns[pageColumnTarget{TimePeriod: fc.TimePeriod, Commit: fc.Commit}] = struct{}{}
	}
	targetDateAndCommits := maps.Keys(columns)
	sort.Slice(targetDateAndCommits, func(i, j int) bool {
		return targetDateAndCommits[i].TimePeriod.DateTo.Before(targetDateAndCommits[j].TimePeriod.DateTo)
	})
	for _, tdc := range targetDateAndCommits {
		tp := tdc.TimePeriod
		res.Periods = append(res.Periods, fmt.Sprintf("%s(%d)", tp.DateTo.String(), tp.Days))
	}

	res.Root.prepareDataFor(targetDateAndCommits)
	return &res
}

type StyleBodyJS struct {
	Style template.CSS
	Body  template.HTML
	JS    template.HTML
}

func stylesBodyJSTemplate(templData *templateHeatmap,
) (template.CSS, template.HTML, template.HTML, error) {
	var styles, body, js bytes.Buffer
	if err := heatmapTemplate.ExecuteTemplate(&styles, "style", templData); err != nil {
		return "", "", "", fmt.Errorf("failed to get styles: %w", err)
	}
	if err := heatmapTemplate.ExecuteTemplate(&body, "body", templData); err != nil {
		return "", "", "", fmt.Errorf("failed to get body: %w", err)
	}
	if err := heatmapTemplate.ExecuteTemplate(&js, "js", templData); err != nil {
		return "", "", "", fmt.Errorf("failed to get js: %w", err)
	}
	return template.CSS(styles.String()),
		template.HTML(body.String()),
		template.HTML(js.Bytes()), nil
}

type Format struct {
	FilterMinCoveredLinesDrop int
	OrderByCoveredLinesDrop   bool
	DropCoveredLines0         bool
}

func DoHeatMapStyleBodyJS(
	ctx context.Context, client spannerclient.SpannerClient, scope *coveragedb.SelectScope, onlyUnique bool,
	sss, managers []string, dataFilters Format) (template.CSS, template.HTML, template.HTML, error) {
	covAndDates, err := coveragedb.FilesCoverageWithDetails(ctx, client, scope, onlyUnique)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to FilesCoverageWithDetails: %w", err)
	}
	templData := filesCoverageToTemplateData(covAndDates)
	templData.Subsystems = sss
	templData.Managers = managers
	FormatResult(templData, dataFilters)

	return stylesBodyJSTemplate(templData)
}

func DoSubsystemsHeatMapStyleBodyJS(
	ctx context.Context, client spannerclient.SpannerClient, scope *coveragedb.SelectScope, onlyUnique bool,
	sss, managers []string, format Format) (template.CSS, template.HTML, template.HTML, error) {
	covWithDetails, err := coveragedb.FilesCoverageWithDetails(ctx, client, scope, onlyUnique)
	if err != nil {
		panic(err)
	}
	var ssCovAndDates []*coveragedb.FileCoverageWithDetails
	for _, cwd := range covWithDetails {
		for _, ssName := range cwd.Subsystems {
			newRecord := coveragedb.FileCoverageWithDetails{
				Filepath:     cwd.Filepath,
				Subsystem:    ssName,
				Instrumented: cwd.Instrumented,
				Covered:      cwd.Covered,
				TimePeriod:   cwd.TimePeriod,
				Commit:       cwd.Commit,
			}
			ssCovAndDates = append(ssCovAndDates, &newRecord)
		}
	}
	templData := filesCoverageToTemplateData(ssCovAndDates)
	templData.Managers = managers
	FormatResult(templData, format)
	return stylesBodyJSTemplate(templData)
}

func FormatResult(thm *templateHeatmap, format Format) {
	thm.Filter(func(row *templateHeatmapRow) bool {
		if row.IsDir && len(row.Items) > 0 {
			return true
		}
		return slices.Max(row.Covered)-row.Covered[len(row.Covered)-1] >= int64(format.FilterMinCoveredLinesDrop)
	})
	if format.DropCoveredLines0 {
		thm.Filter(func(row *templateHeatmapRow) bool {
			return slices.Max(row.Covered) > 0
		})
	}
	// The files are sorted lexicographically by default.
	if format.OrderByCoveredLinesDrop {
		thm.Sort(func(row1 *templateHeatmapRow, row2 *templateHeatmapRow) int {
			row1CoveredDrop := slices.Max(row1.Covered) - row1.Covered[len(row1.Covered)-1]
			row2CoveredDrop := slices.Max(row2.Covered) - row2.Covered[len(row2.Covered)-1]
			return int(row2CoveredDrop - row1CoveredDrop)
		})
		// We want to show the coverage drop numbers instead of total instrumented blocks.
		thm.Transform(func(row *templateHeatmapRow) {
			row.Summary = -1 * (slices.Max(row.Covered) - row.Covered[len(row.Covered)-1])
		})
	}
}

func approximateInstrumented(points int64) string {
	dim := "_"
	if abs(points) > 10000 {
		dim = "K"
		points /= 1000
	}
	return fmt.Sprintf("%d%s", points, dim)
}

func abs(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

//go:embed templates/heatmap.html
var templatesHeatmap string
var templateHeatmapFuncs = template.FuncMap{
	"approxInstr": approximateInstrumented,
}
var heatmapTemplate = template.Must(template.New("").Funcs(templateHeatmapFuncs).Parse(templatesHeatmap))
