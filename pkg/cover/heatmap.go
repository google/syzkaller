// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"golang.org/x/exp/maps"
)

type templateHeatmapRow struct {
	Items               []*templateHeatmapRow
	Name                string
	Coverage            []int64
	IsDir               bool
	Depth               int
	LastDayInstrumented int64
	Tooltips            []string
	FileCoverageLink    []string

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

func (thm *templateHeatmapRow) prepareDataFor(pageColumns []pageColumnTarget, skipEmpty bool) {
	for _, item := range thm.builder {
		if !skipEmpty {
			thm.Items = append(thm.Items, item)
			continue
		}
		for _, hitCount := range item.covered {
			if hitCount > 0 {
				thm.Items = append(thm.Items, item)
				break
			}
		}
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
			dateCoverage = percent(thm.covered[tp], thm.instrumented[tp])
		}
		thm.Coverage = append(thm.Coverage, dateCoverage)
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
		thm.LastDayInstrumented = thm.instrumented[lastDate]
	}
	for _, item := range thm.builder {
		item.prepareDataFor(pageColumns, skipEmpty)
	}
}

type pageColumnTarget struct {
	TimePeriod coveragedb.TimePeriod
	Commit     string
}

func filesCoverageToTemplateData(fCov []*coveragedb.FileCoverageWithDetails, hideEmpty bool) *templateHeatmap {
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

	res.Root.prepareDataFor(targetDateAndCommits, hideEmpty)
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

func DoHeatMapStyleBodyJS(
	ctx context.Context, client spannerclient.SpannerClient, scope *coveragedb.SelectScope, onlyUnique bool,
	sss, managers []string) (template.CSS, template.HTML, template.HTML, error) {
	covAndDates, err := coveragedb.FilesCoverageWithDetails(ctx, client, scope, onlyUnique)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to FilesCoverageWithDetails: %w", err)
	}
	templData := filesCoverageToTemplateData(covAndDates, onlyUnique)
	templData.Subsystems = sss
	templData.Managers = managers
	return stylesBodyJSTemplate(templData)
}

func DoSubsystemsHeatMapStyleBodyJS(
	ctx context.Context, client spannerclient.SpannerClient, scope *coveragedb.SelectScope, onlyUnique bool,
	sss, managers []string) (template.CSS, template.HTML, template.HTML, error) {
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
	templData := filesCoverageToTemplateData(ssCovAndDates, onlyUnique)
	templData.Managers = managers
	return stylesBodyJSTemplate(templData)
}

func approximateInstrumented(points int64) string {
	dim := "_"
	if points > 10000 {
		dim = "K"
		points /= 1000
	}
	return fmt.Sprintf("%d%s", points, dim)
}

//go:embed templates/heatmap.html
var templatesHeatmap string
var templateHeatmapFuncs = template.FuncMap{
	"approxInstr": approximateInstrumented,
}
var heatmapTemplate = template.Must(template.New("").Funcs(templateHeatmapFuncs).Parse(templatesHeatmap))
