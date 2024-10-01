// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"golang.org/x/exp/maps"
	"google.golang.org/api/iterator"
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
	Root    *templateHeatmapRow
	Periods []string
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
	thm.Items = maps.Values(thm.builder)
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
			dateCoverage = 100 * thm.covered[tp] / thm.instrumented[tp]
		}
		thm.Coverage = append(thm.Coverage, dateCoverage)
		thm.Tooltips = append(thm.Tooltips, fmt.Sprintf("Instrumented:\t%d blocks\nCovered:\t%d blocks",
			thm.instrumented[tp], thm.covered[tp]))
		if !thm.IsDir {
			thm.FileCoverageLink = append(thm.FileCoverageLink,
				fmt.Sprintf("/upstream/graph/coverage/file?dateto=%s&period=%s&commit=%s&filepath=%s",
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
		item.prepareDataFor(pageColumns)
	}
}

type fileCoverageWithDetails struct {
	Subsystem    string
	Filepath     string
	Instrumented int64
	Covered      int64
	TimePeriod   coveragedb.TimePeriod `spanner:"-"`
	Commit       string
	Subsystems   []string
}

type pageColumnTarget struct {
	TimePeriod coveragedb.TimePeriod
	Commit     string
}

func filesCoverageToTemplateData(fCov []*fileCoverageWithDetails) *templateHeatmap {
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

func filesCoverageWithDetailsStmt(ns, subsystem string, timePeriod coveragedb.TimePeriod) spanner.Statement {
	stmt := spanner.Statement{
		SQL: `
select
  commit,
  instrumented,
  covered,
  files.filepath,
  subsystems
from merge_history
  join files
    on merge_history.session = files.session
  join file_subsystems
    on merge_history.namespace = file_subsystems.namespace and files.filepath = file_subsystems.filepath
where
  merge_history.namespace=$1 and dateto=$2 and duration=$3`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
		},
	}
	if subsystem != "" {
		stmt.SQL += " and $4=ANY(subsystems)"
		stmt.Params["p4"] = subsystem
	}
	return stmt
}

func filesCoverageWithDetails(ctx context.Context, projectID, ns, subsystem string, timePeriods []coveragedb.TimePeriod,
) ([]*fileCoverageWithDetails, error) {
	client, err := coveragedb.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("spanner.NewClient() failed: %s", err.Error())
	}
	defer client.Close()

	res := []*fileCoverageWithDetails{}
	for _, timePeriod := range timePeriods {
		stmt := filesCoverageWithDetailsStmt(ns, subsystem, timePeriod)
		iter := client.Single().Query(ctx, stmt)
		defer iter.Stop()
		for {
			row, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to iter.Next() spanner DB: %w", err)
			}
			var r fileCoverageWithDetails
			if err = row.ToStruct(&r); err != nil {
				return nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
			}
			r.TimePeriod = timePeriod
			res = append(res, &r)
		}
	}
	return res, nil
}

type StyleBodyJS struct {
	Style template.CSS
	Body  template.HTML
	JS    template.HTML
}

// nolint: dupl
func DoDirHeatMap(w io.Writer, projectID, ns string, periods []coveragedb.TimePeriod) error {
	style, body, js, err := DoHeatMapStyleBodyJS(context.Background(), projectID, ns, "", periods)
	if err != nil {
		return fmt.Errorf("failed to DoHeatMapStyleBodyJS() %w", err)
	}
	return heatmapTemplate.Execute(w, &StyleBodyJS{
		Style: style,
		Body:  body,
		JS:    js,
	})
}

// nolint: dupl
func DoSubsystemsHeatMap(w io.Writer, projectID, ns string, periods []coveragedb.TimePeriod) error {
	style, body, js, err := DoSubsystemsHeatMapStyleBodyJS(context.Background(), projectID, ns, "", periods)
	if err != nil {
		return fmt.Errorf("failed to DoSubsystemsHeatMapStyleBodyJS() %w", err)
	}
	return heatmapTemplate.Execute(w, &StyleBodyJS{
		Style: style,
		Body:  body,
		JS:    js,
	})
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

func DoHeatMapStyleBodyJS(ctx context.Context, projectID, ns, subsystem string, periods []coveragedb.TimePeriod,
) (template.CSS, template.HTML, template.HTML, error) {
	covAndDates, err := filesCoverageWithDetails(ctx, projectID, ns, subsystem, periods)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to filesCoverageWithDetails: %w", err)
	}
	templData := filesCoverageToTemplateData(covAndDates)
	return stylesBodyJSTemplate(templData)
}

func DoSubsystemsHeatMapStyleBodyJS(ctx context.Context, projectID, ns, subsystem string,
	periods []coveragedb.TimePeriod) (template.CSS, template.HTML, template.HTML, error) {
	covWithDetails, err := filesCoverageWithDetails(ctx, projectID, ns, subsystem, periods)
	if err != nil {
		panic(err)
	}
	var ssCovAndDates []*fileCoverageWithDetails
	for _, cwd := range covWithDetails {
		for _, ssName := range cwd.Subsystems {
			newRecord := fileCoverageWithDetails{
				Filepath:     cwd.Filepath,
				Subsystem:    ssName,
				Instrumented: cwd.Instrumented,
				Covered:      cwd.Covered,
				TimePeriod:   cwd.TimePeriod,
			}
			ssCovAndDates = append(ssCovAndDates, &newRecord)
		}
	}
	templData := filesCoverageToTemplateData(ssCovAndDates)
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
