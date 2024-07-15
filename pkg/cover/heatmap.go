// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/spanner/coveragedb"
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

	builder      map[string]*templateHeatmapRow
	instrumented map[civil.Date]int64
	covered      map[civil.Date]int64
}

type templateHeatmap struct {
	Root  *templateHeatmapRow
	Dates []string
}

func (thm *templateHeatmapRow) addParts(depth int, pathLeft []string, instrumented, covered int64, dateto civil.Date) {
	thm.instrumented[dateto] += instrumented
	thm.covered[dateto] += covered
	if len(pathLeft) == 0 {
		return
	}
	nextElement := pathLeft[0]
	isDir := len(pathLeft) > 1
	if _, ok := thm.builder[nextElement]; !ok {
		thm.builder[nextElement] = &templateHeatmapRow{
			Name:         nextElement,
			Depth:        depth,
			IsDir:        isDir,
			builder:      make(map[string]*templateHeatmapRow),
			instrumented: make(map[civil.Date]int64),
			covered:      make(map[civil.Date]int64),
		}
	}
	thm.builder[nextElement].addParts(depth+1, pathLeft[1:], instrumented, covered, dateto)
}

func (thm *templateHeatmapRow) prepareDataFor(dates []civil.Date) {
	thm.Items = maps.Values(thm.builder)
	sort.Slice(thm.Items, func(i, j int) bool {
		if thm.Items[i].IsDir != thm.Items[j].IsDir {
			return thm.Items[i].IsDir
		}
		return thm.Items[i].Name < thm.Items[j].Name
	})
	for _, d := range dates {
		var dateCoverage int64
		if thm.instrumented[d] != 0 {
			dateCoverage = 100 * thm.covered[d] / thm.instrumented[d]
		}
		thm.Coverage = append(thm.Coverage, dateCoverage)
	}
	if len(dates) > 0 {
		lastDate := dates[len(dates)-1]
		thm.LastDayInstrumented = thm.instrumented[lastDate]
	}
	for _, item := range thm.builder {
		item.prepareDataFor(dates)
	}
}

type fileCoverageAndDate struct {
	Filepath     string
	Instrumented int64
	Covered      int64
	Dateto       civil.Date
}

func filesCoverageToTemplateData(fCov []*fileCoverageAndDate) *templateHeatmap {
	res := templateHeatmap{
		Root: &templateHeatmapRow{
			builder:      map[string]*templateHeatmapRow{},
			instrumented: map[civil.Date]int64{},
			covered:      map[civil.Date]int64{},
		},
	}
	dates := map[civil.Date]struct{}{}
	for _, fc := range fCov {
		res.Root.addParts(
			0,
			strings.Split(fc.Filepath, "/"),
			fc.Instrumented,
			fc.Covered,
			fc.Dateto)
		dates[fc.Dateto] = struct{}{}
	}
	sortedDates := maps.Keys(dates)
	sort.Slice(sortedDates, func(i, j int) bool {
		return sortedDates[i].Before(sortedDates[j])
	})
	for _, d := range sortedDates {
		res.Dates = append(res.Dates, d.String())
	}

	res.Root.prepareDataFor(sortedDates)
	return &res
}

func filesCoverageAndDates(ctx context.Context, projectID, ns string, fromDate, toDate civil.Date,
) ([]*fileCoverageAndDate, error) {
	client, err := coveragedb.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("spanner.NewClient() failed: %s", err.Error())
	}
	defer client.Close()

	stmt := spanner.Statement{
		SQL: `
select
  dateto,
  instrumented,
  covered,
  filepath
from merge_history join files
  on merge_history.session = files.session
where namespace=$1 and dateto>=$2 and dateto<=$3
`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": fromDate,
			"p3": toDate,
		},
	}

	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	res := []*fileCoverageAndDate{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iter.Next() spanner DB: %w", err)
		}
		var r fileCoverageAndDate
		if err = row.ToStruct(&r); err != nil {
			return nil, fmt.Errorf("failed to row.ToStruct() spanner DB: %w", err)
		}
		res = append(res, &r)
	}
	return res, nil
}

func DoHeatMap(w io.Writer, projectID, ns string, dateFrom, dateTo civil.Date) error {
	covAndDates, err := filesCoverageAndDates(context.Background(), projectID, ns, dateFrom, dateTo)
	if err != nil {
		panic(err)
	}
	templateData := filesCoverageToTemplateData(covAndDates)
	return heatmapTemplate.Execute(w, templateData)
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
