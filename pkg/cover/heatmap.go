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

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
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
				fmt.Sprintf("/graph/coverage/file?dateto=%s&period=%s&commit=%s&filepath=%s",
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

type fileCoverageWithLineInfo struct {
	fileCoverageWithDetails
	LinesInstrumented []int64
	HitCounts         []int64
}

func (fc *fileCoverageWithLineInfo) CovMap() map[int]int64 {
	return MakeCovMap(fc.LinesInstrumented, fc.HitCounts)
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

func filesCoverageWithDetailsStmt(ns, subsystem, manager string, timePeriod coveragedb.TimePeriod, withLines bool,
) spanner.Statement {
	if manager == "" {
		manager = "*"
	}
	selectColumns := "commit, instrumented, covered, files.filepath, subsystems"
	if withLines {
		selectColumns += ", linesinstrumented, hitcounts"
	}
	stmt := spanner.Statement{
		SQL: "select " + selectColumns + `
from merge_history
  join files
    on merge_history.session = files.session
  join file_subsystems
    on merge_history.namespace = file_subsystems.namespace and files.filepath = file_subsystems.filepath
where
  merge_history.namespace=$1 and dateto=$2 and duration=$3 and manager=$4`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
			"p4": manager,
		},
	}
	if subsystem != "" {
		stmt.SQL += " and $5=ANY(subsystems)"
		stmt.Params["p5"] = subsystem
	}
	stmt.SQL += "\norder by files.filepath"
	return stmt
}

func readCoverage(iterManager spannerclient.RowIterator) ([]*fileCoverageWithDetails, error) {
	res := []*fileCoverageWithDetails{}
	ch := make(chan *fileCoverageWithDetails)
	var err error
	go func() {
		defer close(ch)
		err = readIterToChan(context.Background(), iterManager, ch)
	}()
	for fc := range ch {
		res = append(res, fc)
	}
	if err != nil {
		return nil, fmt.Errorf("readIterToChan: %w", err)
	}
	return res, nil
}

// Unique coverage from specific manager is more expensive to get.
// We get unique coverage comparing manager and total coverage on the AppEngine side.
func readCoverageUniq(full, mgr spannerclient.RowIterator,
) ([]*fileCoverageWithDetails, error) {
	eg, ctx := errgroup.WithContext(context.Background())
	fullCh := make(chan *fileCoverageWithLineInfo)
	eg.Go(func() error {
		defer close(fullCh)
		return readIterToChan(ctx, full, fullCh)
	})
	partCh := make(chan *fileCoverageWithLineInfo)
	eg.Go(func() error {
		defer close(partCh)
		return readIterToChan(ctx, mgr, partCh)
	})
	res := []*fileCoverageWithDetails{}
	eg.Go(func() error {
		partCov := <-partCh
		for fullCov := range fullCh {
			if partCov == nil || partCov.Filepath > fullCov.Filepath {
				// No pair for the file in full aggregation is available.
				cov := fullCov.fileCoverageWithDetails
				cov.Covered = 0
				res = append(res, &cov)
				continue
			}
			if partCov.Filepath == fullCov.Filepath {
				if partCov.Commit != fullCov.Commit ||
					!IsComparable(
						fullCov.LinesInstrumented, fullCov.HitCounts,
						partCov.LinesInstrumented, partCov.HitCounts) {
					return fmt.Errorf("db record for file %s doesn't match", fullCov.Filepath)
				}
				resItem := fullCov.fileCoverageWithDetails // Use Instrumented count from full aggregation.
				resItem.Covered = 0
				for _, hc := range UniqCoverage(fullCov.CovMap(), partCov.CovMap()) {
					if hc > 0 {
						resItem.Covered++
					}
				}
				res = append(res, &resItem)
				partCov = <-partCh
				continue
			}
			// Partial coverage is a subset of full coverage.
			// File can't exist only in partial set.
			return fmt.Errorf("currupted db, file %s can't exist", partCov.Filepath)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("eg.Wait: %w", err)
	}
	return res, nil
}

func MakeCovMap(keys, vals []int64) map[int]int64 {
	res := map[int]int64{}
	for i, key := range keys {
		res[int(key)] = vals[i]
	}
	return res
}

func IsComparable(fullLines, fullHitCounts, partialLines, partialHitCounts []int64) bool {
	if len(fullLines) != len(fullHitCounts) ||
		len(partialLines) != len(partialHitCounts) ||
		len(fullLines) < len(partialLines) {
		return false
	}
	fullCov := MakeCovMap(fullLines, fullHitCounts)
	for iPartial, ln := range partialLines {
		partialHitCount := partialHitCounts[iPartial]
		if fullHitCount, fullExist := fullCov[int(ln)]; !fullExist || fullHitCount < partialHitCount {
			return false
		}
	}
	return true
}

// Returns partial hitcounts that are the only source of the full hitcounts.
func UniqCoverage(fullCov, partCov map[int]int64) map[int]int64 {
	res := maps.Clone(partCov)
	for ln := range partCov {
		if partCov[ln] != fullCov[ln] {
			res[ln] = 0
		}
	}
	return res
}

func readIterToChan[K fileCoverageWithLineInfo | fileCoverageWithDetails](
	ctx context.Context, iter spannerclient.RowIterator, ch chan<- *K) error {
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("iter.Next: %w", err)
		}
		var r K
		if err = row.ToStruct(&r); err != nil {
			return fmt.Errorf("row.ToStruct: %w", err)
		}
		select {
		case ch <- &r:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func filesCoverageWithDetails(
	ctx context.Context, client spannerclient.SpannerClient, scope *SelectScope, onlyUnique bool,
) ([]*fileCoverageWithDetails, error) {
	var res []*fileCoverageWithDetails
	for _, timePeriod := range scope.Periods {
		needLinesDetails := onlyUnique
		iterManager := client.Single().Query(ctx,
			filesCoverageWithDetailsStmt(scope.Ns, scope.Subsystem, scope.Manager, timePeriod, needLinesDetails))
		defer iterManager.Stop()

		var err error
		var periodRes []*fileCoverageWithDetails
		if onlyUnique {
			iterAll := client.Single().Query(ctx,
				filesCoverageWithDetailsStmt(scope.Ns, scope.Subsystem, "", timePeriod, needLinesDetails))
			defer iterAll.Stop()
			periodRes, err = readCoverageUniq(iterAll, iterManager)
			if err != nil {
				return nil, fmt.Errorf("uniqueFilesCoverageWithDetails: %w", err)
			}
		} else {
			periodRes, err = readCoverage(iterManager)
			if err != nil {
				return nil, fmt.Errorf("readCoverage: %w", err)
			}
		}
		for _, r := range periodRes {
			r.TimePeriod = timePeriod
		}
		res = append(res, periodRes...)
	}
	return res, nil
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

type SelectScope struct {
	Ns        string
	Subsystem string
	Manager   string
	Periods   []coveragedb.TimePeriod
}

func DoHeatMapStyleBodyJS(
	ctx context.Context, client spannerclient.SpannerClient, scope *SelectScope, onlyUnique bool, sss, managers []string,
) (template.CSS, template.HTML, template.HTML, error) {
	covAndDates, err := filesCoverageWithDetails(ctx, client, scope, onlyUnique)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to filesCoverageWithDetails: %w", err)
	}
	templData := filesCoverageToTemplateData(covAndDates)
	templData.Subsystems = sss
	templData.Managers = managers
	return stylesBodyJSTemplate(templData)
}

func DoSubsystemsHeatMapStyleBodyJS(
	ctx context.Context, client spannerclient.SpannerClient, scope *SelectScope, onlyUnique bool, sss, managers []string,
) (template.CSS, template.HTML, template.HTML, error) {
	covWithDetails, err := filesCoverageWithDetails(ctx, client, scope, onlyUnique)
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
				Commit:       cwd.Commit,
			}
			ssCovAndDates = append(ssCovAndDates, &newRecord)
		}
	}
	templData := filesCoverageToTemplateData(ssCovAndDates)
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
