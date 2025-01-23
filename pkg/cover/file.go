// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"context"
	"fmt"
	"html"
	"strings"

	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/covermerger"
)

type lineRender func(string, int, *covermerger.MergeResult, *CoverageRenderConfig) string

type CoverageRenderConfig struct {
	RendLine                  lineRender
	ShowLineCoverage          bool
	ShowLineNumbers           bool
	ShowLineSourceExplanation bool
}

func DefaultTextRenderConfig() *CoverageRenderConfig {
	return &CoverageRenderConfig{
		RendLine:                  RendTextLine,
		ShowLineCoverage:          true,
		ShowLineNumbers:           true,
		ShowLineSourceExplanation: false,
	}
}

func DefaultHTMLRenderConfig() *CoverageRenderConfig {
	return &CoverageRenderConfig{
		RendLine:                  RendHTMLLine,
		ShowLineCoverage:          true,
		ShowLineNumbers:           true,
		ShowLineSourceExplanation: false,
	}
}

func RendFileCoverage(repo, forCommit, filePath string, fileProvider covermerger.FileVersProvider,
	mr *covermerger.MergeResult, renderConfig *CoverageRenderConfig) (string, error) {
	repoCommit := covermerger.RepoCommit{Repo: repo, Commit: forCommit}
	files, err := fileProvider.GetFileVersions(filePath, repoCommit)
	if err != nil {
		return "", fmt.Errorf("failed to GetFileVersions: %w", err)
	}
	return rendResult(files[repoCommit], mr, renderConfig), nil
}

func GetMergeResult(c context.Context, ns, repo, forCommit, sourceCommit, filePath string,
	proxy covermerger.FuncProxyURI, tp coveragedb.TimePeriod) (*covermerger.MergeResult, error) {
	config := &covermerger.Config{
		Jobs: 1,
		Base: covermerger.RepoCommit{
			Repo:   repo,
			Commit: forCommit,
		},
		FileVersProvider: covermerger.MakeWebGit(proxy),
	}

	fromDate, toDate := tp.DatesFromTo()
	dbReader := covermerger.MakeBQCSVReader()
	if err := dbReader.InitNsRecords(c,
		ns,
		filePath,
		sourceCommit,
		fromDate,
		toDate,
	); err != nil {
		return nil, fmt.Errorf("failed to dbReader.InitNsRecords: %w", err)
	}
	defer dbReader.Close()
	csvReader, err := dbReader.Reader()
	if err != nil {
		return nil, fmt.Errorf("failed to dbReader.Reader: %w", err)
	}

	ch := make(chan *covermerger.FileMergeResult, 1)
	if err := covermerger.MergeCSVData(c, config, csvReader, ch); err != nil {
		return nil, fmt.Errorf("error merging coverage: %w", err)
	}

	var mr *covermerger.MergeResult
	select {
	case fmr := <-ch:
		if fmr != nil {
			mr = fmr.MergeResult
		}
	default:
	}

	if mr != nil {
		return nil, fmt.Errorf("no merge result for file %s", filePath)
	}
	return mr, nil
}

func rendResult(content string, coverage *covermerger.MergeResult, renderConfig *CoverageRenderConfig) string {
	if coverage == nil {
		coverage = &covermerger.MergeResult{
			HitCounts:   map[int]int64{},
			LineDetails: map[int][]*covermerger.FileRecord{},
		}
	}
	srcLines := strings.Split(content, "\n")
	var resLines []string
	for i, srcLine := range srcLines {
		resLines = append(resLines, renderConfig.RendLine(srcLine, i+1, coverage, renderConfig))
	}
	return strings.Join(resLines, "\n")
}

func RendTextLine(code string, line int, coverage *covermerger.MergeResult, config *CoverageRenderConfig) string {
	res := ""
	if config.ShowLineSourceExplanation {
		explanation := ""
		lineDetails, exist := coverage.LineDetails[line]
		if exist {
			explanation = fmt.Sprintf("(%d)%s ", len(lineDetails), mainSignalSource(lineDetails))
		}
		res += fmt.Sprintf("%50s", explanation)
	}
	covered, instrumented := coverage.HitCounts[line]
	if config.ShowLineCoverage {
		covStr := fmt.Sprintf("%6d", covered)
		if !instrumented {
			covStr = strings.Repeat(" ", 6)
		}
		res += fmt.Sprintf("%s ", covStr)
	}
	if config.ShowLineNumbers {
		res += fmt.Sprintf("%6d ", line)
	}
	res += code
	return res
}

func RendHTMLLine(code string, line int, coverage *covermerger.MergeResult, config *CoverageRenderConfig) string {
	textLine := RendTextLine(code, line, coverage, config)
	return `<pre style="margin: 0">` + html.EscapeString(textLine) + "</pre>"
}

func mainSignalSource(sources []*covermerger.FileRecord) string {
	res := ""
	prevMax := -1
	for _, source := range sources {
		if source.HitCount > prevMax {
			prevMax = source.HitCount
			res = fmt.Sprintf("%s:%d", source.Commit, source.StartLine)
		}
	}
	return res
}
