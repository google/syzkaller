// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"context"
	"fmt"
	"html"
	"strings"

	"github.com/google/syzkaller/pkg/coveragedb"
)

type lineRender func(string, int, *MergeResult, *CoverageRenderConfig) string

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

func RendFileCoverage(repo, forCommit, filePath string, fileProvider FileVersProvider,
	mr *MergeResult, renderConfig *CoverageRenderConfig) (string, error) {
	repoCommit := RepoCommit{Repo: repo, Commit: forCommit}
	files, err := fileProvider.GetFileVersions(filePath, repoCommit)
	if err != nil {
		return "", fmt.Errorf("failed to GetFileVersions: %w", err)
	}
	return rendResult(files[repoCommit], mr, renderConfig), nil
}

// GetMergeResult returns the merge result.
// nolint:revive
func GetMergeResult(ctx context.Context, ns, repo, forCommit, sourceCommit, filePath string,
	proxy FuncProxyURI, tp coveragedb.TimePeriod) (*MergeResult, error) {
	config := &Config{
		Jobs: 1,
		Base: RepoCommit{
			Repo:   repo,
			Commit: forCommit,
		},
		FileVersProvider: MakeWebGit(proxy),
	}

	fromDate, toDate := tp.DatesFromTo()
	csvReader, err := InitNsRecords(ctx, ns, filePath, sourceCommit, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("failed to InitNsRecords: %w", err)
	}
	defer csvReader.Close()

	ch := make(chan *FileMergeResult, 1)
	if err := MergeCSVData(ctx, config, csvReader, ch); err != nil {
		return nil, fmt.Errorf("error merging coverage: %w", err)
	}

	var mr *MergeResult
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

func rendResult(content string, coverage *MergeResult, renderConfig *CoverageRenderConfig) string {
	if coverage == nil {
		coverage = &MergeResult{
			HitCounts:   map[int]int64{},
			LineDetails: map[int][]*FileRecord{},
		}
	}
	srcLines := strings.Split(content, "\n")
	var resLines []string
	for i, srcLine := range srcLines {
		resLines = append(resLines, renderConfig.RendLine(srcLine, i+1, coverage, renderConfig))
	}
	return strings.Join(resLines, "\n")
}

func RendTextLine(code string, line int, coverage *MergeResult, config *CoverageRenderConfig) string {
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

func RendHTMLLine(code string, line int, coverage *MergeResult, config *CoverageRenderConfig) string {
	textLine := RendTextLine(code, line, coverage, config)
	return `<pre style="margin: 0">` + html.EscapeString(textLine) + "</pre>"
}

func mainSignalSource(sources []*FileRecord) string {
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
