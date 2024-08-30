// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"context"
	"fmt"
	"html"
	"strings"

	"cloud.google.com/go/civil"
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

func RendFileCoverage(c context.Context, ns, repo, forCommit, sourceCommit, filePath string,
	proxy covermerger.FuncProxyURI,
	fromDate, toDate civil.Date, renderConfig *CoverageRenderConfig) (string, error) {
	fileContent, err := covermerger.GetFileVersion(filePath, repo, forCommit)
	if err != nil {
		return "", fmt.Errorf("failed to GetFileVersion for file %s, commit %s from repo %s: %w",
			filePath, forCommit, repo, err)
	}
	config := &covermerger.Config{
		Jobs: 1,
		Base: covermerger.RepoCommit{
			Repo:   repo,
			Commit: forCommit,
		},
		FileVersProvider: covermerger.MakeWebGit(proxy),
		StoreDetails:     true,
	}

	dbReader := covermerger.MakeBQCSVReader()
	if err := dbReader.InitNsRecords(c,
		ns,
		filePath,
		sourceCommit,
		fromDate,
		toDate,
	); err != nil {
		return "", fmt.Errorf("failed to dbReader.InitNsRecords: %w", err)
	}
	defer dbReader.Close()
	csvReader, err := dbReader.Reader()
	if err != nil {
		return "", fmt.Errorf("failed to dbReader.Reader: %w", err)
	}

	mergeResult, err := covermerger.MergeCSVData(config, csvReader)
	if err != nil {
		return "", fmt.Errorf("error merging coverage: %w", err)
	}
	if _, exist := mergeResult[filePath]; !exist {
		return "", fmt.Errorf("no merge result for file %s(fileSize %d)", filePath, len(fileContent))
	}

	return rendResult(fileContent, mergeResult[filePath], renderConfig), nil
}

func rendResult(content string, coverage *covermerger.MergeResult, renderConfig *CoverageRenderConfig) string {
	if coverage == nil {
		coverage = &covermerger.MergeResult{
			HitCounts:   map[int]int{},
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
