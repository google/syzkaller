// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/covermerger"
)

type lineRender func(string, int, *covermerger.MergeResult, *CoverageRenderConfig) string

type CoverageRenderConfig struct {
	Render                    lineRender
	ShowLineCoverage          bool
	ShowLineNumbers           bool
	ShowLineSourceExplanation bool
}

func DefaultTextRenderConfig() *CoverageRenderConfig {
	return &CoverageRenderConfig{
		Render:                    RendTextLine,
		ShowLineCoverage:          true,
		ShowLineNumbers:           true,
		ShowLineSourceExplanation: false,
	}
}

func RendFileCoverage(c context.Context, ns, repo, forCommit, sourceCommit, filePath string,
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
		FileVersProvider: covermerger.MakeWebGit(),
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

	return rendResult(fileContent, mergeResult[filePath], renderConfig), nil
}

func rendResult(content string, coverage *covermerger.MergeResult, renderConfig *CoverageRenderConfig) string {
	srcLines := strings.Split(content, "\n")
	var htmlLines []string
	for i, srcLine := range srcLines {
		htmlLines = append(htmlLines, renderConfig.Render(srcLine, i+1, coverage, renderConfig))
	}
	return strings.Join(htmlLines, "\n")
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
