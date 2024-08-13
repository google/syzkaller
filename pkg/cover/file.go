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

type lineRender func(string, bool, int, int) string

func RendFileCoverage(c context.Context, ns, repo, commit, filePath string,
	fromDate, toDate civil.Date, render lineRender) (string, error) {
	fileContent, err := covermerger.GetFileVersion(filePath, repo, commit)
	if err != nil {
		return "", fmt.Errorf("failed to GetFileVersion for file %s, commit %s from repo %s: %w",
			filePath, commit, repo, err)
	}
	config := &covermerger.Config{
		Jobs: 1,
		Base: covermerger.RepoBranchCommit{
			Repo:   repo,
			Commit: commit,
		},
		FileVersProvider: covermerger.MakeWebGit(),
	}

	dbReader := covermerger.MakeBQCSVReader()
	if err := dbReader.InitNsRecords(c,
		ns,
		filePath,
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

	return rendResult(fileContent, mergeResult[filePath], render), nil
}

func rendResult(content string, coverage *covermerger.MergeResult, render lineRender) string {
	srclines := strings.Split(content, "\n")
	var htmlLines []string
	for i, srcLine := range srclines {
		lineNum := i + 1
		covered, instrumented := coverage.HitCounts[lineNum]
		htmlLines = append(htmlLines, render(srcLine, instrumented, covered, lineNum))
	}
	return strings.Join(htmlLines, "\n")
}

func RendTextLine(code string, instrumented bool, covered, num int) string {
	covStr := fmt.Sprintf("%6d", covered)
	if !instrumented {
		covStr = strings.Repeat(" ", 6)
	}
	return fmt.Sprintf("%s %6d %s", covStr, num, code)
}
