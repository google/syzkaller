// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"cloud.google.com/go/spanner"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
)

type TargetFilter struct {
	Prefixes []string
	Limit    int
}

type CoverageTargets struct {
	KernelRepo   string              `json:"kernel_repo"`
	KernelCommit string              `json:"kernel_commit"`
	Targets      []UncoveredFunction `json:"targets"`
}

type UncoveredFunction struct {
	FilePath   string  `json:"file_path"`
	FuncName   string  `json:"func_name"`
	HasCovered bool    `json:"has_covered"`
	Lines      []int64 `json:"lines"`
}

type latestMergeHistoryRow struct {
	Session string
	Repo    string
	Commit  string
}

type targetFileRow struct {
	FilePath          string
	LinesInstrumented []int64
	HitCounts         []int64
}

// GetCoverageTargets queries the latest aggregated coverage session and returns uncovered functions
// located in files that have partial coverage, optionally filtered by path prefixes and capped by limit.
func GetCoverageTargets(ctx context.Context, client *spanner.Client, ns string,
	filter TargetFilter) (*CoverageTargets, error) {
	if client == nil {
		return nil, fmt.Errorf("nil spanner client")
	}
	history, err := queryLatestMergeHistory(ctx, client, ns)
	if err != nil {
		return nil, fmt.Errorf("queryLatestMergeHistory: %w", err)
	}
	if history == nil {
		return &CoverageTargets{Targets: []UncoveredFunction{}}, nil
	}

	files, err := queryPartiallyCoveredFiles(ctx, client, history.Session, filter.Prefixes)
	if err != nil {
		return nil, fmt.Errorf("queryPartiallyCoveredFiles: %w", err)
	}
	if len(files) == 0 {
		return &CoverageTargets{
			KernelRepo:   history.Repo,
			KernelCommit: history.Commit,
			Targets:      []UncoveredFunction{},
		}, nil
	}

	funcs, err := queryFunctions(ctx, client, history.Session, filter.Prefixes)
	if err != nil {
		return nil, fmt.Errorf("queryFunctions: %w", err)
	}

	fileCovered := make(map[string]map[int64]bool, len(files))
	for _, f := range files {
		if len(f.LinesInstrumented) != len(f.HitCounts) {
			continue
		}
		covered := make(map[int64]bool)
		for i, hits := range f.HitCounts {
			if hits > 0 {
				covered[f.LinesInstrumented[i]] = true
			}
		}
		fileCovered[f.FilePath] = covered
	}

	candidates := []UncoveredFunction{}
	for _, fn := range funcs {
		covered, ok := fileCovered[fn.FilePath]
		if !ok {
			continue
		}
		hasCovered := false
		var uncovered []int64
		for _, l := range fn.Lines {
			if covered[l] {
				hasCovered = true
			} else {
				uncovered = append(uncovered, l)
			}
		}
		if len(uncovered) == 0 {
			continue
		}
		slices.Sort(uncovered)
		candidates = append(candidates, UncoveredFunction{
			FilePath:   fn.FilePath,
			FuncName:   fn.FuncName,
			HasCovered: hasCovered,
			Lines:      slices.Compact(uncovered),
		})
	}

	slices.SortFunc(candidates, func(a, b UncoveredFunction) int {
		return cmp.Or(
			cmp.Compare(a.FilePath, b.FilePath),
			cmp.Compare(a.FuncName, b.FuncName),
		)
	})

	if filter.Limit > 0 && len(candidates) > filter.Limit {
		candidates = candidates[:filter.Limit]
	}

	return &CoverageTargets{
		KernelRepo:   history.Repo,
		KernelCommit: history.Commit,
		Targets:      candidates,
	}, nil
}

func queryLatestMergeHistory(ctx context.Context, client *spanner.Client, ns string) (*latestMergeHistoryRow, error) {
	rows, err := queryRows[latestMergeHistoryRow](ctx, client, `
SELECT session, repo, commit
FROM merge_history
WHERE namespace = $1
ORDER BY dateto DESC, duration DESC
LIMIT 1`, map[string]any{"p1": ns})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func queryPartiallyCoveredFiles(ctx context.Context, client *spanner.Client, session string,
	prefixes []string) ([]*targetFileRow, error) {
	params := map[string]any{"p1": session}
	sql := `
SELECT filepath, linesinstrumented, hitcounts
FROM files
WHERE session = $1 AND manager = '*' AND covered > 0 AND covered < instrumented` + prefixClause(prefixes, params)
	return queryRows[targetFileRow](ctx, client, sql, params)
}

func queryFunctions(ctx context.Context, client *spanner.Client, session string,
	prefixes []string) ([]*FuncLines, error) {
	params := map[string]any{"p1": session}
	sql := `
SELECT filepath, funcname, lines
FROM functions
WHERE session = $1` + prefixClause(prefixes, params)
	return queryRows[FuncLines](ctx, client, sql, params)
}

func queryRows[T any](ctx context.Context, client *spanner.Client, sql string, params map[string]any) ([]*T, error) {
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL:    sql,
		Params: params,
	})
	defer iter.Stop()
	return pkgspanner.ReadRows[T](iter)
}

func prefixClause(prefixes []string, params map[string]any) string {
	if len(prefixes) == 0 {
		return ""
	}
	baseIdx := len(params)
	conds := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		idx := baseIdx + i + 1
		conds[i] = fmt.Sprintf("starts_with(filepath, $%d)", idx)
		params[fmt.Sprintf("p%d", idx)] = prefix
	}
	return " AND (" + strings.Join(conds, " OR ") + ")"
}
