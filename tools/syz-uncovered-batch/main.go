// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-uncovered-batch extracts candidate uncovered target functions from syzkaller
// coverage JSONL streams and outputs named input.json task files for syz-aflow batch execution.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand/v2"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/html/urlutil"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

type uncoveredTarget struct {
	ID         string
	FilePath   string
	LineNumber int
}

type filterConfig struct {
	paths               []string
	excludePaths        []string
	filePattern         *regexp.Regexp
	funcPattern         *regexp.Regexp
	excludeFuncPattern  *regexp.Regexp
	excludeInit         bool
	includeCoveredFuncs bool
	limit               int
	rng                 *rand.Rand
}

func main() {
	var (
		flagDashboard          = flag.String("dashboard", "https://syzbot.org", "dashboard URL")
		flagNamespace          = flag.String("namespace", "upstream", "dashboard namespace")
		flagManager            = flag.String("manager", "", "filter coverage by manager name")
		flagPeriod             = flag.String("period", "month", "coverage period (day, month, quarter)")
		flagBase               = flag.String("base", "", "base config JSON file (VM, image, etc.)")
		flagOutputDir          = flag.String("output-dir", "", "directory to write generated task input JSON files")
		flagIncludePaths       = flag.String("include-paths", "", "comma-separated path prefixes to include")
		flagExcludePaths       = flag.String("exclude-paths", "", "comma-separated path prefixes to exclude")
		flagFilePattern        = flag.String("file-pattern", `.*\.c$`, "regular expression to match source file names")
		flagFuncPattern        = flag.String("func-pattern", "", "regular expression to match function names")
		flagExcludeFuncPattern = flag.String("exclude-func-pattern", "", "regular expression of function names to exclude")
		flagExcludeInit        = flag.Bool("exclude-init", true,
			"exclude kernel initialization functions (e.g. *_init, init_*, *_setup)")
		flagIncludeCoveredFuncs = flag.Bool("include-covered-funcs", false, "consider functions that already have coverage")
		flagLimit               = flag.Int("limit", 0, "maximum number of sampled targets (0 = unlimited)")
	)
	defer tool.Init()()

	if *flagOutputDir == "" {
		tool.Failf("-output-dir must be specified")
	}

	var baseInputs map[string]any
	if *flagBase != "" {
		var err error
		baseInputs, err = osutil.ReadJSON[map[string]any](*flagBase)
		if err != nil {
			tool.Failf("failed to read -base config file %q: %v", *flagBase, err)
		}
	}

	includePaths := parsePathList(*flagIncludePaths)
	covURL := fmt.Sprintf("%s/%s/coverage?jsonl=1&period=%s",
		strings.TrimRight(*flagDashboard, "/"), *flagNamespace, *flagPeriod)
	covURL = urlutil.SetParam(covURL, "manager", *flagManager)
	if len(includePaths) == 1 {
		covURL = urlutil.SetParam(covURL, "filepath", includePaths[0])
	}
	reader, err := fetchCoverage(covURL)
	if err != nil {
		tool.Fail(err)
	}
	defer reader.Close()

	repo, commit, targets, err := extractUncoveredTargets(reader, filterConfig{
		paths:               includePaths,
		excludePaths:        parsePathList(*flagExcludePaths),
		filePattern:         compileFlagRegexp("-file-pattern", *flagFilePattern),
		funcPattern:         compileFlagRegexp("-func-pattern", *flagFuncPattern),
		excludeFuncPattern:  compileFlagRegexp("-exclude-func-pattern", *flagExcludeFuncPattern),
		excludeInit:         *flagExcludeInit,
		includeCoveredFuncs: *flagIncludeCoveredFuncs,
		limit:               *flagLimit,
		rng:                 rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	})
	if err != nil {
		tool.Fail(err)
	}

	if err := generateTaskFiles(*flagOutputDir, baseInputs, repo, commit, targets); err != nil {
		tool.Fail(err)
	}
	log.Printf("generated %d tasks in %s", len(targets), *flagOutputDir)
}

func compileFlagRegexp(name, pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		tool.Failf("invalid %s regular expression %q: %v", name, pattern, err)
	}
	return re
}

func parsePathList(s string) []string {
	var res []string
	for p := range strings.SplitSeq(s, ",") {
		p = strings.Trim(path.Clean(strings.TrimSpace(p)), "/")
		if p != "" && p != "." {
			res = append(res, p)
		}
	}
	return res
}

func matchesPrefix(filePath string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool {
		return filePath == p || strings.HasPrefix(filePath, p+"/")
	})
}

func taskID(filePath, funcName string, line int) string {
	clean := strings.ReplaceAll(filePath, "/", "_")
	if funcName != "" {
		return fmt.Sprintf("%s_%s_%d", clean, funcName, line)
	}
	return fmt.Sprintf("%s_%d", clean, line)
}

func fetchCoverage(url string) (io.ReadCloser, error) {
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %s from %s", resp.Status, url)
	}
	return resp.Body, nil
}

func extractUncoveredTargets(r io.Reader, cfg filterConfig) (
	repo, commit string, targets []uncoveredTarget, err error,
) {
	dec := json.NewDecoder(r)
	var (
		candidates []uncoveredTarget
		seenIDs    = make(map[string]bool)
	)

	for {
		var fc cover.FileCoverage
		if err := dec.Decode(&fc); err != nil {
			if err == io.EOF {
				break
			}
			return "", "", nil, fmt.Errorf("failed to decode coverage JSONL: %w", err)
		}

		if repo == "" {
			repo = fc.Repo
		}
		if commit == "" {
			commit = fc.Commit
		}

		cleanFilePath := strings.TrimPrefix(path.Clean(fc.FilePath), "/")
		if cleanFilePath == "" || cleanFilePath == "." || !cfg.matchFile(cleanFilePath) {
			continue
		}

		for _, fn := range fc.Functions {
			if fn == nil {
				continue
			}
			target := cfg.extractTarget(cleanFilePath, fn)
			if target == nil || seenIDs[target.ID] {
				continue
			}
			seenIDs[target.ID] = true
			candidates = append(candidates, *target)
		}
	}

	cfg.rng.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	if cfg.limit > 0 && len(candidates) > cfg.limit {
		candidates = candidates[:cfg.limit]
	}
	return repo, commit, candidates, nil
}

func generateTaskFiles(outputDir string, baseInputs map[string]any, repo, commit string,
	targets []uncoveredTarget) error {
	if err := osutil.MkdirAll(outputDir); err != nil {
		return err
	}
	base := maps.Clone(baseInputs)
	if base == nil {
		base = make(map[string]any)
	}
	if _, ok := base["KernelRepo"]; !ok && repo != "" {
		base["KernelRepo"] = repo
	}
	if _, ok := base["KernelCommit"]; !ok && commit != "" {
		base["KernelCommit"] = commit
	}
	for _, t := range targets {
		inputs := maps.Clone(base)
		inputs["FilePath"] = t.FilePath
		inputs["LineNumber"] = t.LineNumber
		taskPath := filepath.Join(outputDir, t.ID+".json")
		if err := osutil.WriteJSON(taskPath, inputs); err != nil {
			return fmt.Errorf("failed to write %s: %w", taskPath, err)
		}
	}
	return nil
}

func (cfg *filterConfig) matchFile(path string) bool {
	if len(cfg.paths) > 0 && !matchesPrefix(path, cfg.paths) {
		return false
	}
	if matchesPrefix(path, cfg.excludePaths) {
		return false
	}
	if cfg.filePattern != nil && !cfg.filePattern.MatchString(path) {
		return false
	}
	return true
}

var initFuncRe = regexp.MustCompile(`(?i)(^|_)(init|setup)($|_)`)

func (cfg *filterConfig) matchFunc(name string) bool {
	if cfg.excludeInit && initFuncRe.MatchString(name) {
		return false
	}
	if cfg.excludeFuncPattern != nil && cfg.excludeFuncPattern.MatchString(name) {
		return false
	}
	if cfg.funcPattern != nil && !cfg.funcPattern.MatchString(name) {
		return false
	}
	return true
}

func (cfg *filterConfig) extractTarget(filePath string, fn *cover.FuncCoverage) *uncoveredTarget {
	if fn == nil || len(fn.Blocks) == 0 || !cfg.matchFunc(fn.FuncName) {
		return nil
	}
	var uncovered []*cover.Block
	for _, b := range fn.Blocks {
		if b == nil {
			continue
		}
		if b.HitCount > 0 {
			if !cfg.includeCoveredFuncs {
				return nil
			}
			continue
		}
		if b.FromLine > 0 {
			uncovered = append(uncovered, b)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}
	b := uncovered[cfg.rng.IntN(len(uncovered))]
	return &uncoveredTarget{
		ID:         taskID(filePath, fn.FuncName, b.FromLine),
		FilePath:   filePath,
		LineNumber: b.FromLine,
	}
}
