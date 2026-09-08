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
	"math/rand"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

var (
	flagDashboard          = flag.String("dashboard", "https://syzbot.org", "dashboard URL")
	flagNamespace          = flag.String("namespace", "upstream", "dashboard namespace")
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

type UncoveredTarget struct {
	ID         string
	FilePath   string
	LineNumber int
	FuncName   string
}

type FilterConfig struct {
	Paths               []string
	ExcludePaths        []string
	FilePattern         *regexp.Regexp
	FuncPattern         *regexp.Regexp
	ExcludeFuncPattern  *regexp.Regexp
	ExcludeInit         bool
	IncludeCoveredFuncs bool
	Limit               int
	Rand                *rand.Rand
}

func main() {
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

	covURL := fmt.Sprintf("%s/%s/coverage?jsonl=1&period=%s",
		strings.TrimRight(*flagDashboard, "/"), *flagNamespace, *flagPeriod)
	reader, err := fetchCoverage(covURL)
	if err != nil {
		tool.Fail(err)
	}
	defer reader.Close()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	repo, commit, targets, err := ExtractUncoveredTargets(reader, FilterConfig{
		Paths:               parsePathList(*flagIncludePaths),
		ExcludePaths:        parsePathList(*flagExcludePaths),
		FilePattern:         compileFlagRegexp("-file-pattern", *flagFilePattern),
		FuncPattern:         compileFlagRegexp("-func-pattern", *flagFuncPattern),
		ExcludeFuncPattern:  compileFlagRegexp("-exclude-func-pattern", *flagExcludeFuncPattern),
		ExcludeInit:         *flagExcludeInit,
		IncludeCoveredFuncs: *flagIncludeCoveredFuncs,
		Limit:               *flagLimit,
		Rand:                rng,
	})
	if err != nil {
		tool.Fail(err)
	}

	if err := GenerateTaskFiles(*flagOutputDir, baseInputs, repo, commit, targets); err != nil {
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
		if p = strings.Trim(strings.TrimSpace(p), "/"); p != "" {
			res = append(res, p)
		}
	}
	return res
}

func matchesPrefix(filePath string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool {
		p = strings.TrimSuffix(p, "/")
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

type funcCandidate struct {
	filePath string
	funcName string
	blocks   []*cover.Block
}

func ExtractUncoveredTargets(r io.Reader, cfg FilterConfig) (
	repo, commit string, targets []UncoveredTarget, err error,
) {
	dec := json.NewDecoder(r)
	var (
		candidates []funcCandidate
		seenFuncs  = make(map[string]struct{})
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

		cleanFilePath := path.Clean(fc.FilePath)
		if !cfg.matchFile(cleanFilePath) {
			continue
		}

		for _, fn := range fc.Functions {
			if fn == nil {
				continue
			}
			funcKey := cleanFilePath + ":" + fn.FuncName
			if _, ok := seenFuncs[funcKey]; ok {
				continue
			}
			blocks := cfg.uncoveredBlocks(fn)
			if len(blocks) == 0 {
				continue
			}
			seenFuncs[funcKey] = struct{}{}
			shuffle(cfg.Rand, blocks)
			candidates = append(candidates, funcCandidate{
				filePath: cleanFilePath,
				funcName: fn.FuncName,
				blocks:   blocks,
			})
		}
	}

	shuffle(cfg.Rand, candidates)

	// Two blocks of the same function may well resolve to the same line, so the
	// resulting IDs still need to be deduplicated.
	seenIDs := make(map[string]struct{})
	maxBlocks := 0
	for _, c := range candidates {
		maxBlocks = max(maxBlocks, len(c.blocks))
	}
	// Take one block from every function, then a second one from the functions
	// that still have blocks left, and so on, until we run out of either blocks
	// or the requested number of targets.
	for pass := range maxBlocks {
		for _, c := range candidates {
			if pass >= len(c.blocks) {
				continue
			}
			line := pickLine(c.blocks[pass], cfg.Rand)
			id := taskID(c.filePath, c.funcName, line)
			if _, ok := seenIDs[id]; ok {
				continue
			}
			seenIDs[id] = struct{}{}
			targets = append(targets, UncoveredTarget{
				ID:         id,
				FilePath:   c.filePath,
				LineNumber: line,
				FuncName:   c.funcName,
			})
			if cfg.Limit > 0 && len(targets) >= cfg.Limit {
				return repo, commit, targets, nil
			}
		}
	}
	return repo, commit, targets, nil
}

func GenerateTaskFiles(outputDir string, baseInputs map[string]any, repo, commit string,
	targets []UncoveredTarget) error {
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

func (cfg *FilterConfig) matchFile(path string) bool {
	if len(cfg.Paths) > 0 && !matchesPrefix(path, cfg.Paths) {
		return false
	}
	if matchesPrefix(path, cfg.ExcludePaths) {
		return false
	}
	if cfg.FilePattern != nil && !cfg.FilePattern.MatchString(path) {
		return false
	}
	return true
}

var initFuncRe = regexp.MustCompile(`(?i)(^|_)(init|setup)($|_)`)

func (cfg *FilterConfig) matchFunc(name string) bool {
	if cfg.ExcludeInit && initFuncRe.MatchString(name) {
		return false
	}
	if cfg.ExcludeFuncPattern != nil && cfg.ExcludeFuncPattern.MatchString(name) {
		return false
	}
	if cfg.FuncPattern != nil && !cfg.FuncPattern.MatchString(name) {
		return false
	}
	return true
}

func pickLine(b *cover.Block, rng *rand.Rand) int {
	if b.ToLine <= b.FromLine {
		return b.FromLine
	}
	if rng != nil {
		return b.FromLine + rng.Intn(b.ToLine-b.FromLine+1)
	}
	return b.FromLine + (b.ToLine-b.FromLine)/2
}

// shuffle randomizes the order of s in place. A nil rng keeps s as is, which
// makes the target selection deterministic in tests.
func shuffle[T any](rng *rand.Rand, s []T) {
	if rng == nil || len(s) < 2 {
		return
	}
	rng.Shuffle(len(s), func(i, j int) {
		s[i], s[j] = s[j], s[i]
	})
}

func (cfg *FilterConfig) uncoveredBlocks(fn *cover.FuncCoverage) []*cover.Block {
	if fn == nil || len(fn.Blocks) == 0 || !cfg.matchFunc(fn.FuncName) {
		return nil
	}
	var uncovered []*cover.Block
	for _, b := range fn.Blocks {
		if b == nil {
			continue
		}
		if b.HitCount > 0 {
			if !cfg.IncludeCoveredFuncs {
				return nil
			}
			continue
		}
		if b.FromLine > 0 {
			uncovered = append(uncovered, b)
		}
	}
	return uncovered
}
