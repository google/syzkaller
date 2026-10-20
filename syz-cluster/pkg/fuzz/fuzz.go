// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzz provides differential kernel fuzzing orchestration for syz-cluster and local tools.
package fuzz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	pkgbuild "github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"golang.org/x/sync/errgroup"
)

// ErrSkipFuzzing is returned by Run when base and patched kernel binaries are identical.
var ErrSkipFuzzing = errors.New("skip")

// Params defines the configuration and callbacks for a differential fuzzing session.
// Base and Patched must be uncompleted mgrconfig.Config instances; Run completes them in place.
type Params struct {
	Base    *mgrconfig.Config
	Patched *mgrconfig.Config
	// ELF symbol hashes of the base and patched kernels (see build.ReadSymbolHashes).
	// They are used to skip fuzzing of identical binaries and to focus on the modified functions.
	// If any of them is empty, the binary equality check is skipped.
	BaseSymbols    pkgbuild.SectionHashes
	PatchedSymbols pkgbuild.SectionHashes
	Config         *api.FuzzConfig
	Series         *api.Series
	Timeout        time.Duration
	CorpusFiles    []string
	Debug          bool
	// Store is required and records differential fuzzing state and artifacts.
	Store *manager.DiffFuzzerStore

	// Optional callbacks used to report findings and query crash status.
	OnBaseCrash       func(ctx context.Context, title string)
	OnBug             func(ctx context.Context, bug *diff.Bug)
	ShouldIgnoreCrash func(ctx context.Context, title string) (bool, error)
}

// Run executes the differential fuzzing campaign between base and patched kernels.
func Run(ctx context.Context, params *Params) error {
	titleRe, err := compileTitleFilter(params.Config)
	if err != nil {
		return err
	}
	if shouldSkipFuzzing(params.BaseSymbols, params.PatchedSymbols) {
		return ErrSkipFuzzing
	}
	base, patched := params.Base, params.Patched
	osutil.MkdirAll(base.Workdir)
	osutil.MkdirAll(patched.Workdir)
	if err := mgrconfig.Complete(base); err != nil {
		return fmt.Errorf("failed to complete the base config: %w", err)
	}
	if err := mgrconfig.Complete(patched); err != nil {
		return fmt.Errorf("failed to complete the patched config: %w", err)
	}

	var patches [][]byte
	if params.Series != nil {
		patches = params.Series.PatchBodies()
	}
	diff.PatchFocusAreas(patched, patches, params.BaseSymbols.Text, params.PatchedSymbols.Text)
	if params.Series != nil {
		setupAIFocusAreas(params.Config, patched, params.Series)
	}

	if len(params.Config.CorpusURLs) > 0 || len(params.CorpusFiles) > 0 {
		err := prepareCorpus(ctx, patched.Workdir, params.Config.CorpusURLs, params.CorpusFiles, patched.Target)
		if err != nil {
			log.Errorf("failed to prepare the corpus: %v", err)
		}
	}

	eg, groupCtx := errgroup.WithContext(ctx)
	bugs := make(chan *diff.Bug)
	baseCrashes := make(chan string, 16)
	eg.Go(func() error {
		reportLoop(groupCtx, baseCrashes, bugs, params)
		return nil
	})
	eg.Go(func() error {
		defer func() {
			close(baseCrashes)
			close(bugs)
		}()
		defer log.Logf(0, "diff fuzzing terminated")
		return diff.Run(groupCtx, base, patched, diff.Config{
			Debug:              params.Debug,
			PatchedOnly:        bugs,
			BaseCrashes:        baseCrashes,
			Store:              params.Store,
			MaxTriageTime:      params.Timeout / 2,
			FuzzToReachPatched: fuzzToReachPatched(params.Config),
			IgnoreCrash: func(ctx context.Context, title string) (bool, error) {
				if !titleRe.MatchString(title) {
					log.Logf(1, "crash %q doesn't match the filter", title)
					return true, nil
				}
				if params.ShouldIgnoreCrash != nil {
					return params.ShouldIgnoreCrash(ctx, title)
				}
				return false, nil
			},
		})
	})
	err = eg.Wait()
	if errors.Is(err, diff.ErrPatchedAreaNotReached) {
		// We did not reach the modified parts of the kernel, but that's fine.
		return nil
	}
	return err
}

func reportLoop(ctx context.Context, baseCrashes <-chan string, bugs <-chan *diff.Bug, params *Params) {
	defer log.Logf(0, "bug reporting terminated")
	for baseCrashes != nil || bugs != nil {
		select {
		case title, ok := <-baseCrashes:
			if !ok {
				baseCrashes = nil
				continue
			}
			if params.OnBaseCrash != nil {
				params.OnBaseCrash(ctx, title)
			}
		case bug, ok := <-bugs:
			if !ok {
				bugs = nil
				continue
			}
			if params.OnBug != nil {
				params.OnBug(ctx, bug)
			}
		}
	}
}

// FilterFindingCandidates returns unreproduced patched-only crashes eligible for post-fuzzing triage.
func FilterFindingCandidates(bugs []manager.DiffBug) []manager.DiffBug {
	var candidates []manager.DiffBug
	for _, bug := range bugs {
		if bug.Status == manager.DiffBugStatusIgnored || bug.Base.Crashes > 0 || bug.Base.NotCrashed {
			continue
		}
		if bug.Patched.Crashes == 0 || bug.Patched.Report == "" || bug.Patched.CorruptedReport {
			continue
		}
		candidates = append(candidates, bug)
	}
	return candidates
}

// prepareCorpus downloads corpuses from urls, combines them with localFiles,
// and merges them into workdir/corpus.db.
func prepareCorpus(ctx context.Context, workdir string, urls, localFiles []string, target *prog.Target) error {
	// Download to a temporary folder, so that a failed download never leaves a
	// partially written corpus.db behind -- the manager opens it without the repair
	// mode and would abort the whole fuzzing session.
	tmpDir, err := os.MkdirTemp(workdir, "corpus-download")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	urlByFile := map[string]string{}
	var files []string
	client := &http.Client{Timeout: corpusDownloadTimeout}
	for i, url := range urls {
		log.Logf(0, "downloading corpus #%d: %q", i+1, url)
		file := filepath.Join(tmpDir, fmt.Sprintf("%d.db", i))
		if err := downloadFile(ctx, client, url, file); err != nil {
			return fmt.Errorf("failed to download %q: %w", url, err)
		}
		urlByFile[file] = url
		files = append(files, file)
	}
	files = append(files, localFiles...)
	failures, err := db.Merge(filepath.Join(workdir, "corpus.db"), files, target)
	for _, failure := range failures {
		src := failure.File
		if url := urlByFile[src]; url != "" {
			src = url
		}
		log.Errorf("failed to deserialize the corpus from %q: %v", src, failure.Err)
	}
	if err != nil {
		return fmt.Errorf("failed to merge corpuses: %w", err)
	}
	return nil
}

// Corpus files are up to several hundred MBs, but we don't want a stuck
// download to consume the whole fuzzing time budget.
const corpusDownloadTimeout = 10 * time.Minute

func downloadFile(ctx context.Context, client *http.Client, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status is not 200: %s", resp.Status)
	}
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write body: %w", err)
	}
	// Close it explicitly to not miss the flush errors.
	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}
	return nil
}

var ignoreLinuxVariables = map[string]bool{
	"raw_data": true, // from arch/x86/entry/vdso/vdso-image
	// Build versions / timestamps.
	"linux_banner": true,
	"vermagic":     true,
	"init_uts_ns":  true,
}

func shouldSkipFuzzing(base, patched pkgbuild.SectionHashes) bool {
	if len(base.Text) == 0 || len(patched.Text) == 0 {
		// Likely, something went wrong during the kernel build step.
		log.Logf(0, "skipped the binary equality check because some of them have 0 symbols")
		return false
	}
	same := len(base.Text) == len(patched.Text) && len(base.Data) == len(patched.Data)
	// For .text, demand all symbols to be equal.
	for name, hash := range base.Text {
		if patched.Text[name] != hash {
			same = false
			break
		}
	}
	// For data sections ignore some of them.
	for name, hash := range base.Data {
		if !ignoreLinuxVariables[name] && patched.Data[name] != hash {
			log.Logf(1, "symbol %q has different values in base vs patch", name)
			same = false
			break
		}
	}
	if same {
		log.Logf(0, "binaries are the same, no sense to do fuzzing")
		return true
	}
	log.Logf(0, "binaries are different, continuing fuzzing")
	return false
}

func compileTitleFilter(config *api.FuzzConfig) (*regexp.Regexp, error) {
	re, err := regexp.Compile(config.BugTitleRe)
	if err != nil {
		return nil, fmt.Errorf("invalid BugTitleRe regexp: %w", err)
	}
	return re, nil
}

func fuzzToReachPatched(config *api.FuzzConfig) time.Duration {
	if config.SkipCoverCheck {
		return 0
	}
	// Allow up to 30 minutes after the corpus triage to reach the patched code.
	return time.Minute * 30
}

func setupAIFocusAreas(config *api.FuzzConfig, patched *mgrconfig.Config, series *api.Series) {
	isEmptySeries := len(series.Patches) == 0
	hasNoFocusSymbols := len(config.FocusSymbols) == 0
	exceedsPatchLimit := series.IsStableRC() && len(series.Patches) > api.MaxRCFocusedPatches
	if isEmptySeries || hasNoFocusSymbols || exceedsPatchLimit {
		return
	}
	var regexps []string
	for _, name := range config.FocusSymbols {
		regexps = append(regexps, fmt.Sprintf("^%s$", regexp.QuoteMeta(name)))
	}
	patched.Experimental.FocusAreas = append(patched.Experimental.FocusAreas, mgrconfig.FocusArea{
		Name: "ai_focus",
		Filter: mgrconfig.CovFilterCfg{
			Functions: regexps,
		},
		Weight: 10.0,
	})
}
