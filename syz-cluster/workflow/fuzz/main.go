// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzzconfig"
	"golang.org/x/sync/errgroup"
)

var (
	flagConfig       = flag.String("config", "", "path to the fuzz config")
	flagSession      = flag.String("session", "", "session ID")
	flagBaseBuild    = flag.String("base_build", "", "base build ID")
	flagPatchedBuild = flag.String("patched_build", "", "patched build ID")
	flagTime         = flag.String("time", "1h", "how long to fuzz")
	flagWorkdir      = flag.String("workdir", "/workdir", "base workdir path")
)

func main() {
	flag.Parse()
	if *flagConfig == "" || *flagSession == "" || *flagTime == "" {
		app.Fatalf("--config, --session and --time must be set")
	}
	client := app.DefaultClient()
	d, err := time.ParseDuration(*flagTime)
	if err != nil {
		app.Fatalf("invalid --time: %v", err)
	}
	if !prog.GitRevisionKnown() {
		log.Fatalf("the binary is built without the git revision information")
	}

	config := readFuzzConfig()
	ctx := context.Background()
	if err := reportStatus(ctx, config, client, api.TestRunning, nil); err != nil {
		app.Fatalf("failed to report the test: %v", err)
	}

	artifactsDir := filepath.Join(*flagWorkdir, "artifacts")
	osutil.MkdirAll(artifactsDir)
	store := &manager.DiffFuzzerStore{BasePath: artifactsDir}

	// We want to only cancel the run() operation in order to be able to also report
	// the final test result back.
	runCtx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	err = run(runCtx, config, client, d, store)
	status := api.TestPassed // TODO: what about TestFailed?
	if errors.Is(err, errSkipFuzzing) {
		status = api.TestSkipped
	} else if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		app.Errorf("the step failed: %v", err)
		status = api.TestError
	}
	log.Logf(0, "fuzzing is finished")
	logFinalState(store)
	if err := reportStatus(ctx, config, client, status, store); err != nil {
		app.Fatalf("failed to update the test: %v", err)
	}
}

func readFuzzConfig() *api.FuzzConfig {
	raw, err := os.ReadFile(*flagConfig)
	if err != nil {
		app.Fatalf("failed to read config: %v", err)
		return nil
	}
	var req api.FuzzConfig
	err = json.Unmarshal(raw, &req)
	if err != nil {
		app.Fatalf("failed to unmarshal request: %v, %s", err, raw)
		return nil
	}
	return &req
}

func logFinalState(store *manager.DiffFuzzerStore) {
	log.Logf(0, "status at the end:\n%s", store.PlainTextDump())

	// There can be findings that we did not report only because we failed
	// to come up with a reproducer.
	// Let's log such cases so that it's easier to find and manually review them.
	const countCutOff = 10
	for _, bug := range store.List() {
		if bug.Base.Crashes == 0 && bug.Patched.Crashes >= countCutOff {
			log.Logf(0, "possibly patched-only: %s", bug.Title)
		}
	}
}

var errSkipFuzzing = errors.New("skip")

func run(ctx context.Context, config *api.FuzzConfig, client *api.Client,
	timeout time.Duration, store *manager.DiffFuzzerStore) error {
	series, err := client.GetSessionSeries(ctx, *flagSession)
	if err != nil {
		return fmt.Errorf("failed to query the series info: %w", err)
	}

	// Until there's a way to pass the log.Logger object and capture all,
	// use the global log collection.
	const MB = 1000000
	log.EnableLogCaching(100000, 10*MB)

	base, patched, err := generateConfigs(config)
	if err != nil {
		return fmt.Errorf("failed to load configs: %w", err)
	}

	baseSymbols, patchedSymbols, err := readSymbolHashes()
	if err != nil {
		app.Errorf("failed to read symbol hashes: %v", err)
	}

	if shouldSkipFuzzing(baseSymbols, patchedSymbols) {
		return errSkipFuzzing
	}
	diff.PatchFocusAreas(patched, series.PatchBodies(), baseSymbols.Text, patchedSymbols.Text)

	if len(config.CorpusURLs) > 0 {
		err := prepareCorpus(ctx, patched.Workdir, config.CorpusURLs, patched.Target)
		if err != nil {
			app.Errorf("failed to download the corpus: %v", err)
		}
	}

	eg, groupCtx := errgroup.WithContext(ctx)
	bugs := make(chan *diff.Bug)
	baseCrashes := make(chan string, 16)
	eg.Go(func() error {
		defer log.Logf(0, "bug reporting terminated")
		for {
			select {
			case title := <-baseCrashes:
				err := client.UploadBaseFinding(groupCtx, &api.BaseFindingInfo{
					BuildID: *flagBaseBuild,
					Title:   title,
				})
				if err != nil {
					app.Errorf("failed to report a base kernel crash %q: %v", title, err)
				}
			case bug := <-bugs:
				err := reportFinding(groupCtx, config, client, bug)
				if err != nil {
					app.Errorf("failed to report a finding %q: %v", bug.Report.Title, err)
				}
			case <-groupCtx.Done():
				return nil
			}
		}
	})
	eg.Go(func() error {
		defer log.Logf(0, "diff fuzzing terminated")
		return diff.Run(groupCtx, base, patched, diff.Config{
			Debug:              false,
			PatchedOnly:        bugs,
			BaseCrashes:        baseCrashes,
			Store:              store,
			MaxTriageTime:      timeout / 2,
			FuzzToReachPatched: fuzzToReachPatched(config),
			IgnoreCrash: func(ctx context.Context, title string) (bool, error) {
				if !titleMatchesFilter(config, title) {
					log.Logf(1, "crash %q doesn't match the filter", title)
					return true, nil
				}
				ret, err := client.BaseFindingStatus(ctx, &api.BaseFindingInfo{
					BuildID: *flagBaseBuild,
					Title:   title,
				})
				if err != nil {
					return false, err
				}
				if ret.Observed {
					log.Logf(1, "crash %q is already known", title)
				}
				return ret.Observed, nil
			},
		})
	})
	const (
		updatePeriod         = 5 * time.Minute
		artifactUploadPeriod = 30 * time.Minute
	)
	lastArtifactUpdate := time.Now()
	eg.Go(func() error {
		defer log.Logf(0, "status reporting terminated")
		for {
			select {
			case <-groupCtx.Done():
				return nil
			case <-time.After(updatePeriod):
			}
			var useStore *manager.DiffFuzzerStore
			if time.Since(lastArtifactUpdate) > artifactUploadPeriod {
				lastArtifactUpdate = time.Now()
				useStore = store
			}
			err := reportStatus(groupCtx, config, client, api.TestRunning, useStore)
			if err != nil {
				app.Errorf("failed to update status: %v", err)
			}
		}
	})
	err = eg.Wait()
	if errors.Is(err, diff.ErrPatchedAreaNotReached) {
		// We did not reach the modified parts of the kernel, but that's fine.
		return nil
	}
	return err
}

func prepareCorpus(ctx context.Context, workdir string, urls []string, target *prog.Target) error {
	corpusFile := filepath.Join(workdir, "corpus.db")
	var otherFiles []string
	for i, url := range urls {
		log.Logf(0, "downloading corpus #%d: %q", i+1, url)
		downloadTo := corpusFile
		if i > 0 {
			downloadTo = fmt.Sprintf("%s.%d", corpusFile, i)
			otherFiles = append(otherFiles, downloadTo)
		}
		out, err := os.Create(corpusFile)
		if err != nil {
			return err
		}
		defer out.Close()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status is not 200: %s", resp.Status)
		}
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return err
		}
	}
	if len(otherFiles) > 0 {
		log.Logf(0, "merging corpuses")
		skipped, err := db.Merge(corpusFile, otherFiles, target)
		if err != nil {
			return err
		} else if len(skipped) > 0 {
			log.Logf(0, "skipped %d entries", len(skipped))
		}
	}
	return nil
}

func generateConfigs(config *api.FuzzConfig) (*mgrconfig.Config, *mgrconfig.Config, error) {
	base, err := fuzzconfig.GenerateBase(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare base config: %w", err)
	}
	patched, err := fuzzconfig.GeneratePatched(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare patched config: %w", err)
	}
	base.Workdir = filepath.Join(*flagWorkdir, "base")
	osutil.MkdirAll(base.Workdir)
	patched.Workdir = filepath.Join(*flagWorkdir, "patched")
	osutil.MkdirAll(patched.Workdir)
	err = mgrconfig.Complete(base)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to complete the base config: %w", err)
	}
	err = mgrconfig.Complete(patched)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to complete the patched config: %w", err)
	}
	return base, patched, nil
}

func reportStatus(ctx context.Context, config *api.FuzzConfig, client *api.Client,
	status string, store *manager.DiffFuzzerStore) error {
	testName := getTestName(config)
	testResult := &api.SessionTest{
		SessionID:      *flagSession,
		TestName:       testName,
		BaseBuildID:    *flagBaseBuild,
		PatchedBuildID: *flagPatchedBuild,
		Result:         status,
		Log:            []byte(log.CachedLogOutput()),
	}
	err := client.UploadSessionTest(ctx, testResult)
	if err != nil {
		return fmt.Errorf("failed to upload the status: %w", err)
	}
	if store == nil {
		return nil
	}
	tarGzReader, err := compressArtifacts(store.BasePath)
	if errors.Is(err, errWriteOverLimit) {
		app.Errorf("the artifacts archive is too big to upload")
	} else if err != nil {
		return fmt.Errorf("failed to compress the artifacts dir: %w", err)
	} else {
		err = client.UploadTestArtifacts(ctx, *flagSession, testName, tarGzReader)
		if err != nil {
			return fmt.Errorf("failed to upload the status: %w", err)
		}
	}
	return nil
}

func reportFinding(ctx context.Context, config *api.FuzzConfig, client *api.Client, bug *diff.Bug) error {
	finding := &api.RawFinding{
		SessionID: *flagSession,
		TestName:  getTestName(config),
		Title:     bug.Report.Title,
		Report:    bug.Report.Report,
		Log:       bug.Report.Output,
	}
	if repro := bug.Repro; repro != nil {
		if repro.Prog != nil {
			finding.SyzRepro = repro.Prog.Serialize()
			finding.SyzReproOpts = repro.Opts.Serialize()
		}
		if repro.CRepro {
			var err error
			finding.CRepro, err = repro.CProgram()
			if err != nil {
				app.Errorf("failed to generate C program: %v", err)
			}
		}
	}
	return client.UploadFinding(ctx, finding)
}

func getTestName(config *api.FuzzConfig) string {
	return fmt.Sprintf("[%s] Fuzzing", config.Track)
}

var ignoreLinuxVariables = map[string]bool{
	"raw_data": true, // from arch/x86/entry/vdso/vdso-image
	// Build versions / timestamps.
	"linux_banner": true,
	"vermagic":     true,
	"init_uts_ns":  true,
}

func shouldSkipFuzzing(base, patched build.SectionHashes) bool {
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

func titleMatchesFilter(config *api.FuzzConfig, title string) bool {
	matched, err := regexp.MatchString(config.BugTitleRe, title)
	if err != nil {
		app.Fatalf("invalid BugTitleRe regexp: %v", err)
	}
	return matched
}

func readSymbolHashes() (base, patched build.SectionHashes, err error) {
	// These are saved by the build step.
	base, err = readSectionHashes("/base/symbol_hashes.json")
	if err != nil {
		return build.SectionHashes{}, build.SectionHashes{}, fmt.Errorf("failed to read base hashes: %w", err)
	}
	patched, err = readSectionHashes("/patched/symbol_hashes.json")
	if err != nil {
		return build.SectionHashes{}, build.SectionHashes{}, fmt.Errorf("failed to read patched hashes: %w", err)
	}
	log.Logf(0, "extracted %d text symbol hashes for base and %d for patched", len(base.Text), len(patched.Text))
	return
}

func readSectionHashes(file string) (build.SectionHashes, error) {
	f, err := os.Open(file)
	if err != nil {
		return build.SectionHashes{}, err
	}
	defer f.Close()

	var data build.SectionHashes
	err = json.NewDecoder(f).Decode(&data)
	if err != nil {
		return build.SectionHashes{}, err
	}
	return data, nil
}

func fuzzToReachPatched(config *api.FuzzConfig) time.Duration {
	if config.SkipCoverCheck {
		return 0
	}
	// Allow up to 30 minutes after the corpus triage to reach the patched code.
	return time.Minute * 30
}

func compressArtifacts(dir string) (io.Reader, error) {
	var buf bytes.Buffer
	lw := &LimitedWriter{
		writer: &buf,
		// Don't create an archive larger than 64MB.
		limit: 64 * 1000 * 1000,
	}
	err := osutil.TarGzDirectory(dir, lw)
	if err != nil {
		return nil, err
	}
	return &buf, nil
}

type LimitedWriter struct {
	written int
	limit   int
	writer  io.Writer
}

var errWriteOverLimit = errors.New("the writer exceeded the limit")

func (lw *LimitedWriter) Write(p []byte) (n int, err error) {
	if len(p)+lw.written > lw.limit {
		return 0, errWriteOverLimit
	}
	n, err = lw.writer.Write(p)
	lw.written += n
	return
}
