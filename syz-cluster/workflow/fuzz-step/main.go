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
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"golang.org/x/sync/errgroup"
)

var (
	flagConfig       = flag.String("config", "", "syzkaller config")
	flagSession      = flag.String("session", "", "session ID")
	flagBaseBuild    = flag.String("base_build", "", "base build ID")
	flagPatchedBuild = flag.String("patched_build", "", "patched build ID")
	flagTime         = flag.String("time", "1h", "how long to fuzz")
	flagWorkdir      = flag.String("workdir", "/workdir", "base workdir path")
	flagCorpusURL    = flag.String("corpus_url", "", "an URL to download corpus from")
)

const testName = "Fuzzing"

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
	ctx := context.Background()
	if err := reportStatus(ctx, client, api.TestRunning, ""); err != nil {
		app.Fatalf("failed to report the test: %v", err)
	}

	artifactsDir := filepath.Join(*flagWorkdir, "artifacts")
	osutil.MkdirAll(artifactsDir)

	// We want to only cancel the run() operation in order to be able to also report
	// the final test result back.
	runCtx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	err = run(runCtx, client, artifactsDir)
	status := api.TestPassed // TODO: what about TestFailed?
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		app.Errorf("the step failed: %v", err)
		status = api.TestError
	}
	log.Logf(0, "fuzzing is finished")
	if err := reportStatus(ctx, client, status, artifactsDir); err != nil {
		app.Fatalf("failed to update the test: %v", err)
	}
}

func run(baseCtx context.Context, client *api.Client, artifactsDir string) error {
	series, err := client.GetSessionSeries(baseCtx, *flagSession)
	if err != nil {
		return fmt.Errorf("failed to query the series info: %w", err)
	}

	// Until there's a way to pass the log.Logger object and capture all,
	// use the global log collection.
	const MB = 1000000
	log.EnableLogCaching(100000, 10*MB)

	base, patched, err := loadConfigs("/configs", *flagConfig, true)
	if err != nil {
		return fmt.Errorf("failed to load configs: %w", err)
	}
	manager.PatchFocusAreas(patched, series.PatchBodies())

	if *flagCorpusURL != "" {
		err := downloadCorpus(baseCtx, patched.Workdir, *flagCorpusURL)
		if err != nil {
			return fmt.Errorf("failed to download the corpus: %w", err)
		} else {
			log.Logf(0, "downloaded the corpus from %s", *flagCorpusURL)
		}
	}

	eg, ctx := errgroup.WithContext(baseCtx)
	bugs := make(chan *manager.UniqueBug)
	eg.Go(func() error {
		for {
			var bug *manager.UniqueBug
			select {
			case bug = <-bugs:
			case <-ctx.Done():
			}
			if bug == nil {
				break
			}
			// TODO: filter out all INFO: bugs?
			err := reportFinding(ctx, client, bug)
			if err != nil {
				app.Errorf("failed to report a finding %s: %v", bug.Report.Title, err)
			}
		}
		return nil
	})
	eg.Go(func() error {
		return manager.RunDiffFuzzer(ctx, base, patched, manager.DiffFuzzerConfig{
			Debug:        false,
			PatchedOnly:  bugs,
			ArtifactsDir: artifactsDir,
		})
	})
	const (
		updatePeriod         = 5 * time.Minute
		artifactUploadPeriod = 30 * time.Minute
	)
	lastArtifactUpdate := time.Now()
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(updatePeriod):
			}
			artifacts := ""
			if time.Since(lastArtifactUpdate) > artifactUploadPeriod {
				lastArtifactUpdate = time.Now()
				artifacts = artifactsDir
			}
			err := reportStatus(ctx, client, api.TestRunning, artifacts)
			if err != nil {
				app.Errorf("failed to update status: %v", err)
			}
		}
	})
	return eg.Wait()
}

func downloadCorpus(ctx context.Context, workdir, url string) error {
	out, err := os.Create(filepath.Join(workdir, "corpus.db"))
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
	return err
}

// To reduce duplication, patched configs are stored as a delta to their corresponding base.cfg version.
// loadConfigs performs all the necessary merging and parsing and returns two ready to use configs.
func loadConfigs(configFolder, configName string, complete bool) (*mgrconfig.Config, *mgrconfig.Config, error) {
	var baseRaw, deltaRaw json.RawMessage
	err := config.LoadFile(filepath.Join(configFolder, configName, "base.cfg"), &baseRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the base config: %w", err)
	}
	err = config.LoadFile(filepath.Join(configFolder, configName, "patched.cfg"), &deltaRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the patched config: %w", err)
	}
	patchedRaw, err := config.MergeJSONs(baseRaw, deltaRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to merge the configs: %w", err)
	}
	base, err := mgrconfig.LoadPartialData(baseRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the base config: %w", err)
	}
	patched, err := mgrconfig.LoadPartialData(patchedRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the patched config: %w", err)
	}
	if complete {
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
	}
	return base, patched, nil
}

func reportStatus(ctx context.Context, client *api.Client, status, artifactsDir string) error {
	testResult := &api.TestResult{
		SessionID:      *flagSession,
		TestName:       testName,
		BaseBuildID:    *flagBaseBuild,
		PatchedBuildID: *flagPatchedBuild,
		Result:         status,
		Log:            []byte(log.CachedLogOutput()),
	}
	err := client.UploadTestResult(ctx, testResult)
	if err != nil {
		return fmt.Errorf("failed to upload the status: %w", err)
	}
	if artifactsDir == "" {
		return nil
	}
	tarGzReader, err := compressArtifacts(artifactsDir)
	if err != nil {
		return fmt.Errorf("failed to compress the artifacts dir: %w", err)
	}
	err = client.UploadTestArtifacts(ctx, *flagSession, testName, tarGzReader)
	if err != nil {
		return fmt.Errorf("failed to upload the status: %w", err)
	}
	return nil
}

func reportFinding(ctx context.Context, client *api.Client, bug *manager.UniqueBug) error {
	finding := &api.NewFinding{
		SessionID: *flagSession,
		TestName:  testName,
		Title:     bug.Report.Title,
		Report:    bug.Report.Report,
		Log:       bug.Report.Output,
		// TODO: include the reproducer.
	}
	return client.UploadFinding(ctx, finding)
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
